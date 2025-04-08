use blst::min_pk::{PublicKey, Signature};
use clap::Parser;
use dag::candidate::Candidate;
use dag::vertex::{Transaction, Vertex};
use log::{debug, error, info, warn};
use opt::config::AppConfig;
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use state::global::GlobalState;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::{Notify, RwLock};

mod dag;
mod opt;
mod state;

#[derive(Serialize, Deserialize, Debug)]
enum MessageType {
    SignRequest(Candidate),         // Request for signing vertex
    SignedMessage(Candidate),       // Sending back a signed vertex
    ConsensusSignedMessage(Vertex), // Message with a vertex that has reached consensus and aggregated signature
    AddPeer {
        address: String,
        public_key: PublicKey,
    },
    // Registering a new node in the blockchain network
    PeersList(Vec<(String, PublicKey)>), // Message containing the current list of nodes
    RequestPeers,                        // Node List Query
}

async fn send_request_peers(address: &String, socket: Arc<UdpSocket>) -> Result<(), String> {
    let target: SocketAddr = format!("{}", address)
        .parse::<SocketAddr>()
        .map_err(|e| e.to_string())?;

    let request_message = MessageType::RequestPeers;
    let request_data = bincode::serialize(&request_message)
        .map_err(|_| "Failed to serialize RequestPeers message".to_string())?;

    debug!("message sent to: {}", target);
    socket
        .send_to(&request_data, target)
        .await
        .map_err(|_| "Failed to send RequestPeers message".to_string())?;

    info!("Sent RequestPeers to {}", address);
    Ok(())
}

async fn broadcast_new_peer(
    address: String,
    public_key: PublicKey,
    socket: &UdpSocket,
    global_state: Arc<GlobalState>,
) {
    let message = MessageType::AddPeer {
        address: address.clone(),
        public_key: public_key.clone(),
    };
    let serialized = match bincode::serialize(&message) {
        Ok(serialized) => serialized,
        Err(e) => {
            error!("Serialization failed: {}", e);
            return;
        }
    };

    let nodes = global_state.get_all_nodes().await;
    for (peer_address, _) in nodes.iter() {
        if peer_address != &address {
            debug!("message sent to: {}", peer_address);
            if let Err(e) = socket.send_to(&serialized, peer_address).await {
                error!("Failed to send new peer to {}: {}", peer_address, e);
            }
        }
    }
}

async fn broadcast_candidate(
    peers: Arc<RwLock<HashMap<String, PublicKey>>>,
    vertex: Arc<Candidate>,
    socket: &UdpSocket,
) {
    let vertex_cloned = (*vertex).clone();
    let message = MessageType::SignRequest(vertex_cloned);
    let serialized = match bincode::serialize(&message) {
        Ok(serialized) => serialized,
        Err(e) => {
            error!("Serialization failed: {}", e);
            return;
        }
    };

    for (peer, _) in peers.read().await.iter() {
        debug!("message sent to: {}, size: {}", peer, serialized.len());
        if let Err(e) = socket.send_to(&serialized, peer).await {
            error!("Failed to send vertex to {}: {}", peer, e);
        }
    }
}

async fn request_peers(global_state: Arc<GlobalState>, socket: Arc<UdpSocket>) {
    let peers_read = global_state.get_all_nodes().await;

    let tasks: Vec<_> = peers_read
        .iter()
        .map(|(address, _public_key)| {
            let socket_clone = socket.clone();
            let address_clone = address.clone();

            tokio::spawn(async move {
                if let Err(e) = send_request_peers(&address_clone, socket_clone).await {
                    error!("Error sending RequestPeers to {}: {}", address_clone, e);
                }
            })
        })
        .collect();

    // Wait for all tasks to complete
    for task in tasks {
        task.await.unwrap();
    }
}

async fn register_with_network(
    initial_peer: String,
    self_address: String,
    public_key: PublicKey,
    socket: &UdpSocket,
    global_state: Arc<GlobalState>,
) {
    let pk = match PublicKey::try_from(public_key) {
        Ok(pk) => pk,
        Err(e) => {
            error!("Failed to convert public key: {}", e);
            return;
        }
    };

    let message = MessageType::AddPeer {
        address: self_address.clone(),
        public_key: pk,
    };

    let serialized = match bincode::serialize(&message) {
        Ok(serialized) => serialized,
        Err(e) => {
            error!("Serialization failed: {}", e);
            return;
        }
    };
    debug!("message sent to: {}", initial_peer);
    if let Err(e) = socket.send_to(&serialized, initial_peer.clone()).await {
        error!("Failed to register with network at {}: {}", initial_peer, e);
    } else {
        global_state.register_node(initial_peer, pk).await;
    }
}

async fn handle_new_peer(
    address: String,
    public_key: PublicKey,
    socket: &UdpSocket,
    global_state: Arc<GlobalState>,
) {
    let propagation;

    info!(
        "Received request to add new peer: {} => {:?}",
        address, public_key
    );

    {
        propagation = global_state
            .register_node(address.clone(), public_key)
            .await;
        info!("Added new peer: {}", address,);
    }

    if propagation {
        // Broadcast new node to other nodes
        broadcast_new_peer(address, public_key, &socket, global_state.clone()).await;
    }
}

async fn handle_sign_request(
    global_state: Arc<GlobalState>,
    socket: Arc<UdpSocket>,
    candidate: Candidate,
    addr: std::net::SocketAddr,
) {
    let id = candidate.id.clone();
    let ref_cnt = candidate.references.len();

    if global_state.check_vertex(&id).await {
        error!("Vertex already signed: {:?}", id);
    } else {
        let mut signed_vertex;
        {
            let signature = global_state.sign_candidate(&candidate).unwrap();
            signed_vertex = candidate;
            signed_vertex.signature = Some(signature.to_bytes().to_vec());
        }

        // Sending a signed message to the sender
        let response = MessageType::SignedMessage(signed_vertex);
        if let Ok(serialized_response) = bincode::serialize(&response) {
            debug!("message sent to: {}, ref: {}", addr, ref_cnt);
            socket
                .send_to(&serialized_response, addr)
                .await
                .expect("Failed to send signed message");
        }
    }
}

async fn handle_signed_message(
    global_state: Arc<GlobalState>,
    vertex_item: Candidate,
    socket: Arc<UdpSocket>,
    peer_address: std::net::SocketAddr,
) {
    let addr_str = format!("{}", peer_address);
    let vertex_clone = vertex_item.clone();
    match vertex_item.signature {
        Some(signature) => match global_state.clone().get_node_public_key(&addr_str).await {
            Some(validator_pk) => {
                if vertex_clone.verify_signature(validator_pk) {
                    global_state.add_signature(validator_pk, signature).await;
                    info!("received valid signature from: {:?}", addr_str);
                } else {
                    error!("ERROR: received invalid signature from: {:?}", addr_str);
                }
            }
            None => {
                error!("This should never happen because public key is generated during booting!");
            }
        },
        None => {
            warn!("wrong signed message");
        }
    };

    let validator_state = global_state.clone().validator_state.clone();
    let consensus = validator_state.write().await.consensus.clone();

    if let Some(mut consensus) = consensus {
        if consensus.commit() {
            let aggregate_signature = consensus.get_aggregated_signature();

            //            info!("aggregate: {:?}", aggregate_signature);

            let vertex = Vertex::from_candidate(
                &vertex_clone,
                consensus.get_signatures(),
                aggregate_signature,
            );

            let res = verify_aggregated_signature(
                &vertex.clone(),
                3,
                global_state.clone().known_nodes.clone(),
            )
            .await;
            debug!("aggregation verify local: {:?}", res);

            global_state.clone().insert_vertex(&vertex).await;

            // propagation about signed vertex
            global_state
                .broadcast_consensus_message(&socket, vertex)
                .await;

            validator_state.write().await.consensus = None;
        }
    } else {
        info!("consensus is not existing anymore");
    }
}

/// Verifies the aggregated signature for a vertex.
///
/// @param vertex The vertex whose signature needs verification.
/// @param signature The aggregated signature to verify.
/// @return true if the signature is valid, false otherwise.
async fn verify_aggregated_signature(
    vertex: &Vertex,
    threshold: usize,
    known_nodes: Arc<RwLock<HashMap<String, PublicKey>>>,
) -> bool {
    // Check if the vertex contains an aggregated signature
    let aggregated_signature_bytes = match &vertex.aggregate_signature {
        Some(signature) => signature,
        None => {
            error!(
                "Vertex {:?} does not contain an aggregated signature.",
                vertex.id
            );
            return false;
        }
    };

    // Attempt to deserialize the aggregated signature
    let aggregated_signature = match Signature::from_bytes(aggregated_signature_bytes) {
        Ok(signature) => signature,
        Err(_) => return false,
    };

    // Collect all public keys from the vertex signatures
    let public_keys: Vec<PublicKey> = vertex
        .signatures
        .keys()
        .filter_map(|key_bytes| {
            // Convert public key bytes to PublicKey object
            PublicKey::from_bytes(key_bytes).ok()
        })
        .collect();

    // Ensure the number of public keys meets the threshold
    if public_keys.len() < threshold {
        error!(
            "Insufficient signatures in vertex {:?}: found {}, required {}.",
            vertex.id,
            public_keys.len(),
            threshold
        );
        return false;
    }

    {
        // Acquire a read lock on known_nodes
        let known_nodes_guard = known_nodes.read().await;

        // Check if all signatures correspond to known nodes
        if vertex.signatures.keys().any(|key_bytes| {
            // Convert public key bytes to PublicKey object
            let public_key = PublicKey::from_bytes(key_bytes).unwrap();

            // Check if the public key exists in known_nodes
            !known_nodes_guard
                .values()
                .any(|known_key| known_key == &public_key)
        }) {
            error!(
                "One or more public keys in vertex {:?} do not exist in known_nodes.",
                vertex.id
            );
            return false;
        }
    }

    // Convert Vec<PublicKey> to Vec<&PublicKey>
    let public_key_refs: Vec<&PublicKey> = public_keys.iter().collect();

    // Serialize the vertex into a message for signature verification
    let msg = match Candidate::from_vertex(vertex.clone()).to_bytes() {
        Ok(bytes) => bytes,
        Err(_) => {
            error!("Failed to serialize the vertex into a message.");
            return false;
        }
    };

    // Verify the aggregated signature
    let dst = "BLS_SIG_DST";
    let valid =
        aggregated_signature.fast_aggregate_verify(false, &msg, &dst.as_bytes(), &public_key_refs);

    // Check the result of verification
    if valid == blst::BLST_ERROR::BLST_SUCCESS {
        info!("Aggregated signature is valid for vertex {:?}.", vertex.id);
        return true;
    } else {
        error!(
            "Aggregated signature is invalid for vertex {:?}.",
            vertex.id
        );
    }
    false
}

async fn handle_consensus_signed_message(global_state: Arc<GlobalState>, vertex: Vertex) {
    // Get the threshold value from the global state
    let threshold = global_state.threshold;

    // Validate the references using the DAG
    if !global_state.validate_references(&vertex, threshold).await {
        error!("Vertex {:?} failed reference validation.", vertex.id);
        return;
    }

    // Add the vertex to the DAG
    global_state.insert_vertex(&vertex.clone()).await;
    info!("Vertex added to the DAG as committed.");
}

async fn handle_message(
    data: Vec<u8>,
    addr: std::net::SocketAddr,
    socket: Arc<UdpSocket>,
    global_state: Arc<GlobalState>,
) {
    match bincode::deserialize::<MessageType>(&data) {
        Ok(MessageType::SignRequest(candidate)) => {
            debug!(
                "deserialize: MessageType::SignRequest, ref: {}, round: {}",
                candidate.references.len(),
                candidate.round_no
            );
            handle_sign_request(
                global_state.clone(),
                socket.clone(),
                candidate,
                addr.clone(),
            )
            .await;
        }
        Ok(MessageType::SignedMessage(candidate)) => {
            debug!("deserialize: MessageType::SignedMessage");
            handle_signed_message(global_state.clone(), candidate, socket.clone(), addr).await;
        }
        Ok(MessageType::ConsensusSignedMessage(vertex)) => {
            debug!("deserialize: MessageType::ConsensusSignedMessage");
            handle_consensus_signed_message(global_state.clone(), vertex).await;
        }
        Ok(MessageType::AddPeer {
            address,
            public_key,
        }) => {
            debug!("deserialize: MessageType::AddPeer");
            handle_new_peer(address, public_key, &socket, global_state.clone()).await;
        }
        Ok(MessageType::RequestPeers) => {
            debug!("deserialize: MessageType::RequestPeers");
            let peers_list: Vec<(String, PublicKey)> = global_state.get_all_nodes().await;

            let response = MessageType::PeersList(peers_list);
            if let Ok(serialized) = bincode::serialize(&response) {
                debug!("message sent to: {}", addr);
                if let Err(e) = socket.send_to(&serialized, addr).await {
                    error!("Failed to send peers list: {}", e);
                }
            }
        }
        Ok(MessageType::PeersList(peers)) => {
            global_state.add_nodes(peers).await;
            info!("Updated peers list");
        }
        Err(err) => {
            error!(
                "Failed to deserialize message from {}: {:?}, len: {}",
                addr,
                err,
                data.len()
            );
        }
    }
}

// simulating new transactions
async fn periodic_vertex_generation(
    rng: Arc<RwLock<StdRng>>, // Use RwLock to share access to RNG
) -> Vec<Transaction> {
    let num_transactions;
    let sleep_duration;

    // Acquire a write lock on the RNG.
    let mut rng = rng.write().await;

    // Generate a random number of transactions (1 to 5)
    num_transactions = rng.gen_range(1..=5);

    sleep_duration = Duration::from_secs(rng.gen_range(15..=60));

    tokio::time::sleep(sleep_duration).await;

    /////////////////////////////////////////////////////////////////////////
    let random_byte;
    {
        let lowercase = b'a'..=b'z';
        let uppercase = b'A'..=b'Z';
        let digits = b'0'..=b'9';
        let characters: Vec<u8> = lowercase.chain(uppercase).chain(digits).collect();
        let mut rng = thread_rng();
        random_byte = characters[rng.gen_range(0..characters.len())];
    }
    /////////////////////////////////////////////////////////////////////////

    let transactions: Vec<Transaction> = (0..num_transactions)
        .map(|id| Transaction {
            id,
            data: random_byte.to_string(), // Example static transaction data
        })
        .collect();
    info!("trying to generate new candidate");

    transactions
}

#[tokio::main]
async fn main() {
    let shutdown_notify = Arc::new(Notify::new());
    let config = Arc::new(AppConfig::parse());

    // Set up logging based on verbosity
    config.setup_logging();

    // threshold = 3
    let global_state = Arc::new(GlobalState::new(3));
    {
        for peer in config.get_initial_peers() {
            global_state
                .clone()
                .register_node(peer.to_string(), PublicKey::default())
                .await;
        }
    }

    let auto_generate_vertices = config.get_auto_generate_vertices();
    let addr = format!("127.0.0.1:{}", config.get_config_port());

    let pk = global_state.clone().get_public_key();
    global_state.clone().register_node(addr.clone(), pk).await;

    let socket = Arc::new(
        UdpSocket::bind(addr.clone())
            .await
            .expect("Failed to bind UDP socket"),
    );

    let pk = global_state.clone().get_public_key();
    let socket_clone = socket.clone();
    if let Some(initial_peer) = config.get_initial_peers().get(0) {
        register_with_network(
            initial_peer.clone(),
            addr.clone(),
            pk,
            &socket_clone,
            global_state.clone(),
        )
        .await;

        request_peers(global_state.clone(), socket_clone).await;
    } else {
        info!("No initial peers provided. Skipping network registration.");
    }

    let socket_clone = socket.clone();
    let socket_send = socket.clone();

    let clone_global_state = global_state.clone();
    let addr_clone = addr.clone();

    let addr_socket = addr_clone
        .parse::<SocketAddr>()
        .map_err(|e| format!("Failed to parse SocketAddr: {}", e))
        .unwrap();

    let shutdown_notify_clone = shutdown_notify.clone();
    tokio::spawn(async move {
        let mut buf = [0; 1500];
        loop {
            tokio::select! {
                // Check if notify has been triggered
                _ = shutdown_notify_clone.notified() => {
                    // If notified, break the loop after completing the current task
                    info!("Receiver thread received stop signal. Completing current task.");
                    break; // Exit the loop if notified
                }

                // Wait for incoming data from the socket
                result = socket_clone.recv_from(&mut buf) => {
                    match result {
                        Ok((size, addr)) => {
                            if addr_socket != addr {
                                let data = buf[..size].to_vec();
                                info!("received message from: {}, size: {}", addr, size);
                                handle_message(data, addr, socket_send.clone(), clone_global_state.clone()).await;
                            }
                        }
                        Err(e) => {
                            // Handle any error from recv_from
                            eprintln!("Error receiving data: {}", e);
                        }
                    }
                }
            }
        }
        // Any clean-up logic after loop completion
        info!("Receiver thread has completed its work.");
    });

    let rng = Arc::new(RwLock::new(StdRng::from_entropy()));

    let global_state_clone = global_state.clone();
    if auto_generate_vertices {
        let shutdown_notify_clone = shutdown_notify.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Wait for shutdown notification
                    _ = shutdown_notify_clone.notified() => {
                        info!("Vertex generation thread received stop signal.");
                        break; // Exit the loop after completing current vertex generation
                    }
                    _ = tokio::spawn({
                        let rng_clone = rng.clone(); // Clone the Arc to ensure lifetime
                        let global_state_clone = global_state_clone.clone();
                        let socket_clone = socket.clone();
                        async move {
                            let transactions = periodic_vertex_generation(rng_clone).await;
                            global_state_clone.clone().register_candidate(transactions, socket_clone.clone()).await;
                        }
                    }) => {}
                }
            }
        });
    }

    let shutdown_notify_clone = shutdown_notify.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        println!("Shutdown signal received.");
        shutdown_notify_clone.notify_waiters();
    });

    shutdown_notify.notified().await;

    let global_state_clone = global_state.clone();
    tokio::spawn(async move {
        // Generate a random 8-digit number
        let rand_num: u32 = rand::thread_rng().gen_range(10000000..99999999);

        // Create the filename using the random number
        let filename = format!("dag_data_{}.txt", rand_num);

        let dag_read = global_state_clone.dag.read().await;
        if let Err(e) = dag_read.save_vertices_by_creator_and_round(&filename) {
            eprintln!("Failed to save DAG data: {:?}", e);
        }
        println!("DAG data saved.");
    })
    .await
    .unwrap();

    println!("Exiting application.");
    process::exit(0);
}
