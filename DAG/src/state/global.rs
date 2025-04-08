use base64::Engine;
use blake2::{Blake2b, Digest};
use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use hex::encode as hex_encode;
use log::{debug, error, info, warn};
use rand::Rng;
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, RwLock},
};

use crate::{
    broadcast_candidate,
    dag::{
        bullshark::ValidatorState,
        candidate::Candidate,
        dag::DAG,
        vertex::{Transaction, Vertex, VertexHash},
    },
    MessageType,
};

pub trait PublicKeyExt {
    fn to_string_base64(&self) -> String;
    fn to_string_hex(&self) -> String;
}

impl PublicKeyExt for PublicKey {
    fn to_string_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.to_bytes())
    }

    fn to_string_hex(&self) -> String {
        hex_encode(&self.to_bytes())
    }
}

/// Represents a key pair for a validator.
#[derive(Clone, Debug, Default)]
pub struct KeyPair {
    /// The secret key of the validator.
    pub secret_key: SecretKey, // SecretKey type depends on the cryptographic library in use.

    /// The public key of the validator.
    pub public_key: PublicKey, // PublicKey type should match the library's definition.

    dst: String,
}

impl KeyPair {
    fn new(secret_key: SecretKey, public_key: PublicKey, dst: String) -> Self {
        Self {
            secret_key,
            public_key,
            dst,
        }
    }
}

/// Represents the global state of the system, combining the DAG and validator states.
#[derive(Debug, Default)]
pub struct GlobalState {
    /// The directed acyclic graph.
    pub dag: RwLock<DAG>,

    /// The state of the validator.
    pub validator_state: Arc<RwLock<ValidatorState>>,

    /// The key pair of the validator.
    key_pair: KeyPair,

    // Threshold value for consensus decision.
    pub threshold: usize,

    /// A hashmap storing public keys of known nodes, with the node's address (IP:port) as the key.
    pub known_nodes: Arc<RwLock<HashMap<String, PublicKey>>>, // IP address and port as the key, PublicKey as the value.

    dst: String,
}

impl GlobalState {
    pub async fn validate_references(&self, vertex: &Vertex, threshold: usize) -> bool {
        self.dag.read().await.validate_references(vertex, threshold)
    }

    pub async fn insert_vertex(&self, vertex: &Vertex) {
        self.dag.write().await.insert_vertex(vertex);
    }

    /// Creates a new global state with default values.
    /// @param key_pair The key pair of the validator.
    /// @return A new instance of GlobalState.
    pub fn new(threshold: usize) -> Self {
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = rng.gen();
        let dst = "BLS_SIG_DST";
        let secret_key =
            SecretKey::key_gen(&seed, dst.as_bytes()).expect("Private key generation error");
        let public_key = secret_key.sk_to_pk();

        debug!("public key: {:?}", public_key);

        GlobalState {
            dag: RwLock::new(DAG::default()),
            validator_state: Arc::new(RwLock::new(ValidatorState::default())),
            key_pair: KeyPair::new(secret_key, public_key, dst.into()),
            threshold,
            known_nodes: Arc::new(RwLock::new(HashMap::new())),
            dst: dst.to_string(),
        }
    }

    pub fn get_dst(&self) -> String {
        self.dst.clone()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.key_pair
            .secret_key
            .sign(msg, self.key_pair.dst.as_bytes(), &[])
    }

    pub fn sign_candidate(&self, candidate: &Candidate) -> Result<Signature, &'static str> {
        let data = bincode::serialize(&candidate).map_err(|_| "Failed to serialize vertex")?;

        // Correctly return Signature wrapped in Result::Ok()
        Ok(self.sign(&data)) // make sure you return Signature and not empty type
    }

    pub async fn check_vertex(&self, id: &VertexHash) -> bool {
        match self.dag.read().await.get(id) {
            Some(_) => true,
            None => false,
        }
    }

    /// Adds a list of nodes (address, public key) to the known nodes.
    ///
    /// @param nodes A vector of tuples containing the address and public key of each node to add.
    pub async fn add_nodes(&self, nodes: Vec<(String, PublicKey)>) {
        let mut known_nodes = self.known_nodes.write().await; // Lock the map for writing

        for (address, public_key) in nodes {
            known_nodes.insert(address.clone(), public_key); // Insert each node into the map
            debug!("{:?} => {:?}", address.to_string(), public_key);
        }
    }

    /// Returns a list of all registered nodes (address and public key).
    ///
    /// @return A vector of tuples containing the address and public key of each known node.
    pub async fn get_all_nodes(&self) -> Vec<(String, PublicKey)> {
        let known_nodes = self.known_nodes.read().await; // Lock the map for reading

        // Collect all (address, public_key) pairs into a vector
        known_nodes
            .iter()
            .map(|(address, public_key)| (address.clone(), public_key.clone()))
            .collect()
    }

    /// Registers a new node's public key with its address.
    ///
    /// @param address The address of the node (IP:port).
    /// @param public_key The public key of the node.
    pub async fn register_node(&self, address: String, public_key: PublicKey) -> bool {
        let mut known_nodes = self.known_nodes.write().await;
        let was_inserted = known_nodes.insert(address.clone(), public_key).is_none();
        if was_inserted {
            info!(
                "Registered new node with address {} and public key {:?}",
                address, public_key
            );
        } else {
            info!(
                "Node with address {} already exists. Public key: {:?}",
                address, public_key
            );
        }
        was_inserted
    }

    /// Retrieves the public key of a node by its address.
    ///
    /// @param address The address of the node (IP:port).
    /// @return An optional reference to the public key, if the node exists.
    pub async fn get_node_public_key(&self, address: &str) -> Option<PublicKey> {
        let known_nodes = self.known_nodes.read().await;
        known_nodes.get(address).cloned()
    }

    /// Registers a new candidate from the provided transactions and registers it in the validator state.
    /// This method will derive the necessary information (such as the creator and references)
    /// from the local state of the validator.
    ///
    /// @param transactions The transactions that will form the payload of the new candidate.
    pub async fn register_candidate(
        &self,
        transactions: Vec<Transaction>,
        socket: Arc<UdpSocket>,
    ) -> bool {
        let result;
        let flag;

        let creator = self.key_pair.public_key.clone();

        let current_round = self
            .dag
            .read()
            .await
            .get_current_round(creator.to_bytes().to_vec());

        info!(
            "starting generating new candidate for round: {}",
            current_round
        );

        // Step 2: Generate a unique vertex ID for the candidate
        let vertex_id = self.generate_vertex_id(&transactions);

        // Step 3: Determine the references for the candidate
        let mut references: BTreeMap<Vec<u8>, VertexHash> = BTreeMap::new();

        if self.known_nodes.read().await.len() >= self.threshold {
            // If current_round is greater than 0, we can fetch the references from the previous round
            if current_round > 0 {
                references = self
                    .dag
                    .read()
                    .await
                    .get_creator_vertices_by_round(current_round - 1);

                //info!("references: {}", references.len());

                if references.len() > self.known_nodes.read().await.len() / 2 {
                    flag = true;
                } else {
                    flag = false;
                }
            } else {
                flag = true;
            }

            if flag {
                // Step 4: Create a new Candidate
                let candidate = Arc::new(Candidate::new(
                    vertex_id,
                    creator,
                    transactions,
                    current_round,
                    references,
                ));

                // Step 5: Register the candidate in the validator state
                let threshold = self.threshold;

                self.validator_state
                    .write()
                    .await
                    .register_candidate(candidate.clone(), threshold);

                let peers = self.known_nodes.clone();

                broadcast_candidate(peers, candidate.clone(), &socket).await;
            } else {
                warn!("candidate generation error: insufficient number of vertices to satisfy consensus criterion, ref: {}", references.len());
            }
            result = true;
        } else {
            result = false;
        }

        result
    }

    /// Generates a vertex ID for a given set of transactions.
    /// This method can generate a unique hash for the candidate.
    fn generate_vertex_id(&self, transactions: &[Transaction]) -> VertexHash {
        // Serialize the transactions using bincode or serde
        let serialized_data =
            bincode::serialize(transactions).expect("Failed to serialize transactions");

        // Create the SHA256 hash of the serialized transactions
        let mut hasher = Sha256::new();
        hasher.update(serialized_data);
        let result = hasher.finalize();

        result.to_vec() // Return the hash as a vector of bytes
    }

    pub fn get_public_key(&self) -> PublicKey {
        self.key_pair.public_key
    }

    pub async fn add_signature(&self, validator_pk: PublicKey, signature: Vec<u8>) {
        match &mut self.validator_state.write().await.consensus {
            Some(consensus) => {
                consensus.add_signature(validator_pk, signature);
            }
            None => {
                warn!("Validator has no item which is in consensus phase");
            }
        };
    }

    /// Broadcasts a signed consensus message containing a vertex to all known nodes.
    ///
    /// @param socket The UDP socket used to send messages.
    /// @param vertex The vertex to be included in the consensus message.
    pub async fn broadcast_consensus_message(&self, socket: &UdpSocket, vertex: Vertex) {
        // Create a consensus signed message containing the vertex
        let message: MessageType = MessageType::ConsensusSignedMessage(vertex);

        // Serialize the message to bytes
        let serialized = match bincode::serialize(&message) {
            Ok(data) => data,
            Err(err) => {
                error!("Failed to serialize consensus message: {:?}", err);
                return;
            }
        };

        // Get the list of known nodes
        let nodes = self.get_all_nodes().await;

        // Iterate over all nodes and send the message
        for (node_address, _) in nodes {
            debug!(
                "message sent to: {}, size: {}",
                node_address,
                serialized.len()
            );
            if let Err(err) = socket.send_to(&serialized, &node_address).await {
                error!("Failed to send message to {}: {:?}", node_address, err);
            } else {
                info!("Message broadcasted to {}", node_address);
            }
        }
    }
}
