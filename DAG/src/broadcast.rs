use std::{collections::HashMap, sync::Arc};
use blst::min_pk::PublicKey;
use log::debug;
use tokio::{net::UdpSocket, sync::RwLock};
use log::{error, info, warn};
use crate::{dag::candidate::Candidate, state::global::GlobalState, MessageType};


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

