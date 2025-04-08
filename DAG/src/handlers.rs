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
