## Project DAG - WIP

A **DAG** (Directed Acyclic Graph) is a data structure consisting of vertices (nodes) connected by directed edges, with the additional condition that the graph is acyclic, meaning it does not contain cycles. In other words, there is no way to start at one vertex and return to it by following the edges.

In the context of blockchain technology, a DAG is sometimes used as an alternative to traditional blockchains. Instead of having a linear structure where each block refers to the previous one, in a DAG each vertex can be connected to multiple other vertices, creating a branching structure. This allows for greater scalability and parallelism, as different vertices can be added to the structure simultaneously without having to wait for a block in the chain.

### Advantages of DAG:

- **No locks**: Since blocks do not need to be processed sequentially, many transactions can occur simultaneously.
- **Better scalability**: Due to parallel transaction processing, a DAG can handle a larger number of operations per second.
- **Lower latency**: In a DAG, each new vertex (e.g., a transaction) is directly added to the graph, resulting in shorter waiting times for confirmation.

In blockchain applications, DAG is used in projects like **IOTA** and **Nano**.

## To run this:

You need at least 4 instances of this application. The recommended setup is to run 1 instance in master mode, and the other instances in secondary mode:

- **Master**:  
  `cargo run -- --port 8080 --auto-generate-vertices --verbosity debug`

- **Secondary**:  
  `cargo run -- --port 8081 --initial-peers 127.0.0.1:8080 --auto-generate-vertices --verbosity debug`

As you can see, the master instance has no peers defined, while the secondary instances should include a list of initial peers. You can provide only 1 IP address to the master. After connecting a new instance, all instances will be updated automatically.

After pressing **CTRL+C**, a new file will be generated in the executable folder containing...


# Key Principles of DAG Mechanism

## No Leader:
- Every node in the network has equal rights to generate candidates for new DAG vertices.
- There is no central node coordinating the consensus process.

## Condition for Creating a Candidate:
- A node can create a new candidate for a vertex only after the consensus on its previous candidate has been completed.
- This ensures that a node does not "flood" the network with new vertices before they have been accepted by other nodes.

## References to Other Vertices:
- A candidate must have references to at least a threshold number of vertices created by other nodes in the same round.
- This enforces mutual data confirmation in the network and ensures that nodes must cooperate.

## Rounds in Consensus:
- Each candidate is assigned to a specific consensus round, marked as n+1.
- References in the candidate must point to vertices created in round n, which enforces the chronology of the process and prevents chaotic vertex creation.

## Signature Verification:
- A candidate sent to other nodes is digitally signed, and the recipient verifies the signature using the sender's public key.
- This ensures data integrity and the authenticity of its origin.
