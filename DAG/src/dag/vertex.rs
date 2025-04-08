use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::candidate::Candidate;

/// Represents a hash value.
pub type VertexHash = Vec<u8>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub(crate) id: u64,
    pub(crate) data: String,
}

/// Represents the state of a vertex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vertex {
    /// Hash identifier of the vertex.
    pub id: VertexHash,

    /// Public key of the creator.
    pub creator: Vec<u8>,

    /// References to other vertices. key = node, value = vertice
    pub references: BTreeMap<Vec<u8>, Vec<u8>>,

    /// Payload of the vertex.
    pub transactions: Vec<Transaction>,

    /// The aggregated signature (if consensus is reached)
    pub aggregate_signature: Option<Vec<u8>>,

    /// Signatures provided by validators
    pub signatures: BTreeMap<Vec<u8>, Vec<u8>>, // PublicKey -> Signature

    /// Round number
    pub round_no: usize,

    /// Timestamp
    pub timestamp: u64,
}

impl Vertex {
    pub fn from_candidate(
        candidate: &Candidate,
        signatures: BTreeMap<Vec<u8>, Vec<u8>>,
        aggregate_signature: Option<Vec<u8>>,
    ) -> Self {
        Self {
            timestamp: candidate.timestamp,
            id: candidate.id.clone(),
            creator: candidate.creator.to_bytes().to_vec(),
            references: candidate.references.clone(),
            transactions: candidate.transactions.clone(),
            aggregate_signature: aggregate_signature,
            signatures,
            round_no: candidate.round_no,
        }
    }
}
