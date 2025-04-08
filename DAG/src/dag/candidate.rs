use super::vertex::{Transaction, Vertex, VertexHash};
use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Enum representing the status of a candidate.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default, Clone)]
pub enum CandidateStatus {
    /// The candidate is waiting for consensus.
    #[default]
    Waiting,

    /// The candidate has been committed.
    Committed,
}

/// Represents a candidate for consensus. This could be a vertex that has been created by a validator
/// but is not yet fully committed.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Candidate {
    /// The unique identifier (hash) of the candidate.
    pub id: VertexHash,

    /// The public key of the validator who created this candidate.
    pub creator: PublicKey,

    /// References to other vertices that are part of the consensus.
    /// key = node, value = vertice
    pub references: BTreeMap<Vec<u8>, Vec<u8>>,

    /// The status of the candidate (whether it is still a candidate or has been committed).
    pub status: CandidateStatus,

    /// The signature for the candidate
    pub signature: Option<Vec<u8>>,

    /// Payload of the vertex.
    pub transactions: Vec<Transaction>,

    /// The timestamp indicating when the candidate was created.
    pub timestamp: u64, // Unix timestamp (seconds since epoch)

    // Round number
    pub round_no: usize,
}

impl Candidate {
    /// Creates a new candidate.
    ///
    /// # Arguments
    /// * `id` - The unique identifier (hash) of the candidate.
    /// * `creator` - The public key of the validator who created this candidate.
    ///
    /// # Returns
    /// A new Candidate.
    pub fn new(
        id: VertexHash,
        creator: PublicKey,
        transactions: Vec<Transaction>,
        round_no: usize,
        references: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Self {
        let timestamp = chrono::Utc::now().timestamp() as u64; // Get the current timestamp in seconds.

        Candidate {
            id,
            creator,
            references,
            status: CandidateStatus::Waiting,
            signature: None,
            transactions,
            timestamp,
            round_no,
        }
    }

    /// Updates the status of the candidate to committed.
    pub fn commit(&mut self) {
        self.status = CandidateStatus::Committed;
    }

    /// Verifies the signature of the candidate using the creator's public key
    pub fn verify_signature(&self, public_key: PublicKey) -> bool {
        // Check if the signature is present
        if let Some(signature_bytes) = &self.signature {
            // Create the signature object from bytes
            let signature = Signature::from_bytes(signature_bytes).unwrap();

            let msg = Candidate::from_candidate(self.clone()).to_bytes().unwrap();

            let dst = "BLS_SIG_DST";

            // Verify the signature using the public key
            let valid = signature.verify(false, &msg, &dst.as_bytes(), &[], &public_key, false);

            valid == BLST_ERROR::BLST_SUCCESS
        } else {
            debug!("no signature found");
            false
        }
    }

    fn from_candidate(candidate: Candidate) -> Self {
        Self {
            id: candidate.id.clone(),
            creator: candidate.creator,
            references: candidate.references,
            status: CandidateStatus::Waiting,
            signature: None,
            transactions: candidate.transactions,
            timestamp: candidate.timestamp,
            round_no: candidate.round_no,
        }
    }

    pub fn from_vertex(vertex: Vertex) -> Self {
        Self {
            id: vertex.id,
            creator: PublicKey::deserialize(&vertex.creator).unwrap(), // To be modified
            references: vertex.references,
            status: CandidateStatus::Waiting,
            signature: None,
            transactions: vertex.transactions,
            timestamp: vertex.timestamp,
            round_no: vertex.round_no,
        }
    }

    /// Converts the Candidate struct to a byte array
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let encoded: Vec<u8> = bincode::serialize(self)?;
        Ok(encoded)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateForSigning {}
