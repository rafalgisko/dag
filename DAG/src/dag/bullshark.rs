use blst::min_pk::{AggregateSignature, PublicKey, Signature};
use log::debug;
use std::{collections::BTreeMap, sync::Arc};

use super::candidate::{Candidate, CandidateStatus};

/// Represents the state of a validator in the consensus process.
#[derive(Debug, Default)]
pub struct ValidatorState {
    /// Consensus as part of the Bullshark consensus process
    pub consensus: Option<BullsharkConsensus>,
}

#[derive(Debug, Clone)]
pub struct BullsharkConsensus {
    /// The candidate for consensus.
    candidate: Option<Candidate>,

    /// The signatures gathered during consensus.
    signatures: BTreeMap<Vec<u8>, Vec<u8>>,

    /// The minimum number of signatures needed for consensus.
    threshold: usize,
}

impl BullsharkConsensus {
    // Creates a new BullsharkConsensus for a candidate.
    pub fn new(candidate: Candidate, threshold: usize) -> Self {
        BullsharkConsensus {
            candidate: Some(candidate),
            signatures: BTreeMap::new(),
            threshold,
        }
    }

    pub fn get_signatures(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.signatures.clone()
    }

    /// Adds a signature to the candidate.
    pub fn add_signature(&mut self, public_key: PublicKey, signature: Vec<u8>) {
        if let Some(candidate) = &self.candidate {
            if candidate.status == CandidateStatus::Waiting {
                let pk = public_key.to_bytes();
                self.signatures.insert(pk.to_vec(), signature);
            }
        }
    }

    /// Checks if the consensus is reached (i.e., the number of signatures meets the threshold).
    pub fn is_consensus_reached(&self) -> bool {
        self.signatures.len() >= self.threshold
    }

    /// Marks the candidate as committed if the consensus is reached.
    pub fn commit(&mut self) -> bool {
        let mut result = false;
        if self.is_consensus_reached() {
            if let Some(candidate) = &mut self.candidate {
                candidate.commit();
                result = true;
            }
        }
        result
    }

    pub fn aggregate_signatures(&self, signatures: &Vec<Signature>) -> Option<Signature> {
        if signatures.is_empty() {
            return None;
        }

        let mut aggregated_signature = AggregateSignature::from_signature(&signatures[0]);

        for sig in &signatures[1..] {
            if let Err(_) = aggregated_signature.add_signature(sig, true) {
                return None;
            }
        }

        Some(Signature::from(aggregated_signature.to_signature()))
    }

    // Retrieves the aggregated signature once consensus is reached.
    pub fn get_aggregated_signature(&self) -> Option<Vec<u8>> {
        // Collect and filter signatures from the HashMap using filter_map
        let sigs: Vec<Signature> = self
            .signatures
            .values()
            .filter_map(|signature_bytes| Signature::from_bytes(signature_bytes).ok())
            .collect();

        // Check if the number of signatures meets the threshold
        if sigs.len() >= self.threshold {
            // Call the aggregate_signatures method to aggregate the signatures
            if let Some(aggregated_signature) = self.aggregate_signatures(&sigs) {
                Some(aggregated_signature.to_bytes().to_vec())
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl ValidatorState {
    /// Registers a new candidate in the validator state.
    ///
    /// This function registers a new candidate as part of the Bullshark consensus process.
    /// It creates a new `BullsharkConsensus` instance with the given candidate and threshold,
    /// and sets it within the validator's state. The candidate's references and round number are logged.
    ///
    /// @param candidate The candidate to register in the consensus process.
    /// @param threshold The minimum number of references required for this round.
    pub fn register_candidate(&mut self, candidate: Arc<Candidate>, threshold: usize) {
        // Clone the Candidate inside the Arc
        let vertex_cloned = (*candidate).clone();

        // Create a new BullsharkConsensus instance with the candidate
        let consensus = BullsharkConsensus::new(vertex_cloned, threshold);

        // Set the consensus in the validator state
        self.consensus = Some(consensus);

        debug!(
            "New candidate registered references: {}, round: {}",
            candidate.references.len(),
            candidate.round_no
        );
    }
}
