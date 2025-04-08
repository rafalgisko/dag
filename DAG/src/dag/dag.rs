use std::collections::BTreeMap;
// Implementation of the DAG and Validator State structures
// using idiomatic Rust.
use log::{debug, error};
use std::io::{self, Write};
/// This code uses doxygen-style comments for documentation.
use std::{collections::HashMap, fs::File};

use super::vertex::{Vertex, VertexHash};

/// Represents the global state of the DAG.
#[derive(Debug, Default)]
pub struct DAG {
    /// Stores all vertices in the DAG.
    vertices: HashMap<VertexHash, Vertex>,

    /// Maps a creator's public key to the list of hashes of their vertices.
    pub creator_index: HashMap<Vec<u8>, Vec<VertexHash>>,

    /// Maps round numbers to lists of vertex hashes created in those rounds.
    round_index: HashMap<usize, Vec<VertexHash>>,
}

impl DAG {
    /**
     * Validates the references of a vertex.
     *
     * @param vertex The vertex whose references are to be validated.
     * @param threshold The minimum number of references required for rounds > 0.
     * @return `true` if all references are valid, `false` otherwise.
     */
    pub fn validate_references(&self, vertex: &Vertex, threshold: usize) -> bool {
        // Check that each reference is valid and satisfies all conditions
        vertex.references.iter().all(|(creator, reference_hash)| {
            match self.vertices.get(reference_hash) {
                Some(reference_vertex) => {
                    // Ensure the reference is from the same round
                    if reference_vertex.round_no != vertex.round_no - 1 {
                        error!(
                            "Invalid reference: vertex {:?} is from round {}, expected round {}.",
                            reference_hash, reference_vertex.round_no, vertex.round_no
                        );
                        return false;
                    }

                    // Ensure references come from different creators
                    if let Some(creator_hashes) = self.creator_index.get(creator) {
                        if !creator_hashes.contains(reference_hash) {
                            error!(
                                "Invalid reference: vertex {:?} not created by expected creator {:?}.",
                                reference_hash, creator
                            );
                            return false;
                        }
                    }
                    true
                }
                None => {
                    error!("Reference vertex not found in the DAG: {:?}", reference_hash);
                    false
                }
            }
        }) && (vertex.round_no == 0 || vertex.references.len() >= threshold)
    }

    pub fn save_vertices_by_creator_and_round(&self, filename: &str) -> io::Result<()> {
        let mut file = File::create(filename)?;

        // Collect all unique creators
        let mut creators: Vec<Vec<u8>> = self.creator_index.keys().cloned().collect();
        creators.sort(); // Sort creators to keep vertices of the same creator grouped together

        // Iterate over creators and save their vertices, sorted by round
        for creator in creators {
            if let Some(vertex_hashes) = self.creator_index.get(&creator) {
                let mut creator_vertices: Vec<Vertex> = vertex_hashes
                    .iter()
                    .filter_map(|hash| self.vertices.get(hash))
                    .cloned()
                    .collect();

                // Sort vertices by round number
                creator_vertices.sort_by_key(|v| v.round_no);

                // Save the vertices of this creator in the correct order
                for vertex in creator_vertices {
                    writeln!(
                        file,
                        "Creator: {:?}, Round: {}, Vertex ID: {:?}, Transactions: {:?}",
                        creator, vertex.round_no, vertex.id, vertex.transactions
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Inserts a new vertex into the DAG.
    /// @param vertex The vertex to be added.
    pub fn insert_vertex(&mut self, vertex: &Vertex) {
        // Add the vertex to the main storage.
        self.vertices.insert(vertex.id.clone(), vertex.clone());

        // Update the creator index.
        self.creator_index
            .entry(vertex.creator.clone())
            .or_insert_with(Vec::new)
            .push(vertex.id.clone());

        // Handle round-based reference management
        let round = vertex.round_no;

        // Retrieve previous round vertices from the creator's index
        let previous_round_vertices = self.get_creator_vertices_by_round(round);

        // Update the round index
        self.round_index
            .entry(round)
            .or_insert_with(Vec::new)
            .push(vertex.id.clone());

        debug!("updating references in vertex for round ({})", round,);

        // Ensure references to previous round vertices are properly assigned
        self.update_references_for_vertex(&vertex, previous_round_vertices);
    }

    /// Updates the references of the vertex according to the vertices from previous rounds.
    fn update_references_for_vertex(
        &mut self,
        vertex: &Vertex,
        previous_round_vertices: BTreeMap<Vec<u8>, VertexHash>,
    ) {
        // If there are previous round vertices, assign them as references
        if !previous_round_vertices.is_empty() {
            //let mut references = Vec::new();
            //for prev_vertex in previous_round_vertices {
            //    references.push(prev_vertex.clone()); // Add each reference as a Vec<u8>
            //}

            // Update the vertex with its references
            let mut updated_vertex = vertex.clone();
            updated_vertex.references = previous_round_vertices;

            // Insert the updated vertex with references back into the DAG
            self.vertices
                .insert(updated_vertex.id.clone(), updated_vertex);
        }
    }

    /// Gets the current round for a given creator based on the vertex creation order.
    pub fn get_current_round(&self, creator: Vec<u8>) -> usize {
        let creator_vertices = self.creator_index.get(&creator);

        // If no previous vertices, it is the first round
        match creator_vertices {
            Some(vertices) => vertices.len(),
            None => 0, // First round for the creator
        }
    }

    /// Retrieves a vertex by its hash identifier.
    /// @param id The hash of the vertex to retrieve.
    /// @return An optional reference to the vertex.
    pub fn get(&self, id: &VertexHash) -> Option<&Vertex> {
        self.vertices.get(id)
    }

    /// Retrieves all vertices created by a specific creator.
    /// @param creator The public key of the creator.
    /// @return A vector of references to vertices created by the given creator.
    pub fn get_vertices_by_creator(&self, creator: &Vec<u8>) -> Vec<&Vertex> {
        self.creator_index
            .get(creator)
            .into_iter()
            .flat_map(|hashes| hashes.iter().filter_map(|hash| self.get(hash)))
            .collect()
    }

    /// Retrieves a HashMap of creators' public keys to their respective VertexHash for a given round.
    ///
    /// This method iterates through the vertices created in the specified round, fetching the creator's
    /// public key and associating it with the corresponding vertex hash.
    ///
    /// @param round The round number to filter the vertices by.
    ///
    /// @return A HashMap where the key is the creator's public key (Vec<u8>) and the value is the
    ///         corresponding VertexHash. The map contains only vertices created in the specified round.
    pub fn get_creator_vertices_by_round(&self, round: usize) -> BTreeMap<Vec<u8>, VertexHash> {
        let mut creator_vertices: BTreeMap<Vec<u8>, VertexHash> = BTreeMap::new();

        // Retrieve the list of vertex hashes created in the specified round
        if let Some(vertex_hashes) = self.round_index.get(&round) {
            debug!("round index: {}", vertex_hashes.len());
            for vertex_hash in vertex_hashes {
                // Get the vertex for each hash
                if let Some(vertex) = self.vertices.get(vertex_hash) {
                    // Get the creator's public key and map it to the vertex hash
                    creator_vertices.insert(vertex.creator.clone(), vertex_hash.clone());
                }
            }
        }

        creator_vertices
    }
}
