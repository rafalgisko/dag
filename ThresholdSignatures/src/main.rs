use blst::*;
use blst::{min_pk::{AggregateSignature, PublicKey, SecretKey, Signature}, BLST_ERROR};
use bc_shamir::split_secret;
use bc_rand::SecureRandomNumberGenerator;

const PARTICIPANTS: usize = 15; // Total number of participants
const THRESHOLD: usize = 10;    // Minimum number of participants required to sign


fn example_threshold() {
    ////////////////////////////////////////////////////////////////////////////////////////////
    // 1. Generate private keys for each participant
    let dst = b"BLS_SIG_DST"; // Domain Separation Tag
    let private_keys: Vec<SecretKey> = (0..PARTICIPANTS)
        .map(|i| {
            let seed = [i as u8; 32];
            SecretKey::key_gen(&seed, dst).expect("Key generation failed")
        })
        .collect();

    ////////////////////////////////////////////////////////////////////////////////////////////
    // 2. Compute public keys
    let public_keys: Vec<PublicKey> = private_keys.iter().map(|sk| sk.sk_to_pk()).collect();

    ////////////////////////////////////////////////////////////////////////////////////////////
    // 3. Define message to be signed
    let message = b"Secure threshold signing example";

    ////////////////////////////////////////////////////////////////////////////////////////////
    // 4. Sign the message using the minimum number of private keys (threshold)
    let mut aggregate_signature = AggregateSignature::from_signature(
        &private_keys[0].sign(message, dst, &[]),
    );

    for sk in private_keys.iter().skip(1).take(THRESHOLD - 1) {
        let partial_signature = sk.sign(message, dst, &[]);
        aggregate_signature
            .add_signature(&partial_signature, true)
            .expect("Failed to add signature");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    // 5. Convert to final aggregated signature
    let final_signature = aggregate_signature.to_signature();

    ////////////////////////////////////////////////////////////////////////////////////////////
    // 6. Prepare inputs for verification
    let public_keys_refs: Vec<&PublicKey> = public_keys.iter().take(THRESHOLD).collect();
    let messages_refs: Vec<&[u8]> = vec![message; THRESHOLD]; // Same message for all participants

    ////////////////////////////////////////////////////////////////////////////////////////////
    // 7. Verify the threshold signature
    let result = final_signature.aggregate_verify(
        true,
        &messages_refs,
        dst,
        &public_keys_refs,
        true,
    );

    if result == BLST_ERROR::BLST_SUCCESS {
        println!("Threshold signature verified successfully!");
    } else {
        println!("Threshold signature verification failed.");
    }
}

fn example_shamir_secret_key_sharing() {
    let dst = b"BLS_SIG_DST";

    // 1. Generate master key and public key
    let master_key = SecretKey::key_gen(&[0u8; 32], dst).expect("Failed to generate master key");
    let master_key_bytes = master_key.to_bytes();
    let public_key = master_key.sk_to_pk();
    println!("Master Key: {:?}", master_key);
    println!("Public Key: {:?}", public_key);

    // 2. Split the master key into secret shares using Shamir's Secret Sharing
    let mut rng = SecureRandomNumberGenerator {};
    let shares = split_secret(THRESHOLD, PARTICIPANTS, &master_key_bytes, &mut rng)
        .expect("Failed to split secret into shares");
    println!("Shares: {:?}", shares);

    // 3. Generate secret keys from shares
    let private_shares: Vec<SecretKey> = shares
        .iter()
        .map(|share| SecretKey::key_gen(share, dst).expect("Failed to generate private key share"))
        .collect();
    println!("Private Key Shares: {:?}", private_shares);

    // 4. Each participant signs the message with their private share
    let message = b"Secure threshold signing example";
    println!("\nMessage: {:?}\n", message);

    let partial_signatures: Vec<Signature> = private_shares
        .iter()
        .take(THRESHOLD)
        .map(|sk| {
            let sig = sk.sign(message, dst, &[]);
            println!("Partial Signature: {:?}", sig);
            sig
        })
        .collect();

    // 5. Aggregate the signatures
    let mut aggregate_signature = AggregateSignature::from_signature(&partial_signatures[0]);
    println!("Initial Aggregate Signature: {:?}", aggregate_signature);

    for sig in partial_signatures.iter().skip(1) {
        aggregate_signature
            .add_signature(sig, true)
            .expect("Failed to add signature");
    }
    println!("Final Aggregate Signature: {:?}", aggregate_signature);

    // 6. Verify the aggregated signature
    let final_signature = aggregate_signature.to_signature();
    let public_keys_refs: Vec<&PublicKey> = vec![&public_key; THRESHOLD];
    let messages_refs: Vec<&[u8]> = vec![message; THRESHOLD];

    let result = final_signature.aggregate_verify(
        true,                     // Enable group signature check
        &messages_refs,           // Messages (all the same in this case)
        dst,                      // Domain Separation Tag
        &public_keys_refs,        // Public keys (repeated)
        true,                     // Enable public key validation
    );

    if result == BLST_ERROR::BLST_SUCCESS {
        println!("Threshold signature verified successfully!");
    } else {
        println!("Threshold signature verification failed.");
        println!("Error Code: {:?}", result);
    }
}

fn example_unknown_signers() {
    // To be implemented: simulate unknown or dynamic set of signers
}

fn main() {
    example_threshold();
    // example_shamir_secret_key_sharing();
    // example_unknown_signers();
}
