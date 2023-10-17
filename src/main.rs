use rand::thread_rng;
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

fn main() {

    ed25519::verify_random_u64_number();
}

mod secp {
    use super::*;
    use secp256k1::{rand::thread_rng, Secp256k1, SecretKey, PublicKey};
    use sha2::{Digest, Sha256};
    pub fn verify_struct (){
        struct DTO {
            pub attribute_one: Vec<u8>,
            pub attribute_two: String,
            pub attribute_three: u128,
        }

        let secp = Secp256k1::new();
        let bp_gens = BulletproofGens::new(64, 1);
        let dto = DTO {
            attribute_one: vec![1, 2, 3],
            attribute_two: "Data Transfer Object".to_string(),
            attribute_three: 1234567890,
        };

        let attr1 = hash_to_scalar(&dto.attribute_one);
        let attr2 = hash_to_scalar(&dto.attribute_two.into_bytes());
        let attr3 = Scalar::from(dto.attribute_three);


    }

    pub fn hash_to_scalar(data: &Vec<u8>) -> SecretKey {


        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);

        SecretKey::from_slice(&bytes).expect("Invalid hash")
    }

    fn create_range_proof(secp: &Secp256k1, bp_gens: &BulletproofGens, transcript: &mut Transcript, value: &SecretKey) -> (Rangeproof, SecretKey) {
        let proof = RangeProof::prove(secp, bp_gens, transcript, value, &SecretKey::random(&mut thread_rng())).expect("Failed to create range proof");
        let committed_value = secp.commit(value, SecretKey::random(&mut thread_rng())).expect("Failed to commit value");
        (proof, committed_value)
    }
}


mod ed25519 {
    use super::*;
    pub  fn verify_random_u64_number() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let secret_value = 1u64;
        let blinding = Scalar::random(&mut thread_rng());
        let mut prover_transcript = Transcript::new(b"ProverTranscript1");

        let (proof, committed_value) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            secret_value,
            &blinding,
            32,
        ).expect("Error");

        // Transfer the proof to the verifier
        // parameters:
        // 1. bp_gens: the BulletproofGens
        // 2. pc_gens: the PedersenGens
        // 3. verifier_transcript: the transcript
        // 4. committed_value: the Pedersen commitment
        // 5. used scalar value:- bit size
        // 7. transcript name as a string
        /*
        Send above as a JSON payload to the verifier
        Example Playload (Send Values as bytes)
        {
            "bp_gens": "BulletproofGens",
            "pc_gens": "PedersenGens",
            "verifier_transcript": "Transcript",
            "committed_value": "Pedersen commitment",
            "used_scalar_value": "bit size",
            "transcript_name": "string"
        }
        */
        let mut verifier_transcript = Transcript::new(b"ProverTranscript1");
        let results = proof
            .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 32);

        println!("results: {:?}", results);
        assert!(results.is_ok());
    }
}
