use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;

fn main() {
    let price = 100_000_000u64;
    // Bullet proof range verification for prices
    ed25519::price(price);
    // bellman::execute();
    // example::run();
}

// bulletproof numerics
mod ed25519 {
    use super::*;
    use bincode::serialize;
    use bulletproofs::ProofError;
    use curve25519_dalek_ng::ristretto::CompressedRistretto;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct ZKPReceiverPayload {
        pub committed_value: String,
        pub bit_size: usize,
        pub transcript_name: String,
    }

    pub fn price(price: u64) {
        // These should be constants in your application.
        let bit_size: usize = 32;
        let gens_capacity: usize = 64;
        let party_capacity: usize = 1;

        let transcript_name = b"ProverTranscript1";

        // These are the parameters for the curve
        // Construct these on sender's node
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(gens_capacity, party_capacity);
        let blinding = Scalar::random(&mut thread_rng());

        let mut prover_transcript = Transcript::new(transcript_name);

        // Create a proof
        // Since this is a price its a single proof
        let (proof, committed_value) = create_single_proof(
            price,
            bit_size,
            &pc_gens,
            &bp_gens,
            &blinding,
            &mut prover_transcript,
        )
        .unwrap();

        // Prepared by the source node which expected verification from a receiver's node

        let creator_payload = ZKPReceiverPayload {
            committed_value: hex::encode(committed_value.to_bytes().to_vec()),
            bit_size,
            transcript_name: hex::encode(b"ProverTranscript1".to_vec()),
        };

        println!("Creator Payload: {:?}", creator_payload);
        /*
        Send above as a JSON payload to the verifier
        Example Play load (Send Values as hex encoded bytes)
        "CreatorPayload: "{
               "committed_value":"7084b49153cd2b959d127dc611f219b6ee231a105cc7f56657fb109d5fa1561a",
               "bit_size":32,
               "transcript_name":"50726f7665725472616e73637269707431"
            }
        */

        // Verifier node can initiate these values
        let v_transcript_name_bytes = hex::decode(creator_payload.transcript_name).unwrap();

        let v_transcript_name: &'static [u8] =
            Box::leak(v_transcript_name_bytes.into_boxed_slice());

        // Construct required params in verifier node
        let v_bit_size = creator_payload.bit_size;
        let v_committed_value =
            CompressedRistretto::from_slice(&hex::decode(creator_payload.committed_value).unwrap());
        let mut v_transcript = Transcript::new(v_transcript_name);

        let verifier_pc_gens = PedersenGens::default();
        let verifier_bp_gens = BulletproofGens::new(64, 1);
        let mut verifier_transcript = Transcript::new(b"ProverTranscript1");

        let results = verify_proof(
            proof,
            v_bit_size,
            &v_committed_value,
            &mut v_transcript,
            &verifier_pc_gens,
            &verifier_bp_gens,
        );

        println!("Verified Results: {:?}", results);
        assert!(results.is_ok());
    }

    /// Verify a single proof
    /// # Arguments
    /// * `proof` - Proof to be verified
    /// * `v_bit_size` - Bit size of the price
    /// * `v_committed_value` - Committed value
    /// * `v_transcript` - Transcript
    /// * `verifier_pc_gens` - Pedersen Gens
    /// * `verifier_bp_gens` - Bulletproof Gens
    /// # Returns
    /// * `Result<(), ProofError>` - Result of the verification
    fn verify_proof(
        proof: RangeProof,
        v_bit_size: usize,
        v_committed_value: &CompressedRistretto,
        mut v_transcript: &mut Transcript,
        verifier_pc_gens: &PedersenGens,
        verifier_bp_gens: &BulletproofGens,
    ) -> Result<(), ProofError> {
        proof.verify_single(
            &verifier_bp_gens,
            &verifier_pc_gens,
            &mut v_transcript,
            &v_committed_value,
            v_bit_size,
        )
    }

    /// Create a single proof
    /// # Arguments
    /// * `price` - Price to be verified
    /// * `bit_size` - Bit size of the price
    /// * `pc_gens` - Pedersen Gens
    /// * `bp_gens` - Bulletproof Gens
    /// * `blinding` - Blinding factor
    fn create_single_proof(
        price: u64,
        bit_size: usize,
        pc_gens: &PedersenGens,
        bp_gens: &BulletproofGens,
        blinding: &Scalar,
        mut prover_transcript: &mut Transcript,
    ) -> Result<(RangeProof, CompressedRistretto), ProofError> {
        RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            price,
            &blinding,
            bit_size,
        )
    }

    pub fn verify_struct() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct Alpha {
            field_a: u128,
            field_b: String,
            field_c: Vec<u8>,
        }

        let alpha = Alpha {
            field_a: 0,
            field_b: "".to_string(),
            field_c: vec![],
        };

        let secrets = serialize(&alpha).unwrap();

        let blindings: Vec<_> = (0..4).map(|_| Scalar::random(&mut thread_rng())).collect();
        // let blinding = Scalar::random(&mut thread_rng());
        let mut prover_transcript = Transcript::new(b"ProverTranscript1");
    }
}
mod example {
    use bellman::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            multipack,
            sha256::sha256,
        },
        groth16, Circuit, ConstraintSystem, SynthesisError,
    };
    use bls12_381::Bls12;
    use ff::PrimeField;
    use pairing::Engine;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Our own SHA-256d gadget. Input and output are in little-endian bit order.
    fn sha256d<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        data: &[Boolean],
    ) -> Result<Vec<Boolean>, SynthesisError> {
        // Flip endianness of each input byte
        let input: Vec<_> = data
            .chunks(8)
            .map(|c| c.iter().rev())
            .flatten()
            .cloned()
            .collect();

        let mid = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;
        let res = sha256(cs.namespace(|| "SHA-256(mid)"), &mid)?;

        // Flip endianness of each output byte
        Ok(res
            .chunks(8)
            .map(|c| c.iter().rev())
            .flatten()
            .cloned()
            .collect())
    }

    struct MyCircuit {
        /// The input to SHA-256d we are proving that we know. Set to `None` when we
        /// are verifying a proof (and do not have the witness data).
        preimage: Option<[u8; 80]>,
    }
    impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
        fn synthesize<CS: ConstraintSystem<Scalar>>(
            self,
            cs: &mut CS,
        ) -> Result<(), SynthesisError> {
            // Compute the values for the bits of the preimage. If we are verifying a proof,
            // we still need to create the same constraints, so we return an equivalent-size
            // Vec of None (indicating that the value of each bit is unknown).
            let bit_values = if let Some(preimage) = self.preimage {
                preimage
                    .into_iter()
                    .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                    .flatten()
                    .map(|b| Some(b))
                    .collect()
            } else {
                vec![None; 80 * 8]
            };
            assert_eq!(bit_values.len(), 80 * 8);

            // Witness the bits of the preimage.
            let preimage_bits = bit_values
                .into_iter()
                .enumerate()
                // Allocate each bit.
                .map(|(i, b)| {
                    AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b)
                })
                // Convert the AllocatedBits into Booleans (required for the sha256 gadget).
                .map(|b| b.map(Boolean::from))
                .collect::<Result<Vec<_>, _>>()?;

            // Compute hash = SHA-256d(preimage).
            let hash = sha256d(cs.namespace(|| "SHA-256d(preimage)"), &preimage_bits)?;

            // Expose the vector of 32 boolean variables as compact public inputs.
            multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
        }
    }

    pub fn run() {
        // Create parameters for our circuit. In a production deployment these would
        // be generated securely using a multiparty computation.
        let params = {
            let c = MyCircuit { preimage: None };
            groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
        };

        // Prepare the verification key (for proof verification).
        let pvk = groth16::prepare_verifying_key(&params.vk);

        // Pick a preimage and compute its hash.
        let preimage = [42; 80];
        let hash = Sha256::digest(&Sha256::digest(&preimage));

        // Create an instance of our circuit (with the preimage as a witness).
        let c = MyCircuit {
            preimage: Some(preimage),
        };

        // Create a Groth16 proof with our parameters.
        let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

        // Pack the hash as inputs for proof verification.
        let hash_bits = multipack::bytes_to_bits_le(&hash);
        let inputs = multipack::compute_multipacking(&hash_bits);
        let result = groth16::verify_proof(&pvk, &proof, &inputs).is_ok();
        // Check the proof!
        println!("Proof result: {:?}", result);
        assert!(result);
    }
}
mod bellman {

    use bincode::{deserialize, serialize};
    use serde::{Deserialize, Serialize};

    use bellman::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            multipack,
            sha256::sha256,
        },
        groth16, Circuit, ConstraintSystem, SynthesisError,
    };
    use bls12_381::Bls12;
    use ff::PrimeField;
    use pairing::Engine;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Alpha {
        field_a: u128,
        field_b: String,
        field_c: Vec<u8>,
    }
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct AlphaCircuit {
        preimage: Option<Vec<u8>>,
    }

    impl<Scalar: PrimeField> Circuit<Scalar> for AlphaCircuit {
        fn synthesize<CS: ConstraintSystem<Scalar>>(
            self,
            cs: &mut CS,
        ) -> Result<(), SynthesisError> {
            let bit_values = if let Some(preimage) = self.preimage {
                preimage
                    .into_iter()
                    .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                    .flatten()
                    .map(|b| Some(b))
                    .collect()
            } else {
                vec![None; 80 * 8]
            };
            assert_eq!(bit_values.len(), 80 * 8);

            // Witness the bits of the preimage.
            let preimage_bits = bit_values
                .into_iter()
                .enumerate()
                // Allocate each bit.
                .map(|(i, b)| {
                    AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b)
                })
                // Convert the AllocatedBits into Booleans (required for the sha256 gadget).
                .map(|b| b.map(Boolean::from))
                .collect::<Result<Vec<_>, _>>()?;

            // Compute hash = SHA-256d(preimage).
            let hash = sha256d(cs.namespace(|| "SHA-256d(preimage)"), &preimage_bits)?;

            // Expose the vector of 32 boolean variables as compact public inputs.
            multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
        }
    }

    fn sha256d<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        data: &[Boolean],
    ) -> Result<Vec<Boolean>, SynthesisError> {
        // Flip endianness of each input byte
        let input: Vec<_> = data
            .chunks(8)
            .map(|c| c.iter().rev())
            .flatten()
            .cloned()
            .collect();

        let mid = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;
        let res = sha256(cs.namespace(|| "SHA-256(mid)"), &mid)?;

        // Flip endianness of each output byte
        Ok(res
            .chunks(8)
            .map(|c| c.iter().rev())
            .flatten()
            .cloned()
            .collect())
    }

    pub fn execute() {
        use bls12_381::Scalar;
        // Initialize structure
        let alpha = Alpha {
            field_a: 1234567890,
            field_b: "Hello World".to_string(),
            field_c: vec![1, 2, 3],
        };

        let alpha_bytes = serialize(&alpha).unwrap();

        // Create instance of the circuit
        let alpha_circuit = AlphaCircuit {
            preimage: Some(alpha_bytes),
        };

        let alpha_circle_bytes = serialize(&alpha_circuit).unwrap();
        let hash = Sha256::digest(&alpha_circle_bytes);

        // This creates a Verifying key
        let params = {
            let c = AlphaCircuit { preimage: None };
            groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
        };

        // Verifying Key | Secret key is getting created using actual data
        let pvk = groth16::prepare_verifying_key(&params.vk);

        let proof = groth16::create_random_proof(alpha_circuit, &params, &mut OsRng).unwrap();
        let hash_bits = multipack::bytes_to_bits_le(&hash);
        let inputs: Vec<Scalar> = multipack::compute_multipacking(&hash_bits);

        let result = groth16::verify_proof(&pvk, &proof, &inputs);
        println!("Proof result: {:?}", result);
        assert!(result.is_ok());
    }
}

mod secp {
    use super::*;
    use secp256k1::{rand::thread_rng, PublicKey, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    pub fn verify_struct() {
        struct DTO {
            pub attribute_one: Vec<u8>,
            pub attribute_two: String,
            pub attribute_three: u128,
        }
        let pc_gens = PedersenGens::default();
        let secp = Secp256k1::new();
        let bp_gens = BulletproofGens::new(64, 1);
        let dto = DTO {
            attribute_one: vec![1, 2, 3],
            attribute_two: "Data Transfer Object".to_string(),
            attribute_three: 1234567890,
        };

        let mut prover_transcript = Transcript::new(b"SECP_TRANSCRIPT");
    }
    /*
    fn bulletproof(
        secrets: Vec<u8>,
        blindings: Vec<Scalar>,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
    ) -> (RangeProof, Scalar) {
        let mut commitments = Vec::new();
        for (secret, blinding) in secrets.iter().zip(blindings.iter()) {
            let x = pc_gens.commit(Scalar::from(*secret), *blinding);
            commitments.push(x);
        }
        let pc_gens = PedersenGens::default();
        let (proof, committed_value) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            transcript,
            &blindings,
            &commitments,
        )
            .expect("Failed to create range proof");

        (proof, committed_value)
    }
    */
}
