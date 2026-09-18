// Copyright (c) 2026 Michael Wroblewski — Apache-2.0
//! Canonical Groth16 verifier and versioned circuit registry.

use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zkp_core::{CircuitDescriptor, ProofEnvelope, ProofError, ProofSystem};
use zkp_crypto::sha256;

pub const ACCEPTED_SYSTEM_ID: u8 = 1;
pub const CIRCUIT_ID_EQUALITY_SQUARE: u32 = 1;
pub const CIRCUIT_VERSION_EQUALITY_SQUARE: u32 = 1;

#[derive(Debug, Clone, Copy)]
pub struct RegisteredCircuit {
    pub descriptor: CircuitDescriptor,
}

pub fn verifying_key_hash(vk: &VerifyingKey<Bn254>) -> Result<[u8; 32], ProofError> {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)
        .map_err(|_| ProofError::VerificationFailed)?;
    sha256(&bytes).map_err(|_| ProofError::VerificationFailed)
}

pub fn register_equality_square(
    vk: &VerifyingKey<Bn254>,
) -> Result<RegisteredCircuit, ProofError> {
    let descriptor = CircuitDescriptor {
        circuit_id: CIRCUIT_ID_EQUALITY_SQUARE,
        version: CIRCUIT_VERSION_EQUALITY_SQUARE,
        verifying_key_hash: verifying_key_hash(vk)?,
    };
    descriptor.validate()?;
    Ok(RegisteredCircuit { descriptor })
}

pub fn verify_groth16(
    circuit: &RegisteredCircuit,
    vk: &VerifyingKey<Bn254>,
    envelope: &ProofEnvelope,
    public_input: ark_bn254::Fr,
) -> Result<bool, ProofError> {
    envelope.validate()?;
    if envelope.system != ProofSystem::Groth16 {
        return Err(ProofError::UnsupportedSystem);
    }
    if envelope.circuit_id != circuit.descriptor.circuit_id {
        return Err(ProofError::CircuitNotRegistered);
    }
    if verifying_key_hash(vk)? != circuit.descriptor.verifying_key_hash {
        return Err(ProofError::VerifyingKeyMismatch);
    }

    let mut expected_public = Vec::new();
    public_input
        .serialize_compressed(&mut expected_public)
        .map_err(|_| ProofError::VerificationFailed)?;
    if envelope.public_inputs != expected_public {
        return Err(ProofError::VerificationFailed);
    }

    let proof = Proof::<Bn254>::deserialize_compressed(envelope.proof.as_slice())
        .map_err(|_| ProofError::VerificationFailed)?;
    let pvk = prepare_verifying_key(vk);
    Groth16::<Bn254>::verify(&pvk, &[public_input], &proof)
        .map_err(|_| ProofError::VerificationFailed)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EnvelopeVerifier;

impl zkp_core::ProofVerifier for EnvelopeVerifier {
    fn verify(&self, envelope: &ProofEnvelope) -> Result<(), ProofError> {
        envelope.validate()?;
        if envelope.system.id() != ACCEPTED_SYSTEM_ID {
            return Err(ProofError::UnsupportedSystem);
        }
        if envelope.circuit_id == 0 {
            return Err(ProofError::CircuitNotRegistered);
        }
        Ok(())
    }
}

pub fn verify_format(system_id: u8, proof_len: usize) -> bool {
    match ProofSystem::from_id(system_id) {
        Some(system) => ProofEnvelope {
            system,
            circuit_id: 1,
            proof: vec![0; proof_len],
            public_inputs: Vec::new(),
        }
        .validate()
        .is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::test_rng;
    use zkp_prover::{prove_square, setup};

    #[test]
    fn registry_binds_verifying_key() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng).expect("setup");
        let circuit = register_equality_square(&vk).expect("registry");
        let envelope =
            prove_square(&pk, ark_bn254::Fr::from(7u64), ark_bn254::Fr::from(49u64), &mut rng)
                .expect("proof");
        assert!(verify_groth16(
            &circuit,
            &vk,
            &envelope,
            ark_bn254::Fr::from(49u64)
        )
        .expect("verify"));
    }

    #[test]
    fn registry_rejects_different_key() {
        let mut rng = test_rng();
        let (_pk_a, vk_a) = setup(&mut rng).expect("setup a");
        let (_pk_b, vk_b) = setup(&mut rng).expect("setup b");
        let circuit = register_equality_square(&vk_a).expect("registry");
        let envelope = ProofEnvelope {
            system: ProofSystem::Groth16,
            circuit_id: CIRCUIT_ID_EQUALITY_SQUARE,
            proof: vec![1; 64],
            public_inputs: Vec::new(),
        };
        assert_eq!(
            verify_groth16(
                &circuit,
                &vk_b,
                &envelope,
                ark_bn254::Fr::from(49u64)
            ),
            Err(ProofError::VerifyingKeyMismatch)
        );
    }

    #[test]
    fn registry_rejects_public_input_mismatch() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng).expect("setup");
        let circuit = register_equality_square(&vk).expect("registry");
        let envelope =
            prove_square(&pk, ark_bn254::Fr::from(7u64), ark_bn254::Fr::from(49u64), &mut rng)
                .expect("proof");

        assert_eq!(
            verify_groth16(
                &circuit,
                &vk,
                &envelope,
                ark_bn254::Fr::from(48u64)
            ),
            Err(ProofError::VerificationFailed)
        );
    }
}
