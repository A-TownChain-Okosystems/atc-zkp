//! Canonical Groth16 backend over BN254.
//!
//! This crate provides actual proof generation and verification primitives.
//! Circuit-specific setup keys must be generated in a controlled ceremony
//! and distributed as audited artifacts; this module does not embed toxic
//! waste or a production proving key.

use ark_bn254::Fr;
pub use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use zkp_core::{ProofEnvelope, ProofError, ProofSystem};

pub const CIRCUIT_ID_EQUALITY_SQUARE: u32 = 1;

#[derive(Clone)]
pub struct SquareCircuit {
    pub x: Option<Fr>,
    pub y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = FpVar::new_witness(cs.clone(), || self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = FpVar::new_input(cs, || self.y.ok_or(SynthesisError::AssignmentMissing))?;
        let square = &x * &x;
        square.enforce_equal(&y)?;
        Ok(())
    }
}

pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), ProofError> {
    Groth16::<Bn254>::circuit_specific_setup(SquareCircuit { x: None, y: None }, rng)
        .map_err(|_| ProofError::VerificationFailed)
}

pub fn prove_square<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    x: Fr,
    y: Fr,
    rng: &mut R,
) -> Result<ProofEnvelope, ProofError> {
    if x * x != y {
        return Err(ProofError::VerificationFailed);
    }
    let proof = Groth16::<Bn254>::prove(
        pk,
        SquareCircuit { x: Some(x), y: Some(y) },
        rng,
    )
    .map_err(|_| ProofError::VerificationFailed)?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|_| ProofError::VerificationFailed)?;

    let mut public_bytes = Vec::new();
    y.serialize_compressed(&mut public_bytes)
        .map_err(|_| ProofError::VerificationFailed)?;

    let envelope = ProofEnvelope {
        system: ProofSystem::Groth16,
        circuit_id: CIRCUIT_ID_EQUALITY_SQUARE,
        proof: proof_bytes,
        public_inputs: public_bytes,
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn verify_square(
    vk: &VerifyingKey<Bn254>,
    envelope: &ProofEnvelope,
    y: Fr,
) -> Result<bool, ProofError> {
    envelope.validate()?;
    if envelope.system != ProofSystem::Groth16 || envelope.circuit_id != CIRCUIT_ID_EQUALITY_SQUARE {
        return Err(ProofError::UnsupportedSystem);
    }

    let proof = Proof::<Bn254>::deserialize_compressed(envelope.proof.as_slice())
        .map_err(|_| ProofError::VerificationFailed)?;
    let mut expected_public = Vec::new();
    y.serialize_compressed(&mut expected_public)
        .map_err(|_| ProofError::VerificationFailed)?;
    if envelope.public_inputs != expected_public {
        return Err(ProofError::VerificationFailed);
    }

    let pvk = prepare_verifying_key(vk);
    Groth16::<Bn254>::verify(&pvk, &[y], &proof)
        .map_err(|_| ProofError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn real_groth16_round_trip_and_negative_case() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng).expect("setup");
        let x = Fr::from(7u64);
        let y = x * x;

        let envelope = prove_square(&pk, x, y, &mut rng).expect("proof");
        assert!(verify_square(&vk, &envelope, y).expect("verification"));

        let wrong_y = Fr::from(48u64);
        assert!(!verify_square(&vk, &envelope, wrong_y).unwrap_or(false));
    }
}
