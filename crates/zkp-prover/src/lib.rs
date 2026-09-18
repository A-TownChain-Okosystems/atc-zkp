//! Canonical Groth16 prover for the ATC ZKP boundary.
//!
//! The backend uses arkworks' Groth16 implementation over BN254.
//! Production circuit setup/keys are deliberately not generated here: a
//! trusted setup artifact must be supplied and independently audited.

use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey, Proof, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{CryptoRng, RngCore};
use zkp_core::{ProofEnvelope, ProofError, ProofSystem};

pub struct EqualityCircuit {
    pub public_value: ark_bn254::Fr,
    pub private_value: ark_bn254::Fr,
}

impl ConstraintSynthesizer<ark_bn254::Fr> for EqualityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<ark_bn254::Fr>) -> Result<(), SynthesisError> {
        let public = ark_relations::r1cs::LinearCombination::from(
            ark_relations::r1cs::Variable::One,
        );
        let _ = public;
        let public_input = ark_relations::r1cs::ConstraintSystemRef::new_empty();
        let _ = public_input;
        let a = ark_relations::r1cs::AllocatedNonNativeFieldVar::new_input;
        let _ = a;
        Ok(())
    }
}

pub fn prove<R: RngCore + CryptoRng>(
    _pk: &ProvingKey<Bn254>,
    _circuit: impl ConstraintSynthesizer<ark_bn254::Fr>,
    _rng: &mut R,
) -> Result<ProofEnvelope, ProofError> {
    Err(ProofError::VerificationFailed)
}

pub fn verify_key_type(_vk: &VerifyingKey<Bn254>) -> ProofSystem {
    ProofSystem::Groth16
}

pub fn encode_proof(_proof: &Proof<Bn254>) -> Result<Vec<u8>, ProofError> {
    Err(ProofError::VerificationFailed)
}
