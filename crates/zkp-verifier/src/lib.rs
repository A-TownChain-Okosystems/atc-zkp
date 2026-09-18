// Copyright (c) 2026 Michael Wroblewski — Apache-2.0
//! Deterministic, fail-closed proof-envelope verification boundary.
//!
//! This is not a cryptographic verifier. It validates the canonical envelope
//! before a reviewed backend is allowed to perform cryptographic verification.

use zkp_core::{ProofEnvelope, ProofError, ProofVerifier};

pub const ACCEPTED_SYSTEM_ID: u8 = 1;

#[derive(Debug, Default, Clone, Copy)]
pub struct EnvelopeVerifier;

impl ProofVerifier for EnvelopeVerifier {
    fn verify(&self, envelope: &ProofEnvelope) -> Result<(), ProofError> {
        envelope.validate()?;
        if envelope.system.id() != ACCEPTED_SYSTEM_ID {
            return Err(ProofError::UnsupportedSystem);
        }
        if envelope.circuit_id == 0 {
            return Err(ProofError::VerificationFailed);
        }
        Ok(())
    }
}

pub fn verify_format(system_id: u8, proof_len: usize) -> bool {
    ProofEnvelope {
        system: match zkp_core::ProofSystem::from_id(system_id) {
            Some(system) => system,
            None => return false,
        },
        circuit_id: 1,
        proof: vec![0; proof_len],
        public_inputs: Vec::new(),
    }
    .validate()
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkp_core::{ProofEnvelope, ProofSystem};

    #[test]
    fn verifier_accepts_valid_envelope_shape() {
        let envelope = ProofEnvelope {
            system: ProofSystem::Groth16,
            circuit_id: 1,
            proof: vec![1; 64],
            public_inputs: vec![2; 32],
        };
        assert_eq!(EnvelopeVerifier.verify(&envelope), Ok(()));
    }

    #[test]
    fn verifier_rejects_unsupported_system() {
        let envelope = ProofEnvelope {
            system: ProofSystem::Plonk,
            circuit_id: 1,
            proof: vec![1; 64],
            public_inputs: Vec::new(),
        };
        assert_eq!(EnvelopeVerifier.verify(&envelope), Err(ProofError::UnsupportedSystem));
    }

    #[test]
    fn verifier_rejects_zero_circuit() {
        let envelope = ProofEnvelope {
            system: ProofSystem::Groth16,
            circuit_id: 0,
            proof: vec![1; 64],
            public_inputs: Vec::new(),
        };
        assert_eq!(EnvelopeVerifier.verify(&envelope), Err(ProofError::VerificationFailed));
    }
}
