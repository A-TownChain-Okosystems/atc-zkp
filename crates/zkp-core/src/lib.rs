// Copyright (c) 2026 Michael Wroblewski — Apache-2.0
//! Canonical, deterministic ZKP core types and bounded proof envelope.
//!
//! Concrete proof-system backends must implement the trait below and pass
//! independent cryptographic review before production use.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitStats {
    pub gates: u64,
    pub public_inputs: u64,
    pub private_witnesses: u64,
}

impl CircuitStats {
    pub fn valid(&self) -> bool {
        self.gates > 0 && self.public_inputs + self.private_witnesses > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    Groth16 = 1,
    Plonk = 2,
    Halo2 = 3,
    Stark = 4,
}

impl ProofSystem {
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::Groth16),
            2 => Some(Self::Plonk),
            3 => Some(Self::Halo2),
            4 => Some(Self::Stark),
            _ => None,
        }
    }

    pub const fn id(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelope {
    pub system: ProofSystem,
    pub circuit_id: u32,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl ProofEnvelope {
    pub const MAX_PROOF_BYTES: usize = 1 << 20;
    pub const MAX_PUBLIC_INPUT_BYTES: usize = 1 << 16;

    pub fn validate(&self) -> Result<(), ProofError> {
        if self.proof.is_empty() || self.proof.len() > Self::MAX_PROOF_BYTES {
            return Err(ProofError::InvalidProofSize);
        }
        if self.public_inputs.len() > Self::MAX_PUBLIC_INPUT_BYTES {
            return Err(ProofError::InvalidPublicInputSize);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitDescriptor {
    pub circuit_id: u32,
    pub version: u32,
    pub verifying_key_hash: [u8; 32],
}

impl CircuitDescriptor {
    pub fn validate(&self) -> Result<(), ProofError> {
        if self.circuit_id == 0 || self.version == 0 || self.verifying_key_hash == [0; 32] {
            return Err(ProofError::InvalidCircuitDescriptor);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    InvalidProofSize,
    InvalidPublicInputSize,
    UnsupportedSystem,
    VerificationFailed,
    InvalidCircuitDescriptor,
    CircuitNotRegistered,
    VerifyingKeyMismatch,
}

pub trait ProofVerifier {
    fn verify(&self, envelope: &ProofEnvelope) -> Result<(), ProofError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_validation() {
        assert!(CircuitStats {
            gates: 1,
            public_inputs: 1,
            private_witnesses: 0
        }
        .valid());
        assert!(!CircuitStats {
            gates: 0,
            public_inputs: 1,
            private_witnesses: 0
        }
        .valid());
        assert!(!CircuitStats {
            gates: 1,
            public_inputs: 0,
            private_witnesses: 0
        }
        .valid());
    }

    #[test]
    fn proof_system_ids_are_stable() {
        assert_eq!(ProofSystem::from_id(1), Some(ProofSystem::Groth16));
        assert_eq!(ProofSystem::Stark.id(), 4);
        assert_eq!(ProofSystem::from_id(255), None);
    }

    #[test]
    fn envelope_rejects_empty_and_oversized_proofs() {
        let empty = ProofEnvelope {
            system: ProofSystem::Groth16,
            circuit_id: 1,
            proof: Vec::new(),
            public_inputs: Vec::new(),
        };
        assert_eq!(empty.validate(), Err(ProofError::InvalidProofSize));

        let oversized = ProofEnvelope {
            system: ProofSystem::Groth16,
            circuit_id: 1,
            proof: vec![0; ProofEnvelope::MAX_PROOF_BYTES + 1],
            public_inputs: Vec::new(),
        };
        assert_eq!(oversized.validate(), Err(ProofError::InvalidProofSize));
    }
}
