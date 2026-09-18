//! Public SDK boundary for canonical ATC Groth16 proofs.

use ark_bn254::Fr;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_std::rand::{CryptoRng, RngCore};
use zkp_core::{ProofEnvelope, ProofError};
use zkp_prover::{prove_square, verify_square, Bn254};

pub use zkp_core::ProofSystem;

pub fn prove_square_statement<R: RngCore + CryptoRng>(
    proving_key: &ProvingKey<Bn254>,
    x: Fr,
    y: Fr,
    rng: &mut R,
) -> Result<ProofEnvelope, ProofError> {
    prove_square(proving_key, x, y, rng)
}

pub fn verify_square_statement(
    verifying_key: &VerifyingKey<Bn254>,
    envelope: &ProofEnvelope,
    y: Fr,
) -> Result<bool, ProofError> {
    verify_square(verifying_key, envelope, y)
}
