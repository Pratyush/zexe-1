use algebra::PairingEngine;
use snark::{ConstraintSystem, SynthesisError};

use crate::crypto_primitives::nizk::NIZK;
use snark_gadgets::utils::{AllocGadget, ToBitsGadget, ToBytesGadget};

pub mod gm17;

pub trait NIZKVerifierGadget<N: NIZK, E: PairingEngine> {
    type VerificationKey: AllocGadget<N::VerificationParameters, E> + ToBytesGadget<E>;

    type Proof: AllocGadget<N::Proof, E>;

    fn verify<'a, CS, I, T>(
        cs: CS,
        verification_key: &Self::VerificationKey,
        input: I,
        proof: &Self::Proof,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>,
        I: Iterator<Item = &'a T>,
        T: 'a + ToBitsGadget<E> + ?Sized;
}
