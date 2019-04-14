use crate::crypto_primitives::CommitmentScheme;
use algebra::PairingEngine;
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::{
    uint8::UInt8,
    utils::{AllocGadget, EqGadget, ToBytesGadget},
};
use std::fmt::Debug;

pub mod blake2s;
pub mod injective_map;
pub mod pedersen;

pub trait CommitmentGadget<C: CommitmentScheme, E: PairingEngine> {
    type Output: EqGadget<E> + ToBytesGadget<E> + AllocGadget<C::Output, E> + Clone + Sized + Debug;
    type Parameters: AllocGadget<C::Parameters, E> + Clone;
    type Randomness: AllocGadget<C::Randomness, E> + Clone;

    fn check_commitment<CS: ConstraintSystem<E>>(
        cs: CS,
        parameters: &Self::Parameters,
        input: &[UInt8],
        r: &Self::Randomness,
    ) -> Result<Self::Output, SynthesisError>;
}
