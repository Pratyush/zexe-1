use algebra::PairingEngine;
use std::fmt::Debug;

use crate::crypto_primitives::crh::FixedLengthCRH;
use snark::{ConstraintSystem, SynthesisError};

use snark_gadgets::{
    uint8::UInt8,
    utils::{AllocGadget, CondSelectGadget, ConditionalEqGadget, EqGadget, ToBytesGadget},
};

pub mod injective_map;
pub mod pedersen;

pub trait FixedLengthCRHGadget<H: FixedLengthCRH, E: PairingEngine>: Sized {
    type Output: ConditionalEqGadget<E>
        + EqGadget<E>
        + ToBytesGadget<E>
        + CondSelectGadget<E>
        + AllocGadget<H::Output, E>
        + Debug
        + Clone
        + Sized;
    type Parameters: AllocGadget<H::Parameters, E> + Clone;

    fn check_evaluation<CS: ConstraintSystem<E>>(
        cs: CS,
        parameters: &Self::Parameters,
        input: &[UInt8],
    ) -> Result<Self::Output, SynthesisError>;

    fn cost() -> usize;
}
