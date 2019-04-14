use algebra::PairingEngine;
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::{
    uint8::UInt8,
    utils::{AllocGadget, EqGadget, ToBytesGadget},
};

use crate::crypto_primitives::signature::SignatureScheme;

pub mod schnorr;

pub trait SigRandomizePkGadget<S: SignatureScheme, E: PairingEngine> {
    type Parameters: AllocGadget<S::Parameters, E> + Clone;

    type PublicKey: ToBytesGadget<E> + EqGadget<E> + AllocGadget<S::PublicKey, E> + Clone;

    fn check_randomization<CS: ConstraintSystem<E>>(
        cs: CS,
        parameters: &Self::Parameters,
        public_key: &Self::PublicKey,
        randomness: &[UInt8],
    ) -> Result<Self::PublicKey, SynthesisError>;
}
