// use algebra::{utils::ToEngineFr, FpParameters, PairingEngine, PrimeField};

// use crate::fields::fp::FpGadget;
// use snark::{ConstraintSystem, SynthesisError};

// use super::boolean::{AllocatedBit, Boolean};
// use crate::{
//     utils::{AllocGadget, ConditionalEqGadget, EqGadget, ToBitsGadget},
//     Assignment,
// };
// use std::borrow::Borrow;

macro_rules! doc_comment {
    ($x:expr, $($tt:tt)*) => {
        #[doc = $x]
        $($tt)*
    };
}

macro_rules! uint_impl {
    ($name:ident, $width:expr, $plain:ident, $mod_name: ident) => {
        uint_impl!($name, $width, $plain, $mod_name, stringify!($name), stringify!($width), stringify!($plain));
    };
    ($name:ident, $width:expr, $plain:ident, $mod_name: ident, $name_str:expr, $width_str: expr, $plain_str:expr) => {
        pub mod $mod_name {
            #[allow(unused_imports)]
            use super::*;
            use algebra::{utils::ToEngineFr, FpParameters, PairingEngine, PrimeField, Field};

            use crate::fields::fp::FpGadget;
            use snark::{ConstraintSystem, LinearCombination, SynthesisError};

            use super::boolean::{AllocatedBit, Boolean};
            use crate::{
                utils::{AllocGadget, ConditionalEqGadget, EqGadget, ToBitsGadget, ToBytesGadget},
                Assignment,
            };
            use std::borrow::Borrow;

            doc_comment! {
                concat!(
                    "Represents an interpretation of ", $width_str," `Boolean` ",
                    "objects as an unsigned integer."
                ),
                #[derive(Clone, Debug)]
                pub struct $name {
                    // Least significant bit_gadget first
                    pub(crate) bits:  Vec<Boolean>,
                    pub(crate) value: Option<$plain>,
                }
            }

            impl $name {
                pub fn get_value(&self) -> Option<$plain> {
                    self.value
                }

                doc_comment! {
                    concat!(
                        "Construct a `Vec<", $name_str, ">` of length `values.len()`",
                        " from a slice of `", $plain_str, "`'s."
                    ),
                    pub fn constant_vec(values: &[$plain]) -> Vec<Self> {
                        let mut result = Vec::new();
                        for value in values {
                            result.push($name::constant(*value));
                        }
                        result
                    }
                }

                doc_comment! {
                    concat!("Construct a constant `", $name_str, "` from a `", $plain_str, "`."),
                    pub fn constant(value: $plain) -> Self {
                        let mut bits = Vec::with_capacity($width);

                        let mut tmp = value;
                        for _ in 0..$width {
                            // If last bit is one, push one.
                            if tmp & 1 == 1 {
                                bits.push(Boolean::constant(true))
                            } else {
                                bits.push(Boolean::constant(false))
                            }

                            tmp >>= 1;
                        }

                        Self {
                            bits,
                            value: Some(value),
                        }
                    }
                }

                pub fn alloc_vec<E, CS, T>(mut cs: CS, values: &[T]) -> Result<Vec<Self>, SynthesisError>
                where
                    E: PairingEngine,
                    CS: ConstraintSystem<E>,
                    T: Into<Option<$plain>> + Copy,
                {
                    let mut output_vec = Vec::with_capacity(values.len());
                    for (i, value) in values.into_iter().enumerate() {
                        let byte: Option<$plain> = Into::into(*value);
                        let alloc_byte = Self::alloc(&mut cs.ns(|| format!("byte_{}", i)), || byte.get())?;
                        output_vec.push(alloc_byte);
                    }
                    Ok(output_vec)
                }

                doc_comment! {
                    concat!(
                        "Allocates a vector of `", $plain_str, "`'s by first",
                        "converting (chunks of) them to `E::Fr` elements, ",
                        "(thus reducing the number of input allocations), and",
                        " then converts this list of `E::Fr` gadgets back into `",
                        $name_str, "`'s."
                    ),
                    pub fn alloc_input_vec<E, CS>(mut cs: CS, values: &[$plain]) -> Result<Vec<Self>, SynthesisError>
                    where
                        E: PairingEngine,
                        CS: ConstraintSystem<E>,
                    {
                        let values_len = values.len();
                        let field_elements: Vec<E::Fr> = ToEngineFr::<E>::to_engine_fr(values).unwrap();

                        let max_size = $width * (<E::Fr as PrimeField>::Params::CAPACITY / $width) as usize;
                        let mut allocated_bits = Vec::new();
                        for (i, field_element) in field_elements.into_iter().enumerate() {
                            let fe = FpGadget::alloc_input(&mut cs.ns(|| format!("Field element {}", i)), || {
                                Ok(field_element)
                            })?;
                            let mut fe_bits = fe.to_bits(cs.ns(|| format!("Convert fe to bits {}", i)))?;
                            // FpGadget::to_bits outputs a big-endian binary representation of
                            // fe_gadget's value, so we have to reverse it to get the little-endian
                            // form.
                            fe_bits.reverse();

                            // Remove the most significant bit, because we know it should be zero
                            // because `values.to_engine_fr()` only
                            // packs field elements up to the penultimate bit.
                            // That is, the most significant bit (`E::Fr::NUM_BITS`-th bit) is
                            // unset, so we can just pop it off.
                            allocated_bits.extend_from_slice(&fe_bits[0..max_size]);
                        }

                        // Chunk up slices of $width into bytes.
                        Ok(allocated_bits[0..$width * values_len]
                            .chunks($width)
                            .map(Self::from_bits_le)
                            .collect())
                    }
                }


                doc_comment! {
                    concat!(
                        "Turns this `", $name_str, "` into its little-endian byte \
                        order representation. LSB-first means that we can easily get \
                        the corresponding field element via double and add."
                        ),
                        pub fn to_bits_le(&self) -> Vec<Boolean> {
                            self.bits.iter().cloned().collect()
                        }
                }

                doc_comment! {
                    concat!(
                        "Converts a little-endian byte order representation of bits \
                        into a `", $name_str, "`."
                    ),
                    pub fn from_bits_le(bits: &[Boolean]) -> Self {
                        assert_eq!(bits.len(), $width);

                        let bits = bits.to_vec();

                        let mut value = Some(0);
                        for b in bits.iter().rev() {
                            value.as_mut().map(|v| *v <<= 1);

                            match *b {
                                Boolean::Constant(b) => {
                                    if b {
                                        value.as_mut().map(|v| *v |= 1);
                                    }
                                },
                                Boolean::Is(ref b) => match b.get_value() {
                                    Some(true) => {
                                        value.as_mut().map(|v| *v |= 1);
                                    },
                                    Some(false) => {},
                                    None => value = None,
                                },
                                Boolean::Not(ref b) => match b.get_value() {
                                    Some(false) => {
                                        value.as_mut().map(|v| *v |= 1);
                                    },
                                    Some(true) => {},
                                    None => value = None,
                                },
                            }
                        }

                        Self { value, bits }
                    }
                }

                doc_comment! {
                    concat!("XOR this `", $name_str, "` with another `", $name_str, "`."),
                    pub fn xor<E, CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
                    where
                        E: PairingEngine,
                        CS: ConstraintSystem<E>,
                    {
                        let new_value = match (self.value, other.value) {
                            (Some(a), Some(b)) => Some(a ^ b),
                            _ => None,
                        };

                        let bits = self
                            .bits
                            .iter()
                            .zip(other.bits.iter())
                            .enumerate()
                            .map(|(i, (a, b))| Boolean::xor(cs.ns(|| format!("xor of bit_gadget {}", i)), a, b))
                            .collect::<Result<_, _>>()?;

                        Ok(Self {
                            bits,
                            value: new_value,
                        })
                    }
                }

                pub fn rotate_right(&self, by: usize) -> Self {
                    let by = by % $width;

                    let new_bits = self
                        .bits
                        .iter()
                        .skip(by)
                        .chain(self.bits.iter())
                        .take($width)
                        .cloned()
                        .collect();

                    Self {
                        bits:  new_bits,
                        value: self.value.map(|v| v.rotate_right(by as u32)),
                    }
                }

                doc_comment! {
                    concat!("Perform modular addition of several `", $name_str, "` objects."),
                    pub fn addmany<E, CS>(mut cs: CS, operands: &[Self]) -> Result<Self, SynthesisError>
                    where
                        E: PairingEngine,
                        CS: ConstraintSystem<E>,
                    {
                        // Make some arbitrary bounds for ourselves to avoid overflows
                        // in the scalar field
                        assert!(<E::Fr as PrimeField>::Params::MODULUS_BITS >= 128);
                        assert!(operands.len() >= 2); // Weird trivial cases that should never happen
                        assert!(operands.len() <= 10);

                        // Compute the maximum value of the sum so we allocate enough bits for
                        // the result
                        let mut max_value = (operands.len() as u128) * u128::from($plain::max_value());

                        // Keep track of the resulting value
                        let mut result_value = Some(0u128);

                        // This is a linear combination that we will enforce to be "zero"
                        let mut lc = LinearCombination::zero();

                        let mut all_constants = true;

                        // Iterate over the operands
                        for op in operands {
                            // Accumulate the value
                            match op.value {
                                Some(val) => {
                                    result_value.as_mut().map(|v| *v += u128::from(val));
                                },
                                None => {
                                    // If any of our operands have unknown value, we won't
                                    // know the value of the result
                                    result_value = None;
                                },
                            }

                            // Iterate over each bit_gadget of the operand and add the operand to
                            // the linear combination
                            let mut coeff = E::Fr::one();
                            for bit in &op.bits {
                                match *bit {
                                    Boolean::Is(ref bit) => {
                                        all_constants = false;

                                        // Add coeff * bit_gadget
                                        lc = lc + (coeff, bit.get_variable());
                                    },
                                    Boolean::Not(ref bit) => {
                                        all_constants = false;

                                        // Add coeff * (1 - bit_gadget) = coeff * ONE - coeff * bit_gadget
                                        lc = lc + (coeff, CS::one()) - (coeff, bit.get_variable());
                                    },
                                    Boolean::Constant(bit) => {
                                        if bit {
                                            lc = lc + (coeff, CS::one());
                                        }
                                    },
                                }

                                coeff.double_in_place();
                            }
                        }

                        // The value of the actual result is modulo the width of Self.
                        let modular_value = result_value.map(|v| v as $plain);

                        if all_constants && modular_value.is_some() {
                            // We can just return a constant, rather than
                            // unpacking the result into allocated bits.

                            return Ok(Self::constant(modular_value.unwrap()));
                        }

                        // Storage area for the resulting bits
                        let mut result_bits = vec![];

                        // Allocate each bit_gadget of the result
                        let mut coeff = E::Fr::one();
                        let mut i = 0;
                        while max_value != 0 {
                            // Allocate the bit_gadget
                            let b = AllocatedBit::alloc(cs.ns(|| format!("result bit_gadget {}", i)), || {
                                result_value.map(|v| (v >> i) & 1 == 1).get()
                            })?;

                            // Subtract this bit_gadget from the linear combination to ensure the sums
                            // balance out
                            lc = lc - (coeff, b.get_variable());

                            result_bits.push(b.into());

                            max_value >>= 1;
                            i += 1;
                            coeff.double_in_place();
                        }

                        // Enforce that the linear combination equals zero
                        cs.enforce(|| "modular addition", |lc| lc, |lc| lc, |_| lc);

                        // Discard carry bits that we don't care about
                        result_bits.truncate($width);

                        Ok(Self {
                            bits:  result_bits,
                            value: modular_value,
                        })
                    }
                }
            }

            impl PartialEq for $name {
                fn eq(&self, other: &Self) -> bool {
                    !self.value.is_none() && !other.value.is_none() && self.value == other.value
                }
            }

            impl Eq for $name {}

            impl<E: PairingEngine> ConditionalEqGadget<E> for $name {
                fn conditional_enforce_equal<CS: ConstraintSystem<E>>(
                    &self,
                    mut cs: CS,
                    other: &Self,
                    condition: &Boolean,
                ) -> Result<(), SynthesisError> {
                    for (i, (a, b)) in self.bits.iter().zip(&other.bits).enumerate() {
                        a.conditional_enforce_equal(
                            &mut cs.ns(|| format!("{} equality check for {}-th bit", stringify!($name), i)),
                            b,
                            condition,
                        )?;
                    }
                    Ok(())
                }

                fn cost() -> usize {
                    $width * <Boolean as ConditionalEqGadget<E>>::cost()
                }
            }

            impl<E: PairingEngine> EqGadget<E> for $name {}

            impl<E: PairingEngine> AllocGadget<$plain, E> for $name {
                fn alloc<F, T, CS: ConstraintSystem<E>>(
                    mut cs: CS,
                    value_gen: F,
                ) -> Result<Self, SynthesisError>
                where
                    F: FnOnce() -> Result<T, SynthesisError>,
                    T: Borrow<$plain>,
                {
                    let value = value_gen().map(|val| *val.borrow());
                    let values = match value {
                        Ok(mut val) => {
                            let mut v = Vec::with_capacity($width);

                            for _ in 0..$width {
                                v.push(Some(val & 1 == 1));
                                val >>= 1;
                            }

                            v
                        },
                        _ => vec![None; $width],
                    };

                    let bits = values
                        .into_iter()
                        .enumerate()
                        .map(|(i, v)| {
                            Ok(Boolean::from(AllocatedBit::alloc(
                                &mut cs.ns(|| format!("allocated bit_gadget {}", i)),
                                || v.ok_or(SynthesisError::AssignmentMissing),
                            )?))
                        })
                        .collect::<Result<Vec<_>, SynthesisError>>()?;

                    Ok(Self {
                        bits,
                        value: value.ok(),
                    })
                }

                fn alloc_input<F, T, CS: ConstraintSystem<E>>(
                    mut cs: CS,
                    value_gen: F,
                ) -> Result<Self, SynthesisError>
                where
                    F: FnOnce() -> Result<T, SynthesisError>,
                    T: Borrow<$plain>,
                {
                    let value = value_gen().map(|val| *val.borrow());
                    let values = match value {
                        Ok(mut val) => {
                            let mut v = Vec::with_capacity($width);
                            for _ in 0..$width {
                                v.push(Some(val & 1 == 1));
                                val >>= 1;
                            }

                            v
                        },
                        _ => vec![None; $width],
                    };

                    let bits = values
                        .into_iter()
                        .enumerate()
                        .map(|(i, v)| {
                            Ok(Boolean::from(AllocatedBit::alloc_input(
                                &mut cs.ns(|| format!("allocated bit_gadget {}", i)),
                                || v.ok_or(SynthesisError::AssignmentMissing),
                            )?))
                        })
                        .collect::<Result<Vec<_>, SynthesisError>>()?;

                    Ok(Self {
                        bits,
                        value: value.ok(),
                    })
                }

            }

            impl<E: PairingEngine> ToBytesGadget<E> for $name {
                #[inline]
                fn to_bytes<CS: ConstraintSystem<E>>(&self, _cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
                    let value_chunks = match self.value.map(|val| {
                        use algebra::bytes::ToBytes;
                        let mut bytes = [0u8; $width/8];
                        val.write(bytes.as_mut()).unwrap();
                        bytes
                    }) {
                        Some(chunks) => chunks.iter().map(|&val| Some(val)).collect(),
                        None => vec![None; $width/8],
                    };
                    let mut bytes = Vec::new();
                    for (i, chunk8) in self.to_bits_le().chunks(8).into_iter().enumerate() {
                        let byte = UInt8 {
                            bits:  chunk8.to_vec(),
                            value: value_chunks[i],
                        };
                        bytes.push(byte);
                    }

                    Ok(bytes)
                }

                fn to_bytes_strict<CS: ConstraintSystem<E>>(
                    &self,
                    cs: CS,
                    ) -> Result<Vec<UInt8>, SynthesisError> {
                    self.to_bytes(cs)
                }
            }

            #[cfg(test)]
            mod test {
                use super::$name;
                use crate::{
                    bits::boolean::Boolean, test_constraint_system::TestConstraintSystem, utils::AllocGadget,
                };
                use algebra::curves::bls12_381::Bls12_381;
                use algebra::Field;
                use rand::{Rng, SeedableRng, XorShiftRng};
                use snark::ConstraintSystem;

                #[test]
                fn test_from_bits_to_bits() {
                    let mut cs = TestConstraintSystem::<Bls12_381>::new();
                    let byte_val = 0b01110001;
                    let byte = $name::alloc(cs.ns(|| "alloc value"), || Ok(byte_val)).unwrap();
                    let bits = byte.to_bits_le();
                    for (i, bit) in bits.iter().enumerate() {
                        assert_eq!(bit.get_value().unwrap(), (byte_val >> i) & 1 == 1)
                    }
                }

                #[test]
                fn test_alloc_input_vec() {
                    let mut cs = TestConstraintSystem::<Bls12_381>::new();
                    let vals = (64..128).into_iter().collect::<Vec<_>>();
                    let bytes = $name::alloc_input_vec(cs.ns(|| "alloc value"), &vals).unwrap();
                    for (native_byte, gadget_byte) in vals.into_iter().zip(bytes) {
                        let bits = gadget_byte.to_bits_le();
                        for (i, bit) in bits.iter().enumerate() {
                            assert_eq!(bit.get_value().unwrap(), (native_byte >> i) & 1 == 1)
                        }
                    }
                }

                #[test]
                fn test_from_bits() {
                    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

                    for _ in 0..1000 {
                        let v = (0..$width)
                            .map(|_| Boolean::constant(rng.gen()))
                            .collect::<Vec<_>>();

                        let b = $name::from_bits_le(&v);

                        for (i, bit_gadget) in b.bits.iter().enumerate() {
                            match bit_gadget {
                                &Boolean::Constant(bit_gadget) => {
                                    assert!(bit_gadget == ((b.value.unwrap() >> i) & 1 == 1));
                                },
                                _ => unreachable!(),
                            }
                        }

                        let expected_to_be_same = b.to_bits_le();

                        for x in v.iter().zip(expected_to_be_same.iter()) {
                            match x {
                                (&Boolean::Constant(true), &Boolean::Constant(true)) => {},
                                (&Boolean::Constant(false), &Boolean::Constant(false)) => {},
                                _ => unreachable!(),
                            }
                        }
                    }
                }

                #[test]
                fn test_xor() {
                    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

                    for _ in 0..1000 {
                        let mut cs = TestConstraintSystem::<Bls12_381>::new();

                        let a: $plain = rng.gen();
                        let b: $plain = rng.gen();
                        let c: $plain = rng.gen();

                        let mut expected = a ^ b ^ c;

                        let a_bit = $name::alloc(cs.ns(|| "a_bit"), || Ok(a)).unwrap();
                        let b_bit = $name::constant(b);
                        let c_bit = $name::alloc(cs.ns(|| "c_bit"), || Ok(c)).unwrap();

                        let r = a_bit.xor(cs.ns(|| "first xor"), &b_bit).unwrap();
                        let r = r.xor(cs.ns(|| "second xor"), &c_bit).unwrap();

                        assert!(cs.is_satisfied());

                        assert!(r.value == Some(expected));

                        for b in r.bits.iter() {
                            match b {
                                &Boolean::Is(ref b) => {
                                    assert!(b.get_value().unwrap() == (expected & 1 == 1));
                                },
                                &Boolean::Not(ref b) => {
                                    assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                                },
                                &Boolean::Constant(b) => {
                                    assert!(b == (expected & 1 == 1));
                                },
                            }

                            expected >>= 1;
                        }
                    }
                }

                #[test]
                fn test_addmany_constants() {
                    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

                    for _ in 0..1000 {
                        let mut cs = TestConstraintSystem::<Bls12_381>::new();

                        let a: $plain = rng.gen();
                        let b: $plain = rng.gen();
                        let c: $plain = rng.gen();

                        let a_bit = $name::constant(a);
                        let b_bit = $name::constant(b);
                        let c_bit = $name::constant(c);

                        let mut expected = a.wrapping_add(b).wrapping_add(c);

                        let r = $name::addmany(cs.ns(|| "addition"), &[a_bit, b_bit, c_bit]).unwrap();

                        assert!(r.value == Some(expected));

                        for b in r.bits.iter() {
                            match b {
                                &Boolean::Is(_) => panic!(),
                                &Boolean::Not(_) => panic!(),
                                &Boolean::Constant(b) => {
                                    assert!(b == (expected & 1 == 1));
                                },
                            }

                            expected >>= 1;
                        }
                    }
                }

                #[test]
                fn test_addmany() {
                    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

                    for _ in 0..1000 {
                        let mut cs = TestConstraintSystem::<Bls12_381>::new();

                        let a: $plain = rng.gen();
                        let b: $plain = rng.gen();
                        let c: $plain = rng.gen();
                        let d: $plain = rng.gen();

                        let mut expected = (a ^ b).wrapping_add(c).wrapping_add(d);

                        let a_bit = $name::alloc(cs.ns(|| "a_bit"), || Ok(a)).unwrap();
                        let b_bit = $name::constant(b);
                        let c_bit = $name::constant(c);
                        let d_bit = $name::alloc(cs.ns(|| "d_bit"), || Ok(d)).unwrap();

                        let r = a_bit.xor(cs.ns(|| "xor"), &b_bit).unwrap();
                        let r = $name::addmany(cs.ns(|| "addition"), &[r, c_bit, d_bit]).unwrap();

                        assert!(cs.is_satisfied());

                        assert!(r.value == Some(expected));

                        for b in r.bits.iter() {
                            match b {
                                &Boolean::Is(ref b) => {
                                    assert!(b.get_value().unwrap() == (expected & 1 == 1));
                                },
                                &Boolean::Not(ref b) => {
                                    assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                                },
                                &Boolean::Constant(_) => unreachable!(),
                            }

                            expected >>= 1;
                        }

                        // Flip a bit_gadget and see if the addition constraint still works
                        if cs.get("addition/result bit_gadget 0/boolean").is_zero() {
                            cs.set("addition/result bit_gadget 0/boolean", Field::one());
                        } else {
                            cs.set("addition/result bit_gadget 0/boolean", Field::zero());
                        }

                        assert!(!cs.is_satisfied());
                    }
                }

                #[test]
                fn test_rotate_right() {
                    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

                    let mut num = rng.gen();

                    let a = $name::constant(num);

                    for i in 0..$width {
                        let b = a.rotate_right(i);

                        assert!(b.value.unwrap() == num);

                        let mut tmp = num;
                        for b in &b.bits {
                            match b {
                                &Boolean::Constant(b) => {
                                    assert_eq!(b, tmp & 1 == 1);
                                },
                                _ => unreachable!(),
                            }

                            tmp >>= 1;
                        }

                        num = num.rotate_right(1);
                    }
                }
            }
        }
    }
}
