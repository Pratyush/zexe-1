use crate::{
    bytes::FromBytes,
    curves::{
        models::{ModelParameters, SWModelParameters, TEModelParameters},
        short_weierstrass_jacobian::{GroupAffine as SWAffine, GroupProjective as SWProjective},
        twisted_edwards_extended::{GroupAffine as TEAffine, GroupProjective as TEProjective},
        ProjectiveCurve,
    },
    Fp2, Fp2Parameters, FpParameters, PairingEngine, PrimeField, SquareRootField,
};
use failure::Error;

pub trait ToEngineFr<E: PairingEngine> {
    fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error>;
}

// Impl for base field
impl<F, E: PairingEngine<Fr = F>> ToEngineFr<E> for F
where
    F: PrimeField + SquareRootField + Into<<E::Fr as PrimeField>::BigInt>,
{
    #[inline]
    fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
        Ok(vec![*self])
    }
}

// Impl for base field
impl<F, E: PairingEngine<Fr = F>> ToEngineFr<E> for [F]
where
    F: PrimeField + SquareRootField + Into<<E::Fr as PrimeField>::BigInt>,
{
    #[inline]
    fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
        Ok(self.to_vec())
    }
}

impl<E: PairingEngine> ToEngineFr<E> for () {
    #[inline]
    fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
        Ok(Vec::new())
    }
}

// Impl for Fp2<E::Fr>
impl<E: PairingEngine, P: Fp2Parameters<Fp = E::Fr>> ToEngineFr<E> for Fp2<P> {
    #[inline]
    fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
        let mut c0 = <E::Fr as ToEngineFr<E>>::to_engine_fr(&self.c0)?;
        let c1 = <E::Fr as ToEngineFr<E>>::to_engine_fr(&self.c1)?;
        c0.extend_from_slice(&c1);
        Ok(c0)
    }
}

impl<E, M> ToEngineFr<E> for TEAffine<M>
where
    E: PairingEngine,
    M: TEModelParameters,
    <M as ModelParameters>::BaseField: ToEngineFr<E>,
{
    #[inline]
    fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
        let mut x_fe = self.x.to_engine_fr()?;
        let y_fe = self.y.to_engine_fr()?;
        x_fe.extend_from_slice(&y_fe);
        Ok(x_fe)
    }
}

impl<E, M> ToEngineFr<E> for TEProjective<M>
where
    E: PairingEngine,
    M: TEModelParameters,
    <M as ModelParameters>::BaseField: ToEngineFr<E>,
{
    #[inline]
    fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
        let affine = self.into_affine();
        let mut x_fe = affine.x.to_engine_fr()?;
        let y_fe = affine.y.to_engine_fr()?;
        x_fe.extend_from_slice(&y_fe);
        Ok(x_fe)
    }
}

impl<E, M> ToEngineFr<E> for SWAffine<M>
where
    E: PairingEngine,
    M: SWModelParameters,
    <M as ModelParameters>::BaseField: ToEngineFr<E>,
{
    #[inline]
    fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
        let mut x_fe = self.x.to_engine_fr()?;
        let y_fe = self.y.to_engine_fr()?;
        x_fe.extend_from_slice(&y_fe);
        Ok(x_fe)
    }
}

impl<E, M> ToEngineFr<E> for SWProjective<M>
where
    E: PairingEngine,
    M: SWModelParameters,
    <M as ModelParameters>::BaseField: ToEngineFr<E>,
{
    #[inline]
    fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
        let affine = self.into_affine();
        let mut x_fe = affine.x.to_engine_fr()?;
        let y_fe = affine.y.to_engine_fr()?;
        x_fe.extend_from_slice(&y_fe);
        Ok(x_fe)
    }
}

macro_rules! impl_for_uint {
    ($plain:ident, $width:expr) => {
        impl<E: PairingEngine> ToEngineFr<E> for [$plain] {
            #[inline]
            fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
                use crate::bytes::ToBytes;
                let max_size = <E::Fr as PrimeField>::Params::CAPACITY / $width;
                let max_size = max_size as usize;
                let fes = self
                    .chunks(max_size)
                    .map(|chunk| {
                        let mut chunk = chunk.to_vec();
                        let len = chunk.len();
                        for _ in len..(max_size + 1) {
                            chunk.push(0);
                        }
                        let bytes = to_bytes![chunk]?;
                        E::Fr::read(bytes.as_slice())
                    })
                .collect::<Result<Vec<_>, _>>()?;
                Ok(fes)
            }
        }

        impl<E: PairingEngine> ToEngineFr<E> for [$plain; 32] {
            #[inline]
            fn to_engine_fr(&self) -> Result<Vec<E::Fr>, Error> {
                ToEngineFr::<E>::to_engine_fr(self.as_ref())
            }
        }
    }
}

impl_for_uint!(u8, 8);
impl_for_uint!(u16, 16);
impl_for_uint!(u32, 32);
impl_for_uint!(u64, 64);
