
#[macro_use]
mod macros;

pub use self::{uint8::UInt8, uint16::UInt16, uint32::UInt32, uint64::UInt64};

pub mod boolean;
uint_impl!(UInt8, 8, u8, uint8);
uint_impl!(UInt16, 16, u16, uint16);
uint_impl!(UInt32, 32, u32, uint32);
uint_impl!(UInt64, 64, u64, uint64);
