//! Usage: `use homomorph::prelude::*;`

pub use crate::cipher::{ByteConvertible, Ciphered, CipheredBit};
pub use crate::context::{Context, Parameters, PublicKey, SecretKey};
pub use crate::operations::*;

// Subject to change in the future
pub use crate::impls as homomorph_impls;
