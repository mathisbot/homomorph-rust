//! Usage: `use homomorph::prelude::*;`

pub use crate::cipher::{Ciphered, CipheredBit};
pub use crate::context::{Context, Parameters, PublicKey, SecretKey};
pub use crate::operations::*;
pub use crate::{Decode, Encode};

// Subject to change in the future
pub use crate::impls as homomorph_impls;
