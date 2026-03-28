//! Traits and helpers used to define and execute homomorphic operations.
//!
//! The low-level traits are unsafe because they operate on raw encrypted bits.
//! For day-to-day usage, prefer the safe checked helpers on [`crate::Context`],
//! which validate operation requirements before calling these traits.

use crate::Ciphered;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Error returned when checked homomorphic operations cannot run safely.
pub enum OperationError {
    /// The context does not satisfy the required minimum `d/delta` ratio.
    InvalidParameters {
        required_min_d_over_delta: u16,
        actual_d: u16,
        actual_delta: u16,
    },
}

/// Metadata for homomorphic operations.
///
/// This allows safe wrappers to validate context parameters before delegating
/// to unsafe low-level operation traits.
pub trait OperationRequirement {
    /// Minimum value required for `d/delta`.
    const MIN_D_OVER_DELTA: u16;
}

/// This trait is used to define homomorphic operations on a single ciphered value.
///
/// ## Safety
///
/// As described here <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#properties>,
/// the properties of the system highly depends on the system's parameters.
///
/// Thus, the operation defined is unsafe so that the user ensures the parameters are valid.
/// The developer needs to clearly specify the required minimum value of `d/delta`.
///
/// In order to determine the minimum value, you can refer to
/// <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#properties>.
/// You simply have to compute the boolean degree of the operation you want to implement.
///
/// ## Example
///
#[cfg_attr(not(feature = "derive"), doc = "Using the `derive` flag:")]
#[cfg_attr(
    feature = "derive",
    doc = "This example works because the `derive` feature flag is enabled:"
)]
///
#[cfg_attr(not(feature = "derive"), doc = "```rust,ignore")]
#[cfg_attr(feature = "derive", doc = "```rust")]
/// # use homomorph::prelude::*;
/// #
/// #[derive(Copy, Clone, Debug, Encode, Decode)]
/// struct MyStruct {
///     a: usize,
///     b: usize,
/// }
///
/// struct MyOperation;
///
/// impl HomomorphicOperation1<MyStruct> for MyOperation {
///     /// ## Safety
///     ///
///     /// `d/delta` on cipher must have been at least `2*sizeof::<T>()`.
///     unsafe fn apply(a: &mut Ciphered<MyStruct>) -> &mut Ciphered<MyStruct> {
///         // Boring details here...
///         a
///     }
/// }
/// ```
pub trait HomomorphicOperation1<T: crate::Encode + crate::Decode<()>> {
    /// ## Safety
    ///
    /// The function `apply` is marked as unsafe as it handles raw bits of data.
    /// You must ensure this function will result in valid ciphered data.
    ///
    /// In particular, you need to pay attention to the value of `d/delta`
    /// used on cipher.
    unsafe fn apply(a: &mut Ciphered<T>) -> &mut Ciphered<T>;
}

/// This trait is used to define homomorphic operations between two ciphered values.
///
/// ## Safety
///
/// As described here <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#properties>,
/// the properties of the system highly depends on the system's parameters.
///
/// Thus, the operation defined is unsafe so that the user ensures the parameters are valid.
/// The developer needs to clearly specify the required minimum value of `d/delta`.
///
/// In order to determine the minimum value, you can refer to
/// <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#properties>.
/// You simply have to compute the boolean degree of the operation you want to implement.
///
/// ## Example
///
#[cfg_attr(not(feature = "derive"), doc = "Using the `derive` flag:")]
#[cfg_attr(
    feature = "derive",
    doc = "This example works because the `derive` feature flag is enabled:"
)]
///
#[cfg_attr(not(feature = "derive"), doc = "```rust,ignore")]
#[cfg_attr(feature = "derive", doc = "```rust")]
/// # use homomorph::prelude::*;
/// #
/// #[repr(C)]
/// #[derive(Copy, Clone, Debug, Encode, Decode)]
/// struct MyStruct {
///     a: usize,
///     b: usize,
/// }
///
/// struct MyOperation;
///
/// impl HomomorphicOperation2<MyStruct> for MyOperation {
///     /// ## Safety
///     ///
///     /// `d/delta` on cipher must have been at least `2*sizeof::<T>()`.
///     unsafe fn apply(a: &Ciphered<MyStruct>, b: &Ciphered<MyStruct>) -> Ciphered<MyStruct> {
///         let mut c_pol: Vec<CipheredBit> = Vec::with_capacity(a.len().max(b.len()));
///
///         // Boring details here...
///
///         unsafe { Ciphered::new_from_raw(c_pol) }
///     }
/// }
/// ```
pub trait HomomorphicOperation2<T: crate::Encode + crate::Decode<()>> {
    /// ## Safety
    ///
    /// The function `apply` is marked as unsafe as it handles raw bits of data.
    /// You must ensure this function will result in valid ciphered data.
    ///
    /// In particular, you need to pay attention to the value of `d/delta`
    /// used on cipher.
    unsafe fn apply(a: &Ciphered<T>, b: &Ciphered<T>) -> Ciphered<T>;
}

/// This trait is used to define homomorphic operations for a compile-time-known number of ciphered values.
///
/// ## Safety
///
/// As described here <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#properties>,
/// the properties of the system highly depends on the system's parameters.
///
/// Thus, the operation defined is unsafe so that the user ensures the parameters are valid.
/// The developer needs to clearly specify the required minimum value of `d/delta`.
///
/// In order to determine the minimum value, you can refer to
/// <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#properties>.
/// You simply have to compute the boolean degree of the operation you want to implement.
///
/// ## Example
///
#[cfg_attr(not(feature = "derive"), doc = "Using the `derive` flag:")]
#[cfg_attr(
    feature = "derive",
    doc = "This example works because the `derive` feature flag is enabled:"
)]
///
#[cfg_attr(not(feature = "derive"), doc = "```rust,ignore")]
#[cfg_attr(feature = "derive", doc = "```rust")]
/// # use homomorph::prelude::*;
/// #
/// #[repr(C)]
/// #[derive(Copy, Clone, Debug, Encode, Decode)]
/// struct MyStruct {
///     a: usize,
///     b: usize,
/// }
///
/// struct MyOperation;
///
/// impl<const N: usize> HomomorphicOperation<N, MyStruct> for MyOperation {
///     /// ## Safety
///     ///
///     /// `d/delta` on cipher must have been at least `3*sizeof::<T>()`.
///     unsafe fn apply(args: [&Ciphered<MyStruct>; N]) -> Ciphered<MyStruct> {
///         let result = args[0].to_vec();
///
///         // Boring details here...
///
///         unsafe { Ciphered::new_from_raw(result) }
///     }
/// }
///
/// // Usage
/// # let params = Parameters::new(32, 8, 4, 8);
/// # let mut context = Context::new(params);
/// # context.generate_secret_key();
/// # context.generate_public_key().unwrap();
/// # let sk = context.get_secret_key().unwrap();
/// # let pk = context.get_public_key().unwrap();
/// #
/// let a = Ciphered::cipher(&MyStruct { a: 1, b: 2 }, pk);
/// let b = Ciphered::cipher(&MyStruct { a: 3, b: 4 }, pk);
/// let c = unsafe { MyOperation::apply([&a, &b]) };
/// let d = Ciphered::decipher(&c, sk);
/// ```
pub trait HomomorphicOperation<const N: usize, T: crate::Encode + crate::Decode<()>> {
    /// ## Safety
    ///
    /// The function `apply` is marked as unsafe as it handles raw bits of data.
    /// You must ensure this function will result in valid ciphered data.
    ///
    /// In particular, you need to pay attention to the value of `d/delta`
    /// used on cipher.
    unsafe fn apply(args: [&Ciphered<T>; N]) -> Ciphered<T>;
}
