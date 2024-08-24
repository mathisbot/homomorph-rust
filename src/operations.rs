//! This module defines the traits used to define homomorphic operations on ciphered data.
//!
//! Currently, there are 3 traits that you can use :
//!
//! - `HomomorphicOperation1<T: Encode + Decode>`
//! - `HomomorphicOperation2<T: Encode + Decode>`
//! - `HomomorphicOperation<const N: usize, T: Encode + Decode>`
//!
//! The traits only bounds one function to implement, `apply`.
//! The operation is performed on raw data, which means it takes `Ciphered<T>` as arguments.
//!
//! The first two traits takes respectively 1 and 2 refs on `Ciphered<T>`,
//! while the last one takes a compile-time-known number of arguments as a slice of refs.
//! The main idea behind the last trait is to allow the user to define operations on an arbitrary number of ciphered data
//! while still benefiting from Rust's type system.
//!
//! Inside of the function, you can work with `Cipehered<T>` as if it were a `&Vec<CipheredBit>`
//! (because `Cipehered<T>` implements `Deref<Vec<CipheredBit>`).
//!
//! From that point, all operations are highly unsafe as you are working with raw bits.
//! For instance, can apply logic gates to the `CipheredBit`s.

use crate::Ciphered;

/// This trait is used to define homomorphic operations on a single ciphered data
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
/// ```rust
/// use homomorph::prelude::*;
///
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
pub trait HomomorphicOperation1<T: crate::Encode + crate::Decode> {
    /// ## Safety
    ///
    /// The function `apply` is marked as unsafe as it handles raw bits of data.
    /// You must ensure this function will result in valid ciphered data.
    ///
    /// In particular, you need to pay attention to the value of `d/delta`
    /// used on cipher.
    unsafe fn apply(a: &mut Ciphered<T>) -> &mut Ciphered<T>;
}

/// This trait is used to define homomorphic operations between two ciphered data
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
/// ```rust
/// use homomorph::prelude::*;
///
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
pub trait HomomorphicOperation2<T: crate::Encode + crate::Decode> {
    /// ## Safety
    ///
    /// The function `apply` is marked as unsafe as it handles raw bits of data.
    /// You must ensure this function will result in valid ciphered data.
    ///
    /// In particular, you need to pay attention to the value of `d/delta`
    /// used on cipher.
    unsafe fn apply(a: &Ciphered<T>, b: &Ciphered<T>) -> Ciphered<T>;
}

/// This trait is used to define homomorphic operations between a compile-time-known number of ciphered data
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
/// ```rust
/// use homomorph::prelude::*;
/// use core::ops::Deref;
///
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
///         let result = args[0].deref().clone();
///
///         // Boring details here...
///
///         unsafe { Ciphered::new_from_raw(result) }
///     }
/// }
///
/// // Usage
/// let params = Parameters::new(32, 8, 4, 8);
/// let mut context = Context::new(params);
/// context.generate_secret_key();
/// context.generate_public_key();
/// let sk = context.get_secret_key().unwrap();
/// let pk = context.get_public_key().unwrap();
///
/// let a = Ciphered::cipher(&MyStruct { a: 1, b: 2 }, pk);
/// let b = Ciphered::cipher(&MyStruct { a: 3, b: 4 }, pk);
/// let c = unsafe { MyOperation::apply([&a, &b]) };
/// let d = Ciphered::decipher(&c, sk);
/// ```
pub trait HomomorphicOperation<const N: usize, T: crate::Encode + crate::Decode> {
    /// ## Safety
    ///
    /// The function `apply` is marked as unsafe as it handles raw bits of data.
    /// You must ensure this function will result in valid ciphered data.
    ///
    /// In particular, you need to pay attention to the value of `d/delta`
    /// used on cipher.
    unsafe fn apply(args: [&Ciphered<T>; N]) -> Ciphered<T>;
}
