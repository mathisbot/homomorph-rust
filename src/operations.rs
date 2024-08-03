use crate::{ByteConvertible, Ciphered};

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
/// use homomorph::{Ciphered, HomomorphicOperation1, Polynomial};
///
/// #[derive(Copy, Clone)]
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
pub trait HomomorphicOperation1<T: ByteConvertible> {
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
/// use homomorph::{Ciphered, HomomorphicOperation2, Polynomial};
///
/// #[derive(Copy, Clone)]
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
///         let mut c_pol: Vec<Polynomial> = Vec::with_capacity(a.len().max(b.len()));
///
///         // Boring details here...
///
///         unsafe { Ciphered::new_from_raw(c_pol) }
///     }
/// }
/// ```
pub trait HomomorphicOperation2<T: ByteConvertible> {
    /// ## Safety
    ///
    /// The function `apply` is marked as unsafe as it handles raw bits of data.
    /// You must ensure this function will result in valid ciphered data.
    ///
    /// In particular, you need to pay attention to the value of `d/delta`
    /// used on cipher.
    unsafe fn apply(a: &Ciphered<T>, b: &Ciphered<T>) -> Ciphered<T>;
}
