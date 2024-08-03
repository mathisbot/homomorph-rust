//! # Homomorphic Encryption in Rust
//!
//! A library for homomorphic encryption using a polynomial-based system.
//!
//! Homomorphic encryption allows you to perform operations on encrypted data without decrypting it.
//! If you want to learn more about the what homomorphic encryption is, visit <https://github.com/mathisbot/homomorph-rust>
//!
//! ## Usage
//!
//! The crate can be used to perform basic operations on encrypted data, or to define your own operations.
//!
//! ### Basic usage
//!
//! Basic usage consists of creating a context, generating keys, and performing operations.
//!
//! #### Context
//!
//! The first step is to create a context.
//! The system uses 4 parameters: `d`, `dp`, `delta` and `tau`.
//! If you want to learn more about how to choose your parameters, visit <https://github.com/mathisbot/homomorph-rust>
//! Otherwise, (d, dp, delta, tau) = (128, 64, 16, 128) is a good starting point.
//!
//! ```rust
//! use homomorph::{Context, Parameters};
//!
//! let parameters = Parameters::new(64, 32, 8, 32);
//! let mut context = Context::new(parameters);
//! context.generate_secret_key();
//! context.generate_public_key();
//! ```
//!
//! If you need to save the keys for later use, you can do so by saving the bytes.
//!
//! ```rust
//! use homomorph::{Context, Parameters, PublicKey, SecretKey};
//!
//! let parameters = Parameters::new(64, 32, 8, 32);
//! let mut context = Context::new(parameters);
//! context.generate_secret_key();
//! context.generate_public_key();
//!
//! let sk_bytes = context.get_secret_key().unwrap().get_bytes();
//! let pk_bytes = context.get_public_key().unwrap().get_bytes();
//!
//! context.set_secret_key(SecretKey::new(sk_bytes));
//! context.set_public_key(PublicKey::new(pk_bytes));
//! ```
//!
//! #### Cipher
//!
//! The crates implements the basic traits for a vast majority of std types.
//! This way, you easily cipher your data.
//!
//! ```rust
//! use homomorph::{Context, Parameters, Ciphered};
//!
//! let parameters = Parameters::new(64, 32, 8, 32);
//! let mut context = Context::new(parameters);
//! context.generate_secret_key();
//! context.generate_public_key();
//! let sk = context.get_secret_key().unwrap();
//! let pk = context.get_public_key().unwrap();
//!
//! let data = 0b10001010u8;
//! let ciphered = Ciphered::cipher(&data, &pk);
//! let decrypted = ciphered.decipher(&sk);
//! assert_eq!(data, decrypted);
//! ```
//!
//! #### Operations
//!
//! Once again, the system implements some basic operation for you.
//! For instance, you can already add two ciphered unsigned integers.
//!
//! ```no_run
//! use homomorph::{Context, Parameters, Ciphered, HomomorphicAddition, HomomorphicOperation2};
//!
//! let parameters = Parameters::new(128, 64, 1, 64);
//! let mut context = Context::new(parameters);
//! context.generate_secret_key();
//! context.generate_public_key();
//! let pk = context.get_public_key().unwrap();
//! let sk = context.get_secret_key().unwrap();
//!
//! let a = Ciphered::cipher(&3usize, &pk);
//! let b = Ciphered::cipher(&5usize, &pk);
//! let c = unsafe { HomomorphicAddition::apply(&a, &b) };
//! let d = c.decipher(sk);
//! assert_eq!(d, 3 + 5);
//! ```
//!
//! ### Advanced usage
//!
//! The crate's API also allows you to define your own operations.
//! Let's take a look at how you can do so.
//!
//! #### `ByteConvertible` trait
//!
//! Data is handled as arrays of bits, to match binary representation.
//! Thus, types need to implement a specific trait, `ByteConvertible`.
//!
//! The main idea of the `ByteConvertible` trait is to be able to convert the data to a byte array and back.
//!
//! This trait is already implemented for all types that implement `Copy`.
//!
//! #### Cipher
//!
//! The system uses a `Ciphered<T>` type to store encrypted data.
//! All you have to do is call `Ciphered::cipher` on any data that implements `ByteConvertible`.
//!
//! To decipher it, call `Ciphered::decipher` on the ciphered data.
//!
//! The system is in fact very simple, as it needs to be very general.
//! Every bit is ciphered as a `CipheredBit`, which is a polynomial in the backend.
//! If you want to learn more about the system used here, visit <https://github.com/mathisbot/homomorph-rust>
//!
//! #### `HomomorphicOperationX<T>` trait
//!
//! The system provides traits allowing you to define homomorphic operations.
//!
//! Replace X with a certain number of arguments. Supported values are 1 and 2.
//! If you need more, feel free to implement your own `HomomorphicOperationN`
//! based on examples found in `operations.rs`.
//!
//! The trait only bounds one function to implement, `apply`.
//! The operation is performed on raw data, which means it takes `Ciphered<T>` as arguments.
//!
//! Inside of the function, you can work with `Cipehered<T>` as if it were a `Vec<CipheredBit>`
//! (because this is actually what it is).
//! From that point, all operations are highly unsafe as you are working with raw bits.
//!
//! You will be able to apply logic gates to the `CipheredBit`s.
//!
//! #### Homomorphic operations
//!
//! To implement an homomorphic operation, define a struct that implements `HomomorphicOperationX<T>`.
//!
//! For example, to implement addition, you will have to define a struct `HomomorphicAddition`,
//! and implement the unsafe trait `HomomorphicOperation2<usize>` for it.
//!
//! Fortunately, the crate already implements all of these basic operations for you.
//!
//! #### Example
//!
//! We will be working with a sample data structure.
//!
//! Please remember that a majority of the implementations here are already done for all types
//! that implement basic traits such as `Copy`.
//!
//! First, we need to implement the `ByteConvertible` trait for `MyStruct`.
//! It will make all ciphering operation available for it.
//!
//! ```rust
//! use homomorph::{Ciphered, ByteConvertible};
//! use core::ptr::copy_nonoverlapping as memcpy;
//!
//! struct MyStruct {
//!     a: usize,
//!     b: usize,
//! }
//!
//! unsafe impl ByteConvertible for MyStruct {
//!     fn to_bytes(&self) -> Vec<u8> {
//!         let mut bytes = Vec::with_capacity(size_of::<MyStruct>());
//!         unsafe {
//!             memcpy(self as *const MyStruct as *const u8, bytes.as_mut_ptr(), size_of::<MyStruct>());
//!             bytes.set_len(size_of::<MyStruct>());
//!         }
//!         bytes
//!     }
//!
//!     fn from_bytes(bytes: &[u8]) -> Self {
//!         let mut data = core::mem::MaybeUninit::uninit();
//!         unsafe {
//!             memcpy(
//!                 bytes.as_ptr(),
//!                 data.as_mut_ptr() as *mut u8,
//!                 size_of::<MyStruct>(),
//!             );
//!             data.assume_init()
//!         }
//!     }
//! }
//! ```
//!
//! If we then want to implement an homomorphic addition for `usize`, we will have to define a struct `HomomorphicAddition`
//! that implements the trait `HomomorphicOperation2<usize>`.
//!
//! The key to implement such operations is to mimic the behavior of the operation on unciphered bits, but the bits are unknown.
//! The only little trick is that we can't take decisions based on the value of the bits, as they're ciphered.
//!
//! Keep in mind that you can apply logical gates to the ciphered bits.
//!
//! Here, we just mimic how a processor would implement addition on uint.
//!
//! ```rust
//! use homomorph::{Ciphered, CipheredBit, HomomorphicOperation2};
//!
//! // Here, we derive Copy so that the system can cipher the data
//! #[derive(Copy, Clone)]
//! struct MyStruct {
//!     a: usize,
//!     b: usize,
//! }
//!
//! struct MyOperation;
//!
//! impl HomomorphicOperation2<MyStruct> for MyOperation {
//!     /// ## Safety
//!     ///
//!     /// `d/delta` on cipher must have been at least `2*sizeof::<T>()`.
//!     unsafe fn apply(a: &Ciphered<MyStruct>, b: &Ciphered<MyStruct>) -> Ciphered<MyStruct> {
//!         let mut c_pol: Vec<CipheredBit> = Vec::with_capacity(a.len().max(b.len()));
//!
//!         // Boring details here...
//!
//!         unsafe { Ciphered::new_from_raw(c_pol) }
//!     }
//! }
//! ```
//!
//! Pay attention to the useful documentation on the `apply` function.
//! It is very helpful to the user as they will know what parameters are required for the operation to be valid.
//!
//! In order to determine the minimum value, you can refer to
//! <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#properties>.
//! You simply have to compute the boolean degree of the operation you want to implement.
//!
//! ## Source
//!
//! The source code is available on [GitHub](<https://github.com/mathisbot/homomorph-rust>).
//! You will also find very interesting details on the system and its security.

#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "no_rand")]
pub use getrandom::register_custom_getrandom as provide_getrandom;

mod polynomial;

mod context;
pub use context::*;

mod cipher;
pub use cipher::*;

mod operations;
pub use operations::*;

mod impls;
pub use impls::*;
