//! # Homomorphic Encryption in Rust
//!
//! A library for homomorphic encryption using a polynomial-based system.
//!
//! Homomorphic encryption allows you to perform operations on encrypted data without decrypting it.
//! If you want to learn more about the system used here,
//! visit <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#system>.
//!
//! ## Usage
//!
//! The crate can be used to perform already-implemented operations on ciphered data,
//! or to define your own operations on your own structs.
//!
//! ### Basic usage
//!
//! Basic usage consists of creating a context, generating keys, and performing operations.
//!
//! #### Context
//!
//! The first step is to create a context.
//! The system uses 4 parameters: `d`, `dp`, `delta` and `tau`.
//!
//! Usually, you want `dp` and `tau` to be 128, or 256 for the most sensitive applications.
//! As for `d` and `delta`, you will have to choose them accordingly to the operations you want to perform.
//! This is because the system's properties rely on the value of the ratio `d/delta`.
//!
//! If you want to learn more about how to choose your parameters,
//! visit <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#system>
//!
//! ```rust
//! use homomorph::prelude::*;
//!
//! let parameters = Parameters::new(64, 32, 8, 32);
//! let mut context = Context::new(parameters);
//! context.generate_secret_key();
//! context.generate_public_key();
//! ```
//!
//! If you need to save the keys for later use, you can do so by saving the raw bytes.
//!
//! ```rust
//! use homomorph::prelude::*;
//!
//! let parameters = Parameters::new(64, 32, 8, 32);
//! let mut context = Context::new(parameters);
//! context.generate_secret_key();
//! context.generate_public_key();
//!
//! let sk_bytes = context.get_secret_key().unwrap().get_bytes();
//! let pk_bytes = context.get_public_key().unwrap().get_bytes();
//!
//! context.set_secret_key(SecretKey::new(&sk_bytes));
//! context.set_public_key(PublicKey::new(&pk_bytes));
//! ```
//!
//! #### Cipher
//!
//! The crates features a generic type `Ciphered<T>` that allows you to cipher almost any type
//! (see next section for more information about which types can be ciphered).
//!
//! ```rust
//! use homomorph::prelude::*;
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
//! For instance, you can add two ciphered unsigned integers together.
//!
//! ```no_run
//! use homomorph::prelude::*;
//! use homomorph::impls::numbers::HomomorphicAddition;
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
//! As you can see, applying homomorphic operations is marked as unsafe.
//! This is because you must make sure that your data has been ciphered using
//! a sufficiently high `d/delta` value, according to the documentation
//! of the operation's `apply` function.
//!
//! ### Advanced usage
//!
//! The crate's API also allows you to define your own operations on any ciphered data.
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
//! As some specific logic can be necessary to convert your own structs,
//! the implementation is left to you.
//! For instance, you can't just blindly convert a `Vec` to bytes, as the
//! majority of its data lives on the heap.
//!
//! #### Cipher
//!
//! The system uses a `Ciphered<T>` type to store encrypted data.
//! It is implemented for any type that implements `ByteConvertible`.
//!
//! The system is in fact very simple, as it needs to be very general.
//! Every bit is ciphered as a `CipheredBit` (which is a polynomial in the backend).
//! You can operate on `CipheredBit`s using logic gates.
//!
//! If you want to learn more about the way bits can be used,
//! visit <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#extension>.
//!
//! #### `HomomorphicOperation` traits
//!
//! The system provides traits allowing you to define homomorphic operations.
//!
//! Currently, there are 3 traits that you can use :
//!
//! - `HomomorphicOperation1<T: ByteConvertible>`
//! - `HomomorphicOperation2<T: ByteConvertible>`
//! - `HomomorphicOperation<const N: usize, T: ByteConvertible>`
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
//!
//! If you need more information on this traits, visit [their documentation](operations).
//!
//! #### Homomorphic operations
//!
//! To implement an homomorphic operation, define a struct that implements an `HomomorphicOperation` trait.
//!
//! For example, to implement addition for `Ciphered<usize>`, you will have to define a struct `HomomorphicAddition`,
//! and implement the unsafe trait `HomomorphicOperation2<usize>` for it.
//!
//! Fortunately, the crate already implement some of the basic operations.
//!
//! #### Example
//!
//! We will be working with a sample data structure.
//!
//! First, we need to implement the `ByteConvertible` trait for `MyStruct`,
//! because we didn't derive `Copy` for `MyStruct`.
//! In a real-world application, you would derive `Copy` for your struct.
//!
//! Doing so will make all ciphering operation available for this struct.
//!
//! ```rust
//! use homomorph::prelude::*;
//! use core::ptr::copy_nonoverlapping as memcpy;
//!
//! struct MyStruct {
//!     a: u32,
//!     b: u32,
//! }
//!
//! // Fortunately, `MyStruct` is `Sized`!
//! unsafe impl ByteConvertible for MyStruct {
//!     fn to_bytes(&self) -> Vec<u8> {
//!         let mut bytes = Vec::with_capacity(size_of::<MyStruct>());
//!         bytes.extend_from_slice(&self.a.to_le_bytes());
//!         bytes.extend_from_slice(&self.b.to_le_bytes());
//!         bytes
//!     }
//!
//!     fn from_bytes(bytes: &[u8]) -> Self {
//!         if bytes.len() != size_of::<MyStruct>() {
//!             panic!(
//!                 "Invalid size of bytes for conversion: {} instead of {}",
//!                 bytes.len(),
//!                 size_of::<MyStruct>()
//!             );
//!         }
//!
//!         let (a_bytes, b_bytes) = bytes.split_at(size_of::<u32>());
//!
//!         let a = u32::from_le_bytes([a_bytes[0], a_bytes[1], a_bytes[2], a_bytes[3]]);
//!         let b = u32::from_le_bytes([b_bytes[0], b_bytes[1], b_bytes[2], b_bytes[3]]);
//!         MyStruct { a, b }
//!     }
//! }
//! ```
//!
//! If we then want to implement an homomorphic addition for our struct,
//! we will have to define a struct `HomomorphicAddition`
//! that implements the trait `HomomorphicOperation2<usize>`.
//!
//! The key to implement such operations is to mimic the behavior of the operation on unciphered bits.
//! The only little trick is that we can't take decisions based on the value of the bits, as they're ciphered.
//!
//! Keep in mind that you can apply logical gates to the ciphered bits.
//!
//! Here, we would just mimic how a processor would implement addition on uint.
//!
//! ```rust
//! use homomorph::prelude::*;
//!
//! // Here, we derive Copy so that `ByteConvertible` is automatically implemented
//! #[repr(C)]
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
//! This can also be done by trial and error.
//!
//! For a more precise example, you can take a look at the examples in `./examples/`.
//!
//! ## Source
//!
//! The source code is available on [GitHub](<https://github.com/mathisbot/homomorph-rust>).
//! You will also find very interesting details on the system and its security.
#![no_std]
#![deny(clippy::all)]
#![warn(clippy::nursery, clippy::pedantic)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "custom_rand")]
pub use getrandom::register_custom_getrandom;

mod polynomial;

mod context;
pub use context::{Context, Parameters, PublicKey, SecretKey};

mod cipher;
pub use cipher::{ByteConvertible, Ciphered, CipheredBit};

pub mod operations;

pub mod impls;

pub mod prelude;
