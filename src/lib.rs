//! A library for homomorphic encryption.
//! 
//! # Usage
//! 
//! Data is represented as `Vec<bool>`, to match binary representation.
//! `Data` instances can either be created from a `usize` or from a `Vec<bool>` (raw data).
//! 
//! User must then provide a context to its operations, which contains the secret key and the public key.
//! `Context` contains the `Parameters`, `SecretKey` and `PublicKey`.
//! 
//! Once set, the secret key can be used to decrypt the data, while the public key can be used to encrypt the data.
//! Encryption can only be performed on `Data` instances, while decryption can only be performed on `EncryptedData` instances.
//! 
//! For now, `EncryptedData` represents integers. This means you can perform addition as well as multiplication on encrypted data.
//! 
//! # Notes
//! 
//! The backend might undergo heavy changes for performance reasons.
//! 
//! Also, the fronted may change to provide a more generic interface.
//! 
//! The library is parallelized, using the `rayon` crate.
//! 
//! # Examples
//! 
//! ## Basic usage
//! 
//! Of course, this system can be used without performing any homomorphic operation.
//! 
//! Note that you can use the `as_ref()` method on either the `SecretKey` or the `PublicKey` to gain access to their content if you want to save them.
//! 
//! ```
//! use homomorph::{Context, Data, Parameters};
//! 
//! // Define the parameters
//! // -------------------------- d   dp  delta tau
//! let params = Parameters::new(64, 32, 16, 64);
//! 
//! // Create a new context
//! let mut context = Context::new(params);
//! // Initialize keys
//! context.generate_secret_key();
//! // Notice that the public key is generated after the secret key
//! context.generate_public_key();
//! 
//! // Create data from a usize
//! let data = Data::from_usize(42);
//! // Encrypt the data using the public key
//! let encrypted_data = data.encrypt(&context);
//! // Decrypt the data using the secret key
//! let decrypted_data = encrypted_data.decrypt(&context);
//! assert_eq!(data.to_usize(), decrypted_data.to_usize());
//! 
//! // Save the secret key
//! let secret_key = context.get_secret_key().unwrap().as_ref().clone();
//! // Save the public key
//! let public_key = context.get_public_key().unwrap().as_ref().clone();
//! ```
//! 
//! ## Advanced usage
//! 
//! This example shows how to perform homomorphic addition.
//! 
//! ```
//! use homomorph::{Context, Data, Parameters};
//! 
//! // Define the parameters
//! // -------------------------- d   dp  delta tau
//! let params = Parameters::new(512, 256, 16, 256);
//! let mut context = Context::new(params);
//! context.generate_secret_key();
//! context.generate_public_key();
//! 
//! // Create data from a usize
//! let data1 = Data::from_usize(20);
//! let data2 = Data::from_usize(22);
//! 
//! // Encrypt the data using the public key
//! let encrypted_data1 = data1.encrypt(&context);
//! let encrypted_data2 = data2.encrypt(&context);
//! 
//! // Perform homomorphic addition
//! let data3 = data1.add_as_uint(&data2);
//! let encrypted_data3 = encrypted_data1.add_as_uint(&encrypted_data2);
//! 
//! // Decrypt the data using the secret key
//! let decrypted_data = encrypted_data3.decrypt(&context);
//! assert_eq!(data3.to_usize(), decrypted_data.to_usize());
//! ```
//! 
//! It's important to note that here, it's impossible to operate on a data stream: everything is stored in a structure in RAM.
//! If you need to operate on data of several gigabytes in size,
//! it's a good idea to separate them into blocks and process them one by one.
//! 
//! ```ignore
//! use homomorph::{Context, Data, Parameters};
//! use std::fs::File;
//! use std::io::{BufReader, Read, BufWriter, Write};
//! 
//! let file = File::open("data.txt").unwrap();
//! let mut reader = BufReader::new(file);
//! const block_size: usize = 1024; // 524 KB when ciphered 
//! let mut buffer = [0; block_size];
//! 
//! let params = Parameters::new(512, 256, 16, 256);
//! let mut context = Context::new(params);
//! context.generate_secret_key();
//! context.generate_public_key();
//! 
//! loop {
//!     let n = reader.read(&mut buffer).unwrap();
//!     if n == 0 {
//!         break;
//!     }
//!     process_block(&mut buffer[..n], &context);
//! }
//! 
//! fn process_block(block: &mut [u8], context: &Context) {
//!     let data = Data::new(block.iter().map(|&x| x == 1).collect());
//!     // ...
//! }
//! ```
//! 
//! ## Save keys
//! 
//! In order to store ciphered data, you need to save the secret key and the public key for later use.
//! This can be done by storing the coefficients of the keys.
//! 
//! ```ignore
//! use homomorph::{Context, Parameters};
//! 
//! let mut context = Context::new(Parameters::new(6, 3, 2, 5));
//! context.generate_secret_key();
//! 
//! // Reference to the coefficients
//! let s_ref = context.get_secret_key().unwrap().as_ref();
//! 
//! // Convert the coefficients to a vector of bytes
//! let mut bytes: Vec<u8> = Vec::new();
//! for chunk in s_ref.chunks(8) {
//!     let mut byte = 0;
//!     for (i, &bit) in chunk.iter().enumerate() {
//!         if bit {
//!             byte |= 1 << (7 - i);
//!         }
//!     }
//!     bytes.push(byte);
//! }
//! 
//! // Save the bytes to a file
//! let mut file = File::create("secret_key").unwrap();
//! file.write_all(&bytes).unwrap();
//! ```
//! 
//! # Source
//! 
//! The source code is available on [GitHub](https://github.com/mathisbot/homomorph-rust).
//! You will also find details on the system and its security.

use rayon::prelude::*;
use std::mem;

pub mod polynomial;
use polynomial::Polynomial;


/// Parameters for the algorithm.
/// 
/// # Fields
/// 
/// * `d` - The degree of the secret key.
/// * `dp` - The degree of the public key.
/// * `delta` - The noise parameter.
/// * `tau` - The size of public key.
/// 
/// # Examples
/// 
/// ```
/// use homomorph::Parameters;
/// 
/// let parameters = Parameters::new(6, 3, 2, 5);
/// ```
/// 
/// # Note
/// 
/// `delta` must be strictly less than `d`.
// TODO: Hide delta so that it is guaranteed to be 32 times smaller than d
pub struct Parameters {
    d: usize,
    dp: usize,
    delta: usize,
    tau: usize,
}

impl Parameters {
    /// Creates a new set of parameters.
    /// 
    /// # Arguments
    /// 
    /// * `d` - The degree of the secret key.
    /// * `dp` - The degree of the public key.
    /// * `delta` - The noise parameter.
    /// * `tau` - The size of the public key.
    /// 
    /// # Returns
    /// 
    /// A new set of parameters.
    /// 
    /// # Note
    /// 
    /// `d` should be 32 times greater than `delta` in order to use homomorphic addition.
    /// 
    /// # Panics
    /// 
    /// This function will panic if `delta` is greater than or equal to `d`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Parameters;
    /// 
    /// let parameters = Parameters::new(6, 3, 2, 5);
    /// ```
    pub fn new(d: usize, dp: usize, delta: usize, tau: usize) -> Self {
        if delta >= d {
            panic!("Delta must be strictly less than d");
        }
        Parameters { d, dp, delta, tau }
    }
}

/// The secret key.
/// 
/// # Fields
/// 
/// * 's' - The polynomial.
/// 
/// # Examples
/// 
/// ```
/// use homomorph::{Context, Parameters};
/// 
/// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
/// 
/// context.generate_secret_key();
/// ```
pub struct SecretKey {
    s: polynomial::Polynomial,
}

impl SecretKey {
    /// Creates a new secret key.
    /// 
    /// # Arguments
    /// 
    /// * `s` - The polynomial.
    /// 
    /// # Returns
    /// 
    /// A new secret key.
    /// 
    /// # Note
    /// 
    /// For security reasons, the polynomial should only be retrieved from a previous generated secret key.
    /// For a first time generation, use `Context::generate_secret_key`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::SecretKey;
    /// use homomorph::polynomial::Polynomial;
    /// 
    /// // INSECURE!!! Only for demonstration purposes
    /// let s = Polynomial::new(vec![true, false, true]);
    /// 
    /// let sk = SecretKey::new(s);
    /// ```
    pub fn new(s: polynomial::Polynomial) -> Self {
        SecretKey { s }
    }

    pub(crate) fn random(d: usize) -> Self {
        let s = polynomial::Polynomial::random(d, &mut rand::thread_rng());
        SecretKey { s }
    }

    /// Returns a reference to the polynomial.
    /// 
    /// # Returns
    /// 
    /// A reference to the polynomial.
    /// 
    /// # Note
    /// 
    /// Can be useful to save the secret key.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters};
    /// 
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    /// context.generate_secret_key();
    /// 
    /// let s_ref = context.get_secret_key().unwrap().as_ref();
    /// ```
    pub fn as_ref(&self) -> &polynomial::Polynomial {
        &self.s
    }
}

/// The public key.
/// 
/// # Fields
/// 
/// * `list` - The list of polynomials.
/// 
/// # Examples
/// 
/// ```
/// use homomorph::{Context, Parameters};
/// 
/// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
/// 
/// context.generate_secret_key();
/// context.generate_public_key();
pub struct PublicKey {
    list: Vec<polynomial::Polynomial>,
}

impl PublicKey {
    /// Creates a new public key.
    /// 
    /// # Arguments
    /// 
    /// * `v` - The list of polynomials.
    /// 
    /// # Returns
    /// 
    /// A new public key.
    /// 
    /// # Note
    /// 
    /// For security reseasons, the list of polynomials should only be retrieved from a previous generated public key.
    /// For a first time generation, use `Context::generate_public_key`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::PublicKey;
    /// use homomorph::polynomial::Polynomial;
    /// 
    /// // INSECURE!!! Only for demonstration purposes
    /// let p = Polynomial::new(vec![true, false, true]);
    /// 
    /// let pk = PublicKey::new(vec![p]);
    /// ```
    pub fn new(v: Vec<polynomial::Polynomial>) -> Self {
        PublicKey { list: v }
    }

    pub(crate) fn random(dp: usize, delta: usize, tau: usize, secret_key: &SecretKey) -> Self {
        let list: Vec<_> = (0..tau)
            .into_par_iter()
            .map(|_| {
                let q = polynomial::Polynomial::random(dp, &mut rand::thread_rng());
                let sq = secret_key.s.clone() * q;
                let r = polynomial::Polynomial::random(delta, &mut rand::thread_rng());
                let rx = r * unsafe { Polynomial::new_unchecked(vec![false, true], 1) } ;
                let ti = sq + rx;
                ti
            })
            .collect();
    
        PublicKey { list }
    }

    /// Returns a reference to the list of polynomials.
    /// 
    /// # Returns
    /// 
    /// A reference to the list of polynomials.
    /// 
    /// # Note
    /// 
    /// Can be useful to save the public key.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters};
    /// 
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    /// 
    /// context.generate_secret_key();
    /// context.generate_public_key();
    /// 
    /// let pk = context.get_public_key().unwrap();
    /// 
    /// // Saving the public key
    /// let pk_ref = pk.as_ref();
    pub fn as_ref(&self) -> &Vec<polynomial::Polynomial> {
        &self.list
    }
}

/// The context.
/// 
/// # Fields
/// 
/// * `secret_key` - The secret key.
/// * `public_key` - The public key.
/// * `parameters` - The parameters.
/// 
/// # Examples
/// 
/// ```
/// use homomorph::{Context, Parameters};
/// 
/// let params = Parameters::new(6, 3, 2, 5);
/// let mut context = Context::new(params);
/// ```
pub struct Context {
    secret_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    parameters: Parameters,
}

impl Context {
    /// Creates a new context.
    /// 
    /// # Arguments
    /// 
    /// * `params` - The parameters.
    /// 
    /// # Returns
    /// 
    /// A new context.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters};
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// ```
    pub fn new(params: Parameters) -> Self {
        Context { secret_key: None, public_key: None, parameters: params }
    }

    /// Generates a secret key.
    /// 
    /// # Arguments
    /// 
    /// * `rng` - A random number generator.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters};
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// 
    /// context.generate_secret_key();
    /// ```
    pub fn generate_secret_key(&mut self) {
        self.secret_key = Some(SecretKey::random(self.parameters.d));
    }

    /// Generates a public key out of the private key.
    /// 
    /// # Arguments
    /// 
    /// * `rng` - A random number generator.
    /// 
    /// # Panics
    /// 
    /// This function will panic if the secret key has not been generated yet.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters};
    /// use rand::thread_rng;
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// 
    /// context.generate_public_key();
    /// ```
    pub fn generate_public_key(&mut self) {
        if let Some(secret_key) = &self.secret_key {
            self.public_key = Some(PublicKey::random(self.parameters.dp, self.parameters.delta, self.parameters.tau, secret_key));
        } else {
            panic!("Secret key not generated yet");
        }
    }

    /// Returns a reference to the secret key.
    /// 
    /// # Returns
    /// 
    /// A reference to the secret key.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters};
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// let secret_key = context.get_secret_key().unwrap();
    /// ```
    pub fn get_secret_key(&self) -> Option<&SecretKey> {
        self.secret_key.as_ref()
    }

    /// Returns a reference to the public key.
    /// 
    /// # Returns
    /// 
    /// A reference to the public key.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters};
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// context.generate_public_key();
    /// let public_key = context.get_public_key().unwrap();
    /// ```
    pub fn get_public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    /// Explicitly sets the secret key.
    /// 
    /// # Arguments
    /// 
    /// * `secret_key` - The secret key.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters, SecretKey};
    /// use homomorph::polynomial::Polynomial;
    /// 
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    /// 
    /// // INSECURE!!! Only for demonstration purposes
    /// let secret_key = SecretKey::new(Polynomial::new(vec![true, false, true]));
    /// 
    /// context.set_secret_key(secret_key);
    /// ```
    pub fn set_secret_key(&mut self, secret_key: SecretKey) {
        self.secret_key = Some(secret_key);
    }

    /// Explicitly sets the public key.
    /// 
    /// # Arguments
    /// 
    /// * `public_key` - The public key.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters, PublicKey};
    /// use homomorph::polynomial::Polynomial;
    /// 
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    /// 
    /// // INSECURE!!! Only for demonstration purposes
    /// let public_key = PublicKey::new(vec![Polynomial::new(vec![true, false, true])]);
    /// 
    /// context.set_public_key(public_key);
    /// ```
    pub fn set_public_key(&mut self, public_key: PublicKey) {
        self.public_key = Some(public_key);
    }
}

/// The data.
/// 
/// # Fields
/// 
/// * `x` - The data.
/// 
/// # Examples
/// 
/// ```
/// use homomorph::Data;
/// 
/// let data = Data::new(vec![true, false, true]);
/// ```
#[derive(Clone, Debug, Default)]
pub struct Data {
    x: Vec<bool>,
}

impl ParallelIterator for Data {
    type Item = bool;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        self.x.into_par_iter().drive_unindexed(consumer)
    }
}

/// The encrypted data.
/// 
/// # Fields
/// 
/// * `p` - The encrypted data.
/// 
/// # Examples
/// 
/// ```
/// use homomorph::{Data, Context, Parameters};
/// 
/// let params = Parameters::new(6, 3, 2, 5);
/// let mut context = Context::new(params);
/// context.generate_secret_key();
/// context.generate_public_key();
/// 
/// let data = Data::new(vec![true, false, true]);
/// let encrypted_data = data.encrypt(&context);
/// ```
#[derive(Clone, Debug, Default)]
pub struct EncryptedData {
    p: Vec<polynomial::Polynomial>,
}

impl ParallelIterator for EncryptedData {
    type Item = polynomial::Polynomial;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        self.p.into_par_iter().drive_unindexed(consumer)
    }
}

impl Data {
    /// Creates a new data.
    /// 
    /// # Arguments
    /// 
    /// * `x` - The data as a vector of booleans.
    /// 
    /// # Returns
    /// 
    /// A new data.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data = Data::new(vec![true, false, true]);
    /// ```
    pub fn new(x: Vec<bool>) -> Self {
        Data { x }
    }

    /// Creates a new data from a `u32`.
    /// 
    /// # Arguments
    /// 
    /// * `x` - `u32` to convert.
    /// 
    /// # Returns
    /// 
    /// A new data.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data = Data::from_u32(42 as u32);
    /// ```
    pub fn from_u32(x: u32) -> Self {
        let mut result = Vec::with_capacity(mem::size_of::<u32>());
        for i in 0..mem::size_of::<u32>() {
            result.push((x >> i) & 1 == 1);
        }
        Data { x: result }
    }

    /// Creates a new data from a `usize`.
    /// 
    /// # Arguments
    /// 
    /// * `x` - `usize` to convert.
    /// 
    /// # Returns
    /// 
    /// A new data.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data = Data::from_usize(42 as usize);
    /// ```
    pub fn from_usize(x: usize) -> Self {
        let mut result = Vec::with_capacity(mem::size_of::<usize>());
        for i in 0..mem::size_of::<usize>() {
            result.push((x >> i) & 1 == 1);
        }
        Data { x: result }
    }

    /// Creates a new data from a `u64`.
    /// 
    /// # Arguments
    /// 
    /// * `x` - `u64` to convert.
    /// 
    /// # Returns
    /// 
    /// A new data.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data = Data::from_u64(42 as u64);
    /// ```
    pub fn from_u64(x: u64) -> Self {
        let mut result = Vec::with_capacity(mem::size_of::<u64>());
        for i in 0..mem::size_of::<u64>() {
            result.push((x >> i) & 1 == 1);
        }
        Data { x: result }
    }

    /// Converts the data to a `u32`.
    /// 
    /// # Returns
    /// 
    /// The data as a `u32`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data = Data::new(vec![true, false, true]);
    /// let x = data.to_u32();
    /// ```
    pub fn to_u32(&self) -> u32 {
        let mut result = 0;
        let end = self.x.len().min(mem::size_of::<u32>());
        for i in 0..end {
            if self.x[i] {
                result |= 1 << i;
            }
        }
        result
    }

    /// Converts the data to a `usize`.
    /// 
    /// # Returns
    /// 
    /// The data as a `usize`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data = Data::new(vec![true, false, true]);
    /// let x = data.to_usize();
    /// ```
    pub fn to_usize(&self) -> usize {
        let mut result = 0;
        let end = self.x.len().min(mem::size_of::<usize>());
        for i in 0..end {
            if self.x[i] {
                result |= 1 << i;
            }
        }
        result
    }

    /// Converts the data to a `u64`.
    /// 
    /// # Returns
    /// 
    /// The data as a `u64`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data = Data::new(vec![true, false, true]);
    /// let x = data.to_u64();
    /// ```
    pub fn to_u64(&self) -> u64 {
        let mut result = 0;
        let end = self.x.len().min(mem::size_of::<u64>());
        for i in 0..end {
            if self.x[i] {
                result |= 1 << i;
            }
        }
        result
    }

    // Generates a random part of the integer interval \[1,`tau`\] as a vector of `bool`.
    // 
    // # Example
    // 
    // ```
    // use homomorph::Data;
    // use rand::thread_rng;
    // 
    // let part = Data::part(5, &mut thread_rng());
    // 
    // assert_eq!(part.len(), 5);
    // 
    // for bit in part {
    //    assert!(bit == true || bit == false);
    // }
    // ```
    fn part(tau: usize, rng: &mut impl rand::Rng) -> Vec<bool> {
        let mut result = Vec::with_capacity(tau);
        for _ in 0..tau {
            result.push(rng.gen::<bool>());
        }
        result
    }

    fn encrypt_bit(x: bool, pk: &PublicKey, rng: &mut impl rand::Rng) -> polynomial::Polynomial {
        let tau = pk.list.len();
        let random_part = Data::part(tau, rng);

        let sum = (0..tau).into_par_iter()
            .filter_map(|i| {
                    if random_part[i] {
                        // We can't take ownership of the polynomial in the pk list
                        Some(pk.list[i].clone())
                    } else {
                        None
                    }
                })
            .reduce_with(|mut acc, poly| {
                acc = acc.add_fn(&poly);
                acc
            })
            .unwrap_or_else(Polynomial::null);

        // Save computation if x is false
        // This does not give hints about the value of x has sum+0 is exactly the same as sum
        if x {
            unsafe { sum + Polynomial::new_unchecked(vec![x], 0) }
        } else {
            sum
        }
    }

    /// Encrypts the data.
    /// 
    /// # Arguments
    /// 
    /// * `pk` - The public key.
    /// 
    /// # Returns
    /// 
    /// The encrypted data.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Data, Context, Parameters};
    /// use rand::thread_rng;
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// context.generate_public_key();
    /// 
    /// let data = Data::new(vec![true, false, true]);
    /// let encrypted_data = data.encrypt(&context);
    /// ```
    /// 
    /// # Note
    /// 
    /// This function is parallelized.
    pub fn encrypt(&self, context: &Context) -> EncryptedData {
        if let Some(pk) = context.get_public_key() {
            let result: Vec<_> = self.x.par_iter()
                .map(|&bit| {
                    Data::encrypt_bit(bit, pk, &mut rand::thread_rng())
                })
                .collect();
        
            EncryptedData { p: result }
        } else {
            panic!("Public key not generated yet");
        }
    }
}

impl Data {
    /// Adds two `Data` instances assuming they represent integers.
    /// 
    /// # Arguments
    /// 
    /// * `other` - The other `Data` instance.
    /// 
    /// # Returns
    /// 
    /// The sum of the two `Data` instances.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    ///
    /// let data1 = Data::from_usize(20);
    /// let data2 = Data::from_usize(22);
    /// 
    /// let data3 = data1.add_as_uint(&data2);
    /// 
    /// assert_eq!(data3.to_usize(), 42);
    /// ```
    pub fn add_as_uint(&self, other: &Self) -> Self {
        let longest = self.x.len().max(other.x.len());
        let mut result = Vec::with_capacity(longest);
        let mut carry = false;
        for i in 0..longest {
            let d1 = self.x.get(i).unwrap_or(&false);
            let d2 = other.x.get(i).unwrap_or(&false);
            let s = d1 ^ d2 ^ carry;
            carry = ((d1 ^ d2) & carry ) | (d1 & d2);
            result.push(s);
        }
        Data { x: result }
    }

    /// Multiplies two `Data` instances assuming they represent integers.
    /// 
    /// # Arguments
    /// 
    /// * `other` - The other `Data` instance.
    /// 
    /// # Returns
    /// 
    /// The product of the two `Data` instances.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data1 = Data::from_usize(6);
    /// let data2 = Data::from_usize(7);
    /// 
    /// // This function is not yet implemented
    /// // let data3 = data1.mul_as_uint(&data2);
    /// 
    /// // assert_eq!(data3.to_usize(), 42);
    /// ```
    pub fn mul_as_uint(&self, _other: &Self) -> Self {
        unimplemented!("Multiplication is not yet implemented")
    }
}

impl EncryptedData {
    fn decrypt_bit(poly: &polynomial::Polynomial, sk: &SecretKey) -> bool {
        let remainder = poly.rem(sk.as_ref());
        remainder.evaluate(false)
    }

    /// Decrypts the data.
    /// 
    /// # Arguments
    /// 
    /// * `sk` - The secret key.
    /// 
    /// # Returns
    /// 
    /// The decrypted data.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Data, Context, Parameters};
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// context.generate_public_key();
    /// 
    /// let data = Data::new(vec![true, false, true]);
    /// let encrypted_data = data.encrypt(&context);
    /// 
    /// let decrypted_data = encrypted_data.decrypt(&context);
    /// ```
    /// 
    /// # Note
    /// 
    /// This function is parallelized.
    pub fn decrypt(&self, context: &Context) -> Data {
        if let Some(sk) = context.get_secret_key() {
            let result: Vec<_> = self.p.par_iter()
                .map(|poly| {
                    EncryptedData::decrypt_bit(poly, sk)
                })
                .collect();
            Data { x: result }
        } else {
            panic!("Secret key not generated yet");
        }
    }
}

/// Take advantage of the properties of the system to operate on two `EncryptedData` instances.
impl EncryptedData {
    /// Adds two `EncryptedData` instances.
    /// 
    /// # Arguments
    /// 
    /// * `other` - The other `EncryptedData` instance.
    /// 
    /// # Returns
    /// 
    /// The sum of the two `EncryptedData` instances.
    /// 
    /// # Notes
    /// 
    /// Factor `d`/`delta` must be at least 20. 32 is a good value.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Data, Context, Parameters};
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// context.generate_public_key();
    /// 
    /// let data1 = Data::from_usize(12);
    /// let data2 = Data::from_usize(30);
    /// 
    /// let encrypted_data1 = data1.encrypt(&context);
    /// let encrypted_data2 = data2.encrypt(&context);
    /// 
    /// let encrypted_data3 = encrypted_data1.add_as_uint(&encrypted_data2);
    /// ```
    pub fn add_as_uint(&self, other: &Self) -> Self {
        let longest = self.p.len().max(other.p.len());
        let mut result = Vec::with_capacity(longest);
        let mut carry = Polynomial::null();
        // Avoid borrowing issues
        let null_p = Polynomial::null();
        for i in 0..longest {
            let p1 = self.p.get(i).unwrap_or(&null_p);
            let p2 = other.p.get(i).unwrap_or(&null_p);
            let s = p1.bit_xor(&p2).bit_xor(&carry);
            /* This is too long and can be simplified :
            c <- (p1+p2)*c + p2*p2 + p1*p2*(p1+p2)*c
            c <- c*(p1+p2)*(1+p1*p2) + p1*p2 */
            // carry = p1.bit_xor(&p2).bit_and(&carry).bit_or(&p1.bit_and(&p2));
            let p1p2 = p1.mul_fn(&p2);
            carry = unsafe { p1.add_fn(&p2).mul_fn(&carry).mul_fn(&Polynomial::new_unchecked(vec![true], 0).add_fn(&p1p2)).add_fn(&p1p2) };

            result.push(s);
        }
        EncryptedData { p: result }
    }

    /// Multiplies two `EncryptedData` instances.
    /// 
    /// # Arguments
    /// 
    /// * `other` - The other `EncryptedData` instance.
    /// 
    /// # Returns
    /// 
    /// The product of the two `EncryptedData` instances.
    /// 
    /// # Notes
    /// 
    /// This function is not yet implemented.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Data, Context, Parameters};
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// context.generate_public_key();
    /// 
    /// let data1 = Data::from_usize(12);
    /// let data2 = Data::from_usize(30);
    /// 
    /// let encrypted_data1 = data1.encrypt(&context);
    /// let encrypted_data2 = data2.encrypt(&context);
    /// 
    /// // Not yet implemented
    /// // let encrypted_data3 = encrypted_data1.mul_as_uint(&encrypted_data2);
    /// ```
    pub fn mul_as_uint(&self, _other: &Self) -> Self {
        unimplemented!()
        // let longest = self.p.len().max(other.p.len());
        // let mut result = Vec::with_capacity(longest);
        // let mut carry = Polynomial::null();
        // // Avoid borrowing issues
        // let null_p = Polynomial::null();
        // for i in 0..longest {
        //     let p1 = self.p.get(i).unwrap_or(&null_p);
        //     let p2 = other.p.get(i).unwrap_or(&null_p);
        //     let s = p1.bit_and(&p2).bit_xor(&carry);
        //     carry = p1.mul_fn(&p2).add_fn(&p1.bit_and(&p2)).add_fn(&p1.bit_and(&carry)).add_fn(&p2.bit_and(&carry));
        //     result.push(s);
        // }
        // EncryptedData { p: result }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, Rng};

    #[test]
    fn test_data() {
        let data = Data::new(vec![true, false, true]);
        assert_eq!(data.to_usize(), 5);
    }

    #[test]
    fn test_data_from_usize() {
        let data = Data::from_usize(42);
        assert_eq!(data.to_usize(), 42);
    }

    #[test]
    fn test_data_add() {
        let data1 = Data::new(vec![true, false, true]);
        let data2 = Data::new(vec![false, true, false]);
        let data3 = data1.add_as_uint(&data2);
        assert_eq!(data3.to_usize(), 7);
    }

    #[test]
    fn test_encrypted_data() {
        let params = Parameters::new(16, 8, 4, 8);
        let mut context = Context::new(params);
        context.generate_secret_key();
        context.generate_public_key();

        let data = Data::new(vec![true, false, true]);
        let encrypted_data = data.encrypt(&context);
        let decrypted_data = encrypted_data.decrypt(&context);
        assert_eq!(data.to_usize(), decrypted_data.to_usize());
    }

    #[test]
    #[ignore = "Longer version of test_encrypted_data"]
    fn test_encrypted_data_extensive() {
        const N: usize = 256;
        let params = Parameters::new(128, 128, 64, 128);
        let mut context = Context::new(params);

        let mut rng = rand::thread_rng();
        for _ in 0..N {
            context.generate_secret_key();
            context.generate_public_key();

            let data = Data::from_usize(rng.gen());
            let encrypted_data = data.encrypt(&context);
            let decrypted_data = encrypted_data.decrypt(&context);
            assert_eq!(data.to_usize(), decrypted_data.to_usize());
        }
    }

    #[test]
    fn test_encrypted_data_add() {
        let params = Parameters::new(128, 32, 4, 16);
        let mut context = Context::new(params);
        context.generate_secret_key();
        context.generate_public_key();

        let data1 = Data::from_usize(12);
        let data2 = Data::from_usize(30);
        let encrypted_data1 = data1.encrypt(&context);
        let encrypted_data2 = data2.encrypt(&context);
        let encrypted_data3 = encrypted_data1.add_as_uint(&encrypted_data2);
        let decrypted_data = encrypted_data3.decrypt(&context);
        let data3 = data1.add_as_uint(&data2);
        assert_eq!(data3.to_usize(), decrypted_data.to_usize());
    }

    #[test]
    #[ignore = "Longer version of test_encrypted_data_add"]
    fn test_encrypted_data_add_extensive() {
        const N: usize = 100;
        let params = Parameters::new(128, 64, 2, 32);
        let mut context = Context::new(params);

        let mut rng = rand::thread_rng();
        for _ in 0..N {
            context.generate_secret_key();
            context.generate_public_key();

            let data1 = Data::from_usize(rng.gen());
            let data2 = Data::from_usize(rng.gen());
            let encrypted_data1 = data1.encrypt(&context);
            let encrypted_data2 = data2.encrypt(&context);
            let encrypted_data3 = encrypted_data1.add_as_uint(&encrypted_data2);
            let decrypted_data = encrypted_data3.decrypt(&context);
            let data3 = data1.add_as_uint(&data2);
            assert_eq!(data3.to_usize(), decrypted_data.to_usize());
        }
    }

    // #[test]
    // fn test_encrypted_data_mul() {
    //     let params = Parameters::new(128, 64, 8, 32);
    //     let mut context = Context::new(params);
    //     context.generate_secret_key();
    //     context.generate_public_key();

    //     let data1 = Data::from_usize(12);
    //     let data2 = Data::from_usize(30);
    //     let encrypted_data1 = data1.encrypt(&context);
    //     let encrypted_data2 = data2.encrypt(&context);
    //     let encrypted_data3 = encrypted_data1 * encrypted_data2;
    //     let decrypted_data = encrypted_data3.decrypt(&context);
    //     let data3 = data1.mul_as_uint(&data2);
    //     assert_eq!(data3.to_usize(), decrypted_data.to_usize());
    // }

    // #[test]
    // #[ignore = "Longer version of test_encrypted_data_mul"]
    // fn test_encrypted_data_mul_extensive() {
    //     const N: usize = 256;
    //     let params = Parameters::new(256, 64, 4, 32);
    //     let mut context = Context::new(params);

    //     let mut rng = rand::thread_rng();
    //     for _ in 0..N {
    //         context.generate_secret_key();
    //         context.generate_public_key();

    //         let data1 = Data::from_usize(rng.gen());
    //         let data2 = Data::from_usize(rng.gen());
    //         let encrypted_data1 = data1.encrypt(&context);
    //         let encrypted_data2 = data2.encrypt(&context);
    //         let encrypted_data3 = encrypted_data1 * encrypted_data2;
    //         let decrypted_data = encrypted_data3.decrypt(&context);
    //         let data3 = data1.mul_as_uint(&data2);
    //         assert_eq!(data3.to_usize(), decrypted_data.to_usize());
    //     }
    // }
}
