//! A library for homomorphic encryption.
//! 
//! # Usage
//! 
//! Data is represented as `Vec<bool>`, to match binary representation.
//! `Data` instances can either be created from a `usize` or from a `Vec<bool>` (raw data).
//! In the future, other types of data will be supported.
//! 
//! User must then provide a context to its operations, which contains the secret key and the public key.
//! `Context` contains the `Parameters`, `SecretKey` and `PublicKey`.
//! 
//! Once set, the secret key can be used to decrypt the data, while the public key can be used to encrypt the data.
//! Encryption can only be performed on `Data` instances, while decryption can only be performed on `EncryptedData` instances.
//! 
//! Because of the properties of the cryposystem, you can perform several operations on encrypted data.
//! As an example, if encrypted data represents unsigned integers, you can perform addition as well as multiplication.
//! 
//! Recommanded parameters are `d >= 512`, `dp >= 128`, `delta = d/32` and `tau = 256`.
//! 
//! # Examples
//! 
//! ## Basic usage
//! 
//! Of course, this system can be used without performing any homomorphic operation.
//! 
//! ```
//! use homomorph::{Context, Data, Parameters};
//! 
//! // Define the parameters
//! // -------------------------  d  dp delta tau
//! let params = Parameters::new(16, 16, 8, 8);
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
//! ```
//! 
//! ## Advanced usage
//! 
//! This example shows how to perform homomorphic addition on unsigned integers.
//! `delta` should be at least 20 times smaller than `d`.
//! 
//! ```no_run
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
//! let encrypted_data3 = unsafe { encrypted_data1.add_as_uint(&encrypted_data2) };
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
//! ```no_run
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
//! ### Save to a file
//! 
//! ```no_run
//! use homomorph::{Context, Parameters};
//! use std::fs::File;
//! use std::io::Write;
//! 
//! let mut context = Context::new(Parameters::new(6, 3, 2, 5));
//! context.generate_secret_key();
//! 
//! // Reference to the coefficients
//! let key_bytes = context.get_secret_key().unwrap().get_bytes();
//! 
//! // Save the bytes to a file
//! let mut file = File::create("secret_key").unwrap();
//! file.write_all(&key_bytes).unwrap();
//! ```
//! 
//! ### Retrieve from a file
//! 
//! ```no_run
//! use homomorph::{Context, Parameters, SecretKey};
//! use std::fs::File;
//! use std::io::Read;
//! 
//! let mut context = Context::new(Parameters::new(6, 3, 2, 5));
//! 
//! // Read the bytes from a file
//! let mut file = File::open("secret_key").expect("Could not open file");
//! let mut key_bytes = Vec::new();
//! file.read_to_end(&mut key_bytes).unwrap();
//! 
//! // Create the secret key from the bytes
//! let secret_key = SecretKey::new(key_bytes);
//! context.set_secret_key(secret_key);
//! ```
//! 
//! # Source
//! 
//! The source code is available on [GitHub](https://github.com/mathisbot/homomorph-rust).
//! You will also find details on the system and its security.

use rayon::prelude::*;
use std::mem;

mod polynomial;
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
    /// As the system properties highly depends on the quantity `d`/`delta`, it is advised
    /// to take a look at recommandations in the documentation.
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
pub struct SecretKey {
    s: polynomial::Polynomial,
}

impl SecretKey {
    /// Creates a new secret key.
    /// 
    /// # Arguments
    /// 
    /// * `bytes` - The bytes representing the secret key.
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
    /// 
    /// // INSECURE!!! Only for demonstration purposes
    /// let s = vec![5, 14, 8];
    /// 
    /// let sk = SecretKey::new(s);
    /// ```
    pub fn new(bytes: Vec<u8>) -> Self {
        let mut bits: Vec<bool> = Vec::new();
        for byte in bytes.iter() {
            for i in 0..8 {
                bits.push(byte & (1 << i) != 0);
            }
        }
        let s = polynomial::Polynomial::new(bits);
        SecretKey { s }
    }

    pub(self) fn random(d: usize) -> Self {
        let s = polynomial::Polynomial::random(d, &mut rand::thread_rng());
        SecretKey { s }
    }

    /// Returns bytes representing the secret key.
    /// 
    /// # Returns
    /// 
    /// A `Vec<u8>` representing the secret key.
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
    /// let key_bytes = context.get_secret_key().unwrap().get_bytes();
    /// ```
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        for chunk in self.s.chunks(8) {
            let mut byte = 0;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << i;
                }
            }
            bytes.push(byte);
        };
        bytes
    }
}

/// The public key.
pub struct PublicKey {
    list: Vec<polynomial::Polynomial>,
}

impl PublicKey {
    /// Creates a new public key.
    /// 
    /// # Arguments
    /// 
    /// * `bytes` - The bytes representing the public key.
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
    /// 
    /// // INSECURE!!! Only for demonstration purposes
    /// let p = vec![vec![4, 7, 5], vec![1, 2, 3], vec![5, 4, 6]];
    /// 
    /// let pk = PublicKey::new(p);
    /// ```
    pub fn new(bytes: Vec<Vec<u8>>) -> Self {
        let mut list: Vec<polynomial::Polynomial> = Vec::new();
        for bytes in bytes.iter() {
            let mut bits: Vec<bool> = Vec::new();
            for byte in bytes.iter() {
                for i in 0..8 {
                    bits.push(byte & (1 << i) != 0);
                }
            }
            let p = polynomial::Polynomial::new(bits);
            list.push(p);
        }
        PublicKey { list }
    }

    pub(self) fn random(dp: usize, delta: usize, tau: usize, secret_key: &SecretKey) -> Self {
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

    /// Returns bytes representing the public key.
    /// 
    /// # Returns
    /// 
    /// A `Vec<Vec<u8>>` representing the public key.
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
    /// context.generate_secret_key();
    /// context.generate_public_key();
    /// 
    /// let key_bytes = context.get_public_key().unwrap().get_bytes();
    /// ```
    pub fn get_bytes(&self) -> Vec<Vec<u8>> {
        let mut bytes_outer: Vec<Vec<u8>> = Vec::new();
        for pol in self.list.iter() {
            let mut bytes: Vec<u8> = Vec::new();
            for chunk in pol.chunks(8) {
                let mut byte = 0;
                for (i, &bit) in chunk.iter().enumerate() {
                    if bit {
                        byte |= 1 << i;
                    }
                }
                bytes.push(byte);
            }
            bytes_outer.push(bytes);
        }
        bytes_outer
    }
}

/// The cipher context.
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
    /// 
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    /// 
    /// // INSECURE!!! Only for demonstration purposes
    /// let s = vec![5, 14, 8];
    /// let sk = SecretKey::new(s);
    /// 
    /// context.set_secret_key(sk);
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
    /// 
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    /// 
    /// // INSECURE!!! Only for demonstration purposes
    /// let p = vec![vec![4, 7, 5], vec![1, 2, 3], vec![5, 4, 6]];
    /// let pk = PublicKey::new(p);
    /// 
    /// context.set_public_key(pk);
    /// ```
    pub fn set_public_key(&mut self, public_key: PublicKey) {
        self.public_key = Some(public_key);
    }
}

/// The data.
#[derive(Clone, Debug, Default)]
pub struct Data {
    x: Vec<bool>,
}

/// The encrypted data.
#[derive(Clone, Debug, Default)]
pub struct EncryptedData {
    p: Vec<polynomial::Polynomial>,
}

impl Data {
    /// Creates a new data.
    /// 
    /// # Arguments
    /// 
    /// * `x` - The data as a raw vector of booleans.
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

    /// Creates a new data from a `u16`.
    /// 
    /// # Arguments
    /// 
    /// * `x` - `u16` to convert.
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
    /// let data = Data::from_u16(42 as u16);
    /// ```
    pub fn from_u16(x: u16) -> Self {
        let mut result = Vec::with_capacity(mem::size_of::<u16>()*8);
        for i in 0..mem::size_of::<u16>()*8 {
            result.push((x >> i) & 1 == 1);
        }
        Data { x: result }
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
        let mut result = Vec::with_capacity(mem::size_of::<u32>()*8);
        for i in 0..mem::size_of::<u32>()*8 {
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
        let mut result = Vec::with_capacity(mem::size_of::<usize>()*8);
        for i in 0..mem::size_of::<usize>()*8 {
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
        let mut result = Vec::with_capacity(mem::size_of::<u64>()*8);
        for i in 0..mem::size_of::<u64>()*8 {
            result.push((x >> i) & 1 == 1);
        }
        Data { x: result }
    }

    /// Converts the data to a `u16`.
    /// 
    /// # Returns
    /// 
    /// The data as a `u16`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data = Data::new(vec![true, false, true]);
    /// let x = data.to_u16();
    /// ```
    pub fn to_u16(&self) -> u16 {
        let mut result = 0;
        let end = self.x.len().min(mem::size_of::<u16>()*8);
        for i in 0..end {
            if self.x[i] {
                result |= 1 << i;
            }
        }
        result
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
        let end = self.x.len().min(mem::size_of::<u32>()*8);
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
        let end = self.x.len().min(mem::size_of::<usize>()*8);
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
        let end = self.x.len().min(mem::size_of::<u64>()*8);
        for i in 0..end {
            if self.x[i] {
                result |= 1 << i;
            }
        }
        result
    }

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
    /// * `context` - The context.
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

    fn _clone_shifted(&self, n: usize) -> Data {
        let mut new = vec![false; n];
        for &digit in self.x.iter() {
            new.push(digit);
        }
        Data { x: new }
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
    /// # Note
    /// 
    /// It should be faster to convert data to `usize` and multiply them directly.
    /// The only advantage of this function is that it has no overflow as `Data` is `Vec<bool>`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::Data;
    /// 
    /// let data1 = Data::from_usize(6);
    /// let data2 = Data::from_usize(7);
    /// 
    /// // let data3 = data1.mul_as_uint(&data2);
    /// 
    /// // assert_eq!(data3.to_usize(), 42);
    /// ```
    pub fn mul_as_uint(&self, _other: &Self) -> Self {
        unimplemented!("This function is not implemented yet");
        // let mut result = Data { x: vec![false] }; // Initialize result with zero
        // for (i, &digit) in other.x.iter().enumerate() {
        //     if digit {
        //         let temp = self.clone_shifted(i);
        //         result = result.add_as_uint(&temp);
        //     }
        // }
        // result
    }
}

impl EncryptedData {
    fn decrypt_bit(poly: &polynomial::Polynomial, sk: &SecretKey) -> bool {
        let remainder = poly.rem(&sk.s);
        remainder.evaluate(false)
    }

    /// Decrypts the data.
    /// 
    /// # Arguments
    /// 
    /// * `context` - The context.
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
    /// Adds two `EncryptedData` instances, assuming they represent unsigned integers.
    /// 
    /// # Arguments
    /// 
    /// * `other` - The other `EncryptedData` instance.
    /// 
    /// # Returns
    /// 
    /// The sum of the two `EncryptedData` instances.
    /// 
    /// # Safety
    /// 
    /// Factor `d`/`delta` must be at least `2*(self.len() + other.len())`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Data, Context, Parameters};
    /// 
    /// let params = Parameters::new(128, 3, 4, 5);
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
    /// let encrypted_data3 = unsafe { encrypted_data1.add_as_uint(&encrypted_data2) };
    /// ```
    pub unsafe fn add_as_uint(&self, other: &Self) -> Self {
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
            carry <- p1.bit_xor(&p2).bit_and(&carry).bit_or(&p1.bit_and(&p2));
            c <- (p1+p2)*c + p2*p2 + p1*p2*(p1+p2)*c
            c <- c*(p1+p2)*(1+p1*p2) + p1*p2 */
            let p1p2 = p1.mul_fn(&p2);
            carry = unsafe { p1.add_fn(&p2).mul_fn(&carry).mul_fn(&Polynomial::new_unchecked(vec![true], 0).add_fn(&p1p2)).add_fn(&p1p2) };

            result.push(s);
        }
        EncryptedData { p: result }
    }

    // fn clone_shifted(&self, n: usize) -> Vec<Polynomial> {
    //     let mut new = vec![Polynomial::null(); n];
    //     for digit in self.p.iter() {
    //         new.push(digit.clone());
    //     }
    //     new
    // }

    /// Multiplies two `EncryptedData` instances, assuming they represent unsigned integers.
    /// 
    /// # Arguments
    /// 
    /// * `other` - The other `EncryptedData` instance.
    /// 
    /// # Returns
    /// 
    /// The product of the two `EncryptedData` instances.
    /// 
    /// # Safety
    /// 
    /// Factor `d`/`delta` must be at least `2*(self.len() + other.len())`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Data, Context, Parameters};
    /// 
    /// let params = Parameters::new(64, 32, 2, 16);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// context.generate_public_key();
    /// 
    /// let data1 = Data::from_usize(6);
    /// let data2 = Data::from_usize(7);
    /// 
    /// let encrypted_data1 = data1.encrypt(&context);
    /// let encrypted_data2 = data2.encrypt(&context);
    /// 
    /// // let encrypted_data3 = unsafe { encrypted_data1.mul_as_uint(&encrypted_data2) };
    /// ```
    pub unsafe fn mul_as_uint(&self, other: &Self) -> Self {
        let max_index = self.p.len() + other.p.len() - 1;
        let mut result: Vec<Polynomial> = vec![Polynomial::null(); max_index];
        let mut carry = vec![Polynomial::null(); max_index];
        let mut last_carry = vec![Polynomial::null(); max_index];
    
        for i in 0..max_index {
            let mut sum_i = Polynomial::null();
            let mut carry_i = carry[i].clone();
            for j in 0..self.p.len().min(i + 1) {
                if i - j < other.p.len() {
                    let p1 = &self.p[j];
                    let p2 = &other.p[i - j];
                    let s = p1.mul_fn(&p2);
                    sum_i = sum_i.add_fn(&s);
                    let last_carry_i = carry_i.clone();
                    carry_i = s.bit_xor(&carry_i);
                    if i + 1 < carry.len() {
                        last_carry[i + 1] = carry[i + 1].clone();
                        carry[i + 1] =
                            last_carry_i.bit_xor(&carry_i).bit_and(&last_carry_i).bit_xor(&carry[i + 1]);
                    }
                } else {
                    break;
                }
            }
            if i < result.len() {
                result[i] = sum_i.add_fn(&carry[i]);
            }
        }
    
        EncryptedData { p: result }
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

        let data = Data::from_usize(usize::MAX);
        assert_eq!(data.to_usize(), usize::MAX);
    }

    #[test]
    fn test_data_add() {
        let data1 = Data::new(vec![true, false, true]);
        let data2 = Data::new(vec![false, true, false]);
        let data3 = data1.add_as_uint(&data2);
        assert_eq!(data3.to_usize(), 7);
    }

    #[test]
    #[should_panic]
    fn test_data_mul() {
        let data1 = Data::new(vec![true, false, true]);
        let data2 = Data::new(vec![false, true, false]);
        let data3 = data1.mul_as_uint(&data2);
        assert_eq!(10, data3.to_usize());

        let data1 = Data::from_usize(999);
        let data2 = Data::from_usize(999);
        let data3 = data1.mul_as_uint(&data2);
        assert_eq!(999*999, data3.to_usize());
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
        let params = Parameters::new(128, 8, 1, 8);
        let mut context = Context::new(params);
        context.generate_secret_key();
        context.generate_public_key();

        let data1 = Data::from_usize(12);
        let data2 = Data::from_usize(30);
        let encrypted_data1 = data1.encrypt(&context);
        let encrypted_data2 = data2.encrypt(&context);
        let encrypted_data3 = unsafe { encrypted_data1.add_as_uint(&encrypted_data2) };
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
            let encrypted_data3 = unsafe { encrypted_data1.add_as_uint(&encrypted_data2) };
            let decrypted_data = encrypted_data3.decrypt(&context);
            let data3 = data1.add_as_uint(&data2);
            assert_eq!(data3.to_usize(), decrypted_data.to_usize());
        }
    }

    #[test]
    #[should_panic]
    fn test_encrypted_data_mul() {
        let params = Parameters::new(128, 8, 1, 8);
        let mut context = Context::new(params);
        context.generate_secret_key();
        context.generate_public_key();

        let data1 = Data::from_u32(6);
        let data2 = Data::from_u32(7);
        let encrypted_data1 = data1.encrypt(&context);
        let encrypted_data2 = data2.encrypt(&context);
        let encrypted_data3 = unsafe { encrypted_data1.mul_as_uint(&encrypted_data2) };
        let decrypted_data = encrypted_data3.decrypt(&context);
        let data3 = data1.mul_as_uint(&data2);
        assert_eq!(data3.to_u32(), decrypted_data.to_u32());

        let data1 = Data::from_usize(999);
        let data2 = Data::from_usize(999);
        let encrypted_data1 = data1.encrypt(&context);
        let encrypted_data2 = data2.encrypt(&context);
        let encrypted_data3 = unsafe { encrypted_data1.mul_as_uint(&encrypted_data2) };
        let decrypted_data = encrypted_data3.decrypt(&context);
        let data3 = data1.mul_as_uint(&data2);
        assert_eq!(data3.to_usize(), decrypted_data.to_usize());
    }

    #[test]
    #[should_panic]
    #[ignore = "Longer version of test_encrypted_data_mul"]
    fn test_encrypted_data_mul_extensive() {
        const N: usize = 100;
        let params = Parameters::new(128, 64, 4, 32);
        let mut context = Context::new(params);

        let mut rng = rand::thread_rng();
        for _ in 0..N {
            context.generate_secret_key();
            context.generate_public_key();

            let data1 = Data::from_usize(rng.gen());
            let data2 = Data::from_usize(rng.gen());
            let encrypted_data1 = data1.encrypt(&context);
            let encrypted_data2 = data2.encrypt(&context);
            let encrypted_data3 = unsafe { encrypted_data1.mul_as_uint(&encrypted_data2) };
            let decrypted_data = encrypted_data3.decrypt(&context);
            let data3 = data1.mul_as_uint(&data2);
            assert_eq!(data3.to_usize(), decrypted_data.to_usize());
        }
    }

    #[test]
    fn test_get_bytes() {
        let params = Parameters::new(64, 64, 32, 64);
        let mut context = Context::new(params);
        context.generate_secret_key();
        context.generate_public_key();

        let secret_key = context.get_secret_key().unwrap();
        let public_key = context.get_public_key().unwrap();

        let secret_key_bytes = secret_key.get_bytes();
        let public_key_bytes = public_key.get_bytes();

        let secret_key2 = SecretKey::new(secret_key_bytes);
        let public_key2 = PublicKey::new(public_key_bytes);

        assert_eq!(secret_key.get_bytes(), secret_key2.get_bytes());
        assert_eq!(public_key.get_bytes(), public_key2.get_bytes());
    }
}
