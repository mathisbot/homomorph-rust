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
//! The library is highly parallelized, using the `rayon` crate.
//! 
//! # Examples
//! 
//! ```
//! use homomorph::{Context, Data, Parameters};
//! use rand::thread_rng;
//! 
//! // Define the parameters
//! // -------------------------- d, dp, delta, tau
//! let params = Parameters::new(256, 256, 128, 256);
//! 
//! // Create a new context
//! let mut context = Context::new(params);
//! // Initialize keys
//! context.generate_secret_key(&mut thread_rng());
//! // Notice that the public key is generated after the secret key
//! context.generate_public_key(&mut thread_rng());
//! 
//! // Create data from a usize
//! let data = Data::from_usize(42);
//! // Encrypt the data using the public key
//! let encrypted_data = data.encrypt(&context.get_public_key().unwrap(), &mut thread_rng());
//! // Decrypt the data using the secret key
//! let decrypted_data = encrypted_data.decrypt(&context.get_secret_key().unwrap());
//! ```

use rayon::prelude::*;
use std::mem;
use std::ops::{Add, Mul};

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
    /// # Panics
    /// 
    /// This function will panic if `delta` is greater than or equal to `d`.
    /// 
    /// # Complexity
    /// 
    /// O(1).
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
/// use homomorph::SecretKey;
/// use rand::thread_rng;
/// 
/// let s = SecretKey::random(5, &mut thread_rng());
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
    /// For security reseasons, the polynomial should only be retrieved from a previous generated secret key.
    /// For a first time generation, use `SecretKey::random`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::SecretKey;
    /// use homomorph::polynomial::Polynomial;
    /// 
    /// let s = Polynomial::new(vec![true, false, true]);
    /// 
    /// let sk = SecretKey::new(s);
    /// ```
    pub fn new(s: polynomial::Polynomial) -> Self {
        SecretKey { s }
    }

    /// Creates a new random secret key.
    /// 
    /// # Arguments
    /// 
    /// * `d` - The degree of the secret key.
    /// * `rng` - A random number generator.
    /// 
    /// # Returns
    /// 
    /// A new secret key.
    /// 
    /// # Complexity
    /// 
    /// O(n) where n is the degree of the secret key.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::SecretKey;
    /// use rand::thread_rng;
    /// 
    /// let s = SecretKey::random(5, &mut thread_rng());
    /// ```
    pub fn random(d: usize, rng: &mut impl rand::Rng) -> Self {
        let s = polynomial::Polynomial::random(d, rng);
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
    /// use homomorph::SecretKey;
    /// use rand::thread_rng;
    /// 
    /// let s = SecretKey::random(5, &mut thread_rng());
    /// let s_ref = s.as_ref();
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
/// use homomorph::{PublicKey, SecretKey};
/// use rand::thread_rng;
/// 
/// let secret_key = SecretKey::random(5, &mut thread_rng());
/// let pk = PublicKey::random(3, 2, 5, &secret_key, &mut thread_rng());
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
    /// For a first time generation, use `PublicKey::random`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::PublicKey;
    /// use homomorph::polynomial::Polynomial;
    /// 
    /// let p = Polynomial::new(vec![true, false, true]);
    /// 
    /// let pk = PublicKey::new(vec![p]);
    /// ```
    pub fn new(v: Vec<polynomial::Polynomial>) -> Self {
        PublicKey { list: v }
    }

    /// Creates a new random public key.
    /// 
    /// # Arguments
    /// 
    /// * `secret_key` - The secret key.
    /// 
    /// # Returns
    /// 
    /// A new public key.
    /// 
    /// # Complexity
    /// 
    /// O(n) where n is the size of the public key.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{PublicKey, SecretKey};
    /// use rand::thread_rng;
    /// 
    /// let secret_key = SecretKey::random(5, &mut thread_rng());
    /// let pk = PublicKey::random(3, 2, 5, &secret_key, &mut thread_rng());
    /// ```
    pub fn random(dp: usize, delta: usize, tau: usize, secret_key: &SecretKey, rng: &mut impl rand::Rng) -> Self {
        let mut list = Vec::with_capacity(tau);
        for _ in 0..tau {
            let q = polynomial::Polynomial::random(dp, rng);
            let sq = secret_key.s.clone()*q;
            let r = polynomial::Polynomial::random(delta, rng);
            unsafe {
                let rx = r * (Polynomial::new_unchecked(vec![false, true], 1));
                let ti = sq + rx;
                list.push(ti);
            }
        }
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
    /// use homomorph::{PublicKey, SecretKey};
    /// use rand::thread_rng;
    /// 
    /// let secret_key = SecretKey::random(5, &mut thread_rng());
    /// let pk = PublicKey::random(3, 2, 5, &secret_key, &mut thread_rng());
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
    /// use rand::thread_rng;
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key(&mut thread_rng());
    /// ```
    pub fn generate_secret_key(&mut self, rng: &mut impl rand::Rng) {
        self.secret_key = Some(SecretKey::random(self.parameters.d, rng));
    }

    /// Generates a public key out of the private key.
    /// 
    /// # Arguments
    /// 
    /// * `rng` - A random number generator.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::{Context, Parameters};
    /// use rand::thread_rng;
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key(&mut thread_rng());
    /// context.generate_public_key(&mut thread_rng());
    /// ```
    /// 
    /// # Panics
    /// 
    /// This function will panic if the secret key has not been generated yet.
    pub fn generate_public_key(&mut self, rng: &mut impl rand::Rng) {
        if let Some(secret_key) = &self.secret_key {
            self.public_key = Some(PublicKey::random(self.parameters.dp, self.parameters.delta, self.parameters.tau, secret_key, rng));
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
    /// use rand::thread_rng;
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key(&mut thread_rng());
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
    /// use rand::thread_rng;
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key(&mut thread_rng());
    /// context.generate_public_key(&mut thread_rng());
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
    /// use rand::thread_rng;
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// let secret_key = SecretKey::random(5, &mut thread_rng());
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
    /// use homomorph::{Context, Parameters, PublicKey, SecretKey};
    /// use rand::thread_rng;
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// let secret_key = SecretKey::random(5, &mut thread_rng());
    /// let public_key = PublicKey::random(3, 2, 5, &secret_key, &mut thread_rng());
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
pub struct Data {
    x: Vec<bool>,
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
/// use rand::thread_rng;
/// 
/// let params = Parameters::new(6, 3, 2, 5);
/// let mut context = Context::new(params);
/// context.generate_secret_key(&mut thread_rng());
/// context.generate_public_key(&mut thread_rng());
/// 
/// let data = Data::new(vec![true, false, true]);
/// let encrypted_data = data.encrypt(&context.get_public_key().unwrap(), &mut thread_rng());
/// ```
pub struct EncryptedData {
    p: Vec<polynomial::Polynomial>,
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
    /// let data = Data::from_usize(42);
    /// ```
    pub fn from_usize(x: usize) -> Self {
        let mut result = Vec::with_capacity(mem::size_of::<usize>());
        for i in 0..mem::size_of::<usize>() {
            result.push((x >> i) & 1 == 1);
        }
        Data { x: result }
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
    /// context.generate_secret_key(&mut thread_rng());
    /// context.generate_public_key(&mut thread_rng());
    /// 
    /// let data = Data::new(vec![true, false, true]);
    /// let encrypted_data = data.encrypt(&context.get_public_key().unwrap(), &mut thread_rng());
    /// ```
    /// 
    /// # Note
    /// 
    /// This function is highly parallelized.
    /// Parameter `_rng` is unused for now.
    pub fn encrypt(&self, pk: &PublicKey, _rng: &mut impl rand::Rng) -> EncryptedData {
        let result: Vec<_> = self.x.par_iter()
            .map(|&bit| {
                // TODO: Use rng in parameter
                let mut local_rng = rand::thread_rng();
                Data::encrypt_bit(bit, pk, &mut local_rng)
            })
            .collect();
    
        EncryptedData { p: result }
    }
}

/// As the crate currently assumes `Data` is a `usize`, we can add two `Data` instances.
impl Add for Data {
    type Output = Self;

    fn add(self, other: Self) -> Self {
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
}

impl Mul for Data {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let longest = self.x.len().max(other.x.len());
        let mut result = Vec::with_capacity(longest);
        let mut carry = false;
        for i in 0..longest {
            let d1 = self.x.get(i).unwrap_or(&false);
            let d2 = other.x.get(i).unwrap_or(&false);
            let s = d1 & d2 ^ carry;
            carry = (d1 & d2) | (d1 & carry) | (d2 & carry);
            result.push(s);
        }
        Data { x: result }
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
    /// use rand::thread_rng;
    /// 
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key(&mut thread_rng());
    /// context.generate_public_key(&mut thread_rng());
    /// 
    /// let data = Data::new(vec![true, false, true]);
    /// let encrypted_data = data.encrypt(&context.get_public_key().unwrap(), &mut thread_rng());
    /// 
    /// let decrypted_data = encrypted_data.decrypt(&context.get_secret_key().unwrap());
    /// ```
    /// 
    /// # Note
    /// 
    /// This function is highly parallelized.
    pub fn decrypt(&self, sk: &SecretKey) -> Data {
        let result: Vec<_> = self.p.par_iter()
            .map(|poly| {
                EncryptedData::decrypt_bit(poly, sk)
            })
            .collect();
        Data { x: result }
    }
}

/// Take advantage of the properties of the system to add two `EncryptedData` instances.
/// 
/// # Notes
/// 
/// Factor `d`/`delta` must be at least 20. 32 is a good value.
// TODO: Use a better method to ensure the factor is at least 20.
impl Add for EncryptedData {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let longest = self.p.len().max(other.p.len());
        let mut result = Vec::with_capacity(longest);
        let mut carry = Polynomial::null();
        // Avoid borrowing issues
        let null_p = Polynomial::null();
        for i in 0..longest {
            let p1 = self.p.get(i).unwrap_or(&null_p);
            let p2 = other.p.get(i).unwrap_or(&null_p);
            let s = p1.bit_xor(&p2).bit_xor(&carry);
            carry = p1.bit_xor(&p2).bit_and(&carry).bit_or(&p1.bit_and(&p2));
            result.push(s);
        }
        EncryptedData { p: result }
    }
}

impl Mul for EncryptedData {
    type Output = Self;

    fn mul(self, _other: Self) -> Self {
        unimplemented!("Multiplication is not yet implemented");
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
        let data3 = data1 + data2;
        assert_eq!(data3.to_usize(), 7);
    }

    #[test]
    fn test_encrypted_data() {
        let params = Parameters::new(16, 8, 4, 8);
        let mut context = Context::new(params);
        context.generate_secret_key(&mut rand::thread_rng());
        context.generate_public_key(&mut rand::thread_rng());

        let data = Data::new(vec![true, false, true]);
        let encrypted_data = data.encrypt(context.get_public_key().unwrap(), &mut rand::thread_rng());
        let decrypted_data = encrypted_data.decrypt(context.get_secret_key().unwrap());
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
            context.generate_secret_key(&mut rng);
            context.generate_public_key(&mut rng);

            let data = Data::from_usize(rng.gen());
            let encrypted_data = data.encrypt(context.get_public_key().unwrap(), &mut rng);
            let decrypted_data = encrypted_data.decrypt(context.get_secret_key().unwrap());
            assert_eq!(data.to_usize(), decrypted_data.to_usize());
        }
    }

    #[test]
    fn test_encrypted_data_add() {
        let params = Parameters::new(128, 32, 4, 16);
        let mut context = Context::new(params);
        context.generate_secret_key(&mut rand::thread_rng());
        context.generate_public_key(&mut rand::thread_rng());

        let data1 = Data::from_usize(12);
        let data2 = Data::from_usize(30);
        let encrypted_data1 = data1.encrypt(context.get_public_key().unwrap(), &mut rand::thread_rng());
        let encrypted_data2 = data2.encrypt(context.get_public_key().unwrap(), &mut rand::thread_rng());
        let encrypted_data3 = encrypted_data1 + encrypted_data2;
        let decrypted_data = encrypted_data3.decrypt(context.get_secret_key().unwrap());
        let data3 = data1 + data2;
        assert_eq!(data3.to_usize(), decrypted_data.to_usize());
    }

    #[test]
    #[ignore = "Longer version of test_encrypted_data_add"]
    fn test_encrypted_data_add_extensive() {
        const N: usize = 256;
        let params = Parameters::new(256, 64, 4, 32);
        let mut context = Context::new(params);

        let mut rng = rand::thread_rng();
        for _ in 0..N {
            context.generate_secret_key(&mut rand::thread_rng());
            context.generate_public_key(&mut rand::thread_rng());

            let data1 = Data::from_usize(rng.gen());
            let data2 = Data::from_usize(rng.gen());
            let encrypted_data1 = data1.encrypt(context.get_public_key().unwrap(), &mut rand::thread_rng());
            let encrypted_data2 = data2.encrypt(context.get_public_key().unwrap(), &mut rand::thread_rng());
            let encrypted_data3 = encrypted_data1 + encrypted_data2;
            let decrypted_data = encrypted_data3.decrypt(context.get_secret_key().unwrap());
            let data3 = data1 + data2;
            assert_eq!(data3.to_usize(), decrypted_data.to_usize());
        }
    }

    #[test]
    #[should_panic] // Multiplication is not yet implemented
    fn test_encrypted_data_mul() {
        let params = Parameters::new(128, 64, 8, 32);
        let mut context = Context::new(params);
        context.generate_secret_key(&mut rand::thread_rng());
        context.generate_public_key(&mut rand::thread_rng());

        let data1 = Data::from_usize(12);
        let data2 = Data::from_usize(30);
        let encrypted_data1 = data1.encrypt(context.get_public_key().unwrap(), &mut rand::thread_rng());
        let encrypted_data2 = data2.encrypt(context.get_public_key().unwrap(), &mut rand::thread_rng());
        let encrypted_data3 = encrypted_data1 * encrypted_data2;
        let decrypted_data = encrypted_data3.decrypt(context.get_secret_key().unwrap());
        let data3 = data1 * data2;
        assert_eq!(data3.to_usize(), decrypted_data.to_usize());
    }

    #[test]
    #[ignore = "Longer version of test_encrypted_data_mul"]
    #[should_panic] // Multiplication is not yet implemented
    fn test_encrypted_data_mul_extensive() {
        const N: usize = 256;
        let params = Parameters::new(256, 64, 4, 32);
        let mut context = Context::new(params);

        let mut rng = rand::thread_rng();
        for _ in 0..N {
            context.generate_secret_key(&mut rand::thread_rng());
            context.generate_public_key(&mut rand::thread_rng());

            let data1 = Data::from_usize(rng.gen());
            let data2 = Data::from_usize(rng.gen());
            let encrypted_data1 = data1.encrypt(context.get_public_key().unwrap(), &mut rand::thread_rng());
            let encrypted_data2 = data2.encrypt(context.get_public_key().unwrap(), &mut rand::thread_rng());
            let encrypted_data3 = encrypted_data1 * encrypted_data2;
            let decrypted_data = encrypted_data3.decrypt(context.get_secret_key().unwrap());
            let data3 = data1 * data2;
            assert_eq!(data3.to_usize(), decrypted_data.to_usize());
        }
    }
}
