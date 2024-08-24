use crate::polynomial::Polynomial;

use alloc::vec::Vec;

/// Parameters for the algorithm.
///
/// ## Fields
///
/// * `d` - The degree of the secret key.
/// * `dp` - Such that `d+dp` is the degree of the public key.
/// * `delta` - The noise parameter.
/// * `tau` - The size of public key.
///
/// ## Examples
///
/// ```
/// use homomorph::Parameters;
///
/// let parameters = Parameters::new(6, 3, 2, 5);
/// ```
///
/// ## Note
///
/// `delta` is strictly less than `d`.
///
/// For more information, visit <https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#system>.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    d: u16,
    dp: u16,
    delta: u16,
    tau: u16,
}

impl Parameters {
    #[must_use]
    /// Creates a new set of parameters.
    ///
    /// ## Arguments
    ///
    /// * `d` - The degree of the secret key.
    /// * `dp` - Such that `d+dp` is the degree of the public key.
    /// * `delta` - The noise parameter.
    /// * `tau` - The size of the public key.
    ///
    /// ## Returns
    ///
    /// A new set of parameters.
    ///
    /// ## Note
    ///
    /// As the system properties highly depends on the quantity `d`/`delta`, it is advised
    /// to take a look at recommandations in the documentation of the functions you are
    /// planning to use.
    ///
    /// ## Panics
    ///
    /// This function will panic if `delta` is greater than or equal to `d`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use homomorph::Parameters;
    ///
    /// let parameters = Parameters::new(6, 3, 2, 5);
    /// ```
    pub fn new(d: u16, dp: u16, delta: u16, tau: u16) -> Self {
        assert!(delta < d, "Delta must be strictly less than d");
        assert!(
            !(d == 0 || dp == 0 || delta == 0 || tau == 0),
            "Parameters must be strictly positive"
        );
        Self { d, dp, delta, tau }
    }

    #[must_use]
    pub const fn d(&self) -> u16 {
        self.d
    }

    #[must_use]
    pub const fn dp(&self) -> u16 {
        self.dp
    }

    #[must_use]
    pub const fn delta(&self) -> u16 {
        self.delta
    }

    #[must_use]
    pub const fn tau(&self) -> u16 {
        self.tau
    }
}

/// The secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey(Polynomial);

impl SecretKey {
    #[must_use]
    /// Creates a new secret key.
    ///
    /// ## Arguments
    ///
    /// * `bytes` - The bytes representing the secret key.
    ///
    /// ## Returns
    ///
    /// A new secret key.
    ///
    /// ## Note
    ///
    /// For security reasons, the polynomial should only be retrieved from a previous generated secret key.
    /// For a first time generation, use `Context::generate_secret_key`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use homomorph::SecretKey;
    ///
    /// // INSECURE!!! Only for demonstration purposes
    /// let s = vec![5, 14, 8];
    ///
    /// let sk = SecretKey::new(&s);
    /// ```
    pub fn new(bytes: &[u8]) -> Self {
        let mut coeffs: Vec<_> =
            Vec::with_capacity(bytes.len() / size_of::<crate::polynomial::Coefficient>());
        for chunk in bytes.chunks(size_of::<crate::polynomial::Coefficient>()) {
            let mut array = [0; size_of::<crate::polynomial::Coefficient>()];
            array[..chunk.len()].copy_from_slice(chunk);
            coeffs.push(crate::polynomial::Coefficient::from_le_bytes(array));
        }
        Self(Polynomial::new(coeffs))
    }

    #[must_use]
    /// Generates a random secret key of the given degree
    fn random(d: u16) -> Self {
        Self(Polynomial::random(d as usize))
    }

    pub(crate) const fn get_polynomial(&self) -> &Polynomial {
        &self.0
    }

    #[must_use]
    /// Returns bytes representing the secret key.
    ///
    /// ## Returns
    ///
    /// A `Vec<u8>` representing the secret key.
    ///
    /// ## Note
    ///
    /// Can be useful to save the secret key.
    ///
    /// ## Examples
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
        for x in self.get_polynomial().coefficients() {
            bytes.extend_from_slice(x.to_le_bytes().as_ref());
        }
        bytes
    }
}

/// The secret key is zeroized when dropped
/// because its content should not leak.
impl Drop for SecretKey {
    fn drop(&mut self) {
        // Safety
        // The content will not be used afterwards
        // as we are dropping the secret key.
        unsafe { self.0.zeroize() };
    }
}

/// The public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(Vec<Polynomial>);

impl PublicKey {
    #[must_use]
    /// Creates a new public key.
    ///
    /// ## Arguments
    ///
    /// * `bytes` - The bytes representing the public key.
    ///
    /// ## Returns
    ///
    /// A new public key.
    ///
    /// ## Note
    ///
    /// For security reseasons, the list of polynomials should only be retrieved from a previous generated public key.
    /// For a first time generation, use `Context::generate_public_key`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use homomorph::PublicKey;
    ///
    /// // INSECURE!!! Only for demonstration purposes
    /// let p = vec![vec![4, 7, 5], vec![1, 2, 3], vec![5, 4, 6]];
    ///
    /// let pk = PublicKey::new(&p);
    /// ```
    pub fn new(bytes_vec: &Vec<Vec<u8>>) -> Self {
        let mut list: Vec<Polynomial> = Vec::with_capacity(bytes_vec.capacity());
        for bytes in bytes_vec {
            let mut coeffs: Vec<_> =
                Vec::with_capacity(bytes.len() / size_of::<crate::polynomial::Coefficient>());
            for chunk in bytes.chunks(size_of::<crate::polynomial::Coefficient>()) {
                let mut array = [0; size_of::<crate::polynomial::Coefficient>()];
                array[..chunk.len()].copy_from_slice(chunk);
                coeffs.push(crate::polynomial::Coefficient::from_le_bytes(array));
            }
            let p = Polynomial::new(coeffs);
            list.push(p);
        }
        Self(list)
    }

    #[must_use]
    /// Generates a random public key
    fn random(dp: u16, delta: u16, tau: u16, secret_key: &SecretKey) -> Self {
        let list: Vec<_> = (0..tau)
            .map(|_| {
                let q = Polynomial::random(dp as usize);
                let sq = secret_key.clone().get_polynomial().mul(&q);
                let r = Polynomial::random(delta as usize);
                let rx = r.mul(&Polynomial::monomial(1));
                sq.add(&rx)
            })
            .collect();

        Self(list)
    }

    pub(crate) const fn get_polynomials(&self) -> &Vec<Polynomial> {
        &self.0
    }

    #[must_use]
    /// Returns bytes representing the public key.
    ///
    /// ## Returns
    ///
    /// A `Vec<Vec<u8>>` representing the public key.
    ///
    /// ## Note
    ///
    /// Can be useful to save the public key.
    ///
    /// ## Examples
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
        let mut bytes_outer: Vec<Vec<u8>> = Vec::with_capacity(self.get_polynomials().len());
        for pol in self.get_polynomials() {
            let mut bytes: Vec<u8> = Vec::with_capacity((pol.coefficients().len() - 1) * 16);
            for x in pol.coefficients() {
                bytes.extend_from_slice(x.to_le_bytes().as_ref());
            }
            bytes_outer.push(bytes);
        }
        bytes_outer
    }
}

/// The cipher context.
#[derive(Clone, Debug)]
pub struct Context {
    secret_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    parameters: Parameters,
}

impl Context {
    #[must_use]
    /// Creates a new context.
    ///
    /// ## Arguments
    ///
    /// * `params` - The parameters.
    ///
    /// ## Returns
    ///
    /// A new context.
    ///
    /// ## Examples
    ///
    /// ```
    /// use homomorph::{Context, Parameters};
    ///
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// ```
    pub const fn new(params: Parameters) -> Self {
        Self {
            secret_key: None,
            public_key: None,
            parameters: params,
        }
    }

    #[must_use]
    pub const fn parameters(&self) -> &Parameters {
        &self.parameters
    }

    #[must_use]
    /// Returns a reference to the secret key.
    ///
    /// ## Returns
    ///
    /// A reference to the secret key.
    ///
    /// ## Examples
    ///
    /// ```
    /// use homomorph::{Context, Parameters};
    ///
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// let secret_key = context.get_secret_key().unwrap();
    /// ```
    pub const fn get_secret_key(&self) -> Option<&SecretKey> {
        self.secret_key.as_ref()
    }

    #[must_use]
    /// Returns a reference to the public key.
    ///
    /// ## Returns
    ///
    /// A reference to the public key.
    ///
    /// ## Examples
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
    pub const fn get_public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    /// Generates a secret key.
    ///
    /// ## Examples
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
        self.secret_key = Some(SecretKey::random(self.parameters().d()));
    }

    /// Generates a public key out of the private key.
    ///
    /// ## Panics
    ///
    /// This function will panic if the secret key has not been generated yet.
    ///
    /// ## Examples
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
        self.public_key = Some(PublicKey::random(
            self.parameters().dp(),
            self.parameters().delta(),
            self.parameters().tau(),
            self.get_secret_key().expect("Secret key not generated yet"),
        ));
    }

    /// Explicitly sets the secret key.
    ///
    /// ## Arguments
    ///
    /// * `secret_key` - The secret key.
    ///
    /// ## Examples
    ///
    /// ```
    /// use homomorph::{Context, Parameters, SecretKey};
    ///
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    ///
    /// // INSECURE!!! Only for demonstration purposes
    /// let s = vec![5, 14, 8];
    /// let sk = SecretKey::new(&s);
    ///
    /// context.set_secret_key(sk);
    /// ```
    pub fn set_secret_key(&mut self, secret_key: SecretKey) {
        self.secret_key = Some(secret_key);
    }

    /// Explicitly sets the public key.
    ///
    /// ## Arguments
    ///
    /// * `public_key` - The public key.
    ///
    /// ## Examples
    ///
    /// ```
    /// use homomorph::{Context, Parameters, PublicKey};
    ///
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    ///
    /// // INSECURE!!! Only for demonstration purposes
    /// let p = vec![vec![4, 7, 5], vec![1, 2, 3], vec![5, 4, 6]];
    /// let pk = PublicKey::new(&p);
    ///
    /// context.set_public_key(pk);
    /// ```
    pub fn set_public_key(&mut self, public_key: PublicKey) {
        self.public_key = Some(public_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic = "Delta must be strictly less than d"]
    fn test_parameters_delta_panic() {
        let _ = Parameters::new(6, 3, 6, 5);
    }

    #[test]
    #[should_panic = "Parameters must be strictly positive"]
    fn test_parameters_null_panic() {
        let _ = Parameters::new(6, 0, 2, 5);
    }

    #[test]
    fn test_secret_key() {
        let s = vec![5, 14, 8];
        let sk = SecretKey::new(&s);

        let bytes = sk.get_bytes();
        let sk2 = SecretKey::new(&bytes);

        assert_eq!(sk, sk2);
    }

    #[test]
    fn test_secret_key_zeroized_on_drop() {
        let s = vec![5, 14, 8];
        let sk = SecretKey::new(&s);

        let p = sk.get_polynomial().clone();
        let ptr = core::ptr::from_ref(sk.get_polynomial());

        drop(sk);

        // EXTREMELY UNSAFE
        let p_retrieved = unsafe { &*ptr };

        assert_ne!(p, *p_retrieved);
    }

    #[test]
    fn test_public_key() {
        let p = vec![vec![4, 7, 5], vec![1, 2, 3], vec![5, 4, 6]];
        let pk = PublicKey::new(&p);

        let bytes = pk.get_bytes();
        let pk2 = PublicKey::new(&bytes);

        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_context() {
        let params = Parameters::new(64, 32, 8, 32);
        let mut context = Context::new(params);
        context.generate_secret_key();
        context.generate_public_key();
        let sk = context.get_secret_key().unwrap().clone();
        context.set_secret_key(sk.clone());
        let pk = context.get_public_key().unwrap().clone();
        context.set_public_key(pk.clone());

        let sk2 = context.get_secret_key().unwrap().clone();
        let pk2 = context.get_public_key().unwrap().clone();

        assert_eq!(sk, sk2);
        assert_eq!(pk, pk2);
    }

    #[test]
    #[should_panic = "Secret key not generated yet"]
    fn test_context_panic() {
        let params = Parameters::new(64, 32, 8, 32);
        let mut context = Context::new(params);
        context.generate_public_key();
    }
}
