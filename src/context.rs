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
}

/// The secret key.
#[derive(Clone, Debug, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey {
    s: Polynomial,
}

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
        Self {
            s: Polynomial::new(coeffs),
        }
    }

    #[must_use]
    /// Generates a random secret key of the given degree
    pub(self) fn random(d: u16) -> Self {
        Self {
            s: Polynomial::random(d as usize),
        }
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
        for x in self.s.coefficients() {
            bytes.extend_from_slice(x.to_le_bytes().as_ref());
        }
        bytes
    }

    pub(crate) const fn get_polynomial(&self) -> &Polynomial {
        &self.s
    }
}

/// The public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    list: Vec<Polynomial>,
}

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
        Self { list }
    }

    #[must_use]
    /// Generates a random public key
    pub(self) fn random(dp: u16, delta: u16, tau: u16, secret_key: &SecretKey) -> Self {
        let list: Vec<_> = (0..tau)
            .map(|_| {
                let q = Polynomial::random(dp as usize);
                let sq = secret_key.s.clone().mul(&q);
                let r = Polynomial::random(delta as usize);
                let rx = r.mul(&Polynomial::monomial(1));
                sq.add(&rx)
            })
            .collect();

        Self { list }
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
        let mut bytes_outer: Vec<Vec<u8>> = Vec::with_capacity(self.list.len());
        for pol in &self.list {
            let mut bytes: Vec<u8> = Vec::with_capacity((pol.coefficients().len() - 1) * 16);
            for x in pol.coefficients() {
                bytes.extend_from_slice(x.to_le_bytes().as_ref());
            }
            bytes_outer.push(bytes);
        }
        bytes_outer
    }

    pub(crate) const fn get_polynomials(&self) -> &Vec<Polynomial> {
        &self.list
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
        self.secret_key = Some(SecretKey::random(self.parameters.d));
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
        if let Some(secret_key) = &self.secret_key {
            self.public_key = Some(PublicKey::random(
                self.parameters.dp,
                self.parameters.delta,
                self.parameters.tau,
                secret_key,
            ));
        } else {
            panic!("Secret key not generated yet");
        }
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
    fn test_secret_key() {
        let s = vec![5, 14, 8];
        let sk = SecretKey::new(&s);

        let bytes = sk.get_bytes();
        let sk2 = SecretKey::new(&bytes);

        assert_eq!(sk, sk2);
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
