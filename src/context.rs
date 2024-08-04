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
pub struct Parameters {
    d: u16,
    dp: u16,
    delta: u16,
    tau: u16,
}

impl Parameters {
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
        if delta >= d {
            panic!("Delta must be strictly less than d");
        }
        if d == 0 || dp == 0 || delta == 0 || tau == 0 {
            panic!("Parameters must be strictly positive");
        }
        Parameters { d, dp, delta, tau }
    }
}

/// The secret key.
#[derive(Clone, Debug, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey {
    s: Polynomial,
}

impl SecretKey {
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
    /// let sk = SecretKey::new(s);
    /// ```
    pub fn new(bytes: Vec<u8>) -> Self {
        let mut coeffs: Vec<_> = Vec::with_capacity(bytes.len() / 16 + 1);
        let mut n = 0;
        for (i, byte) in bytes.iter().enumerate() {
            n |= (*byte as crate::polynomial::Coefficient) << (i % 8 * 8);
            if i % 8 == 7 {
                coeffs.push(n);
                n = 0;
            }
        }
        if n != 0 {
            coeffs.push(n);
        }
        SecretKey {
            s: Polynomial::new(coeffs),
        }
    }

    pub(self) fn random(d: u16) -> Self {
        SecretKey {
            s: Polynomial::random(d as usize),
        }
    }

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
            for i in 0..8 {
                bytes.push((x >> (i * 8)) as u8);
            }
        }
        bytes
    }

    pub(crate) fn get_polynomial(&self) -> &Polynomial {
        &self.s
    }
}

/// The public key.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    list: Vec<Polynomial>,
}

impl PublicKey {
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
    /// let pk = PublicKey::new(p);
    /// ```
    pub fn new(bytes: Vec<Vec<u8>>) -> Self {
        let mut list: Vec<Polynomial> = Vec::with_capacity(bytes.capacity());
        for bytes in bytes.iter() {
            let mut coeffs: Vec<_> = Vec::with_capacity(bytes.len() / 16 + 1);
            let mut n = 0;
            for (i, byte) in bytes.iter().enumerate() {
                n |= (*byte as crate::polynomial::Coefficient) << (i % 8 * 8);
                if i % 8 == 7 {
                    coeffs.push(n);
                    n = 0;
                }
            }
            if n != 0 {
                coeffs.push(n);
            }
            let p = Polynomial::new(coeffs);
            list.push(p);
        }
        PublicKey { list }
    }

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

        PublicKey { list }
    }

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
        for pol in self.list.iter() {
            let mut bytes: Vec<u8> = Vec::with_capacity((pol.coefficients().len() - 1) * 16);
            for x in pol.coefficients() {
                for i in 0..8 {
                    bytes.push((x >> (i * 8)) as u8);
                }
            }
            bytes_outer.push(bytes);
        }
        bytes_outer
    }

    pub(crate) fn get_polynomials(&self) -> &Vec<Polynomial> {
        &self.list
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
    pub fn new(params: Parameters) -> Self {
        Context {
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
    pub fn get_secret_key(&self) -> Option<&SecretKey> {
        self.secret_key.as_ref()
    }

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
    pub fn get_public_key(&self) -> Option<&PublicKey> {
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
    /// let sk = SecretKey::new(s);
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
    /// let pk = PublicKey::new(p);
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
    fn test_parameters() {
        let params = Parameters::new(64, 32, 8, 32);
        assert_eq!(params.d, 64);
        assert_eq!(params.dp, 32);
        assert_eq!(params.delta, 8);
        assert_eq!(params.tau, 32);
    }

    #[test]
    #[should_panic]
    fn test_panic_parameters() {
        let _ = Parameters::new(0, 0, 0, 0);
    }

    #[test]
    fn test_secret_key() {
        let s = vec![5, 14, 8];
        let sk = SecretKey::new(s);

        let bytes = sk.get_bytes();
        let sk2 = SecretKey::new(bytes);

        assert_eq!(sk.s, sk2.s);
    }

    #[test]
    fn test_public_key() {
        let p = vec![vec![4, 7, 5], vec![1, 2, 3], vec![5, 4, 6]];
        let pk = PublicKey::new(p);

        let bytes = pk.get_bytes();
        let pk2 = PublicKey::new(bytes);

        assert_eq!(pk.list, pk2.list);
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
}
