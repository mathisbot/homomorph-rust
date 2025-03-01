use crate::polynomial::Polynomial;

use alloc::boxed::Box;
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
/// # use homomorph::Parameters;
/// #
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SecretKeyUnset;

impl Parameters {
    #[must_use]
    #[inline]
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
    /// # use homomorph::Parameters;
    /// #
    /// let parameters = Parameters::new(6, 3, 2, 5);
    /// ```
    pub const fn new(d: u16, dp: u16, delta: u16, tau: u16) -> Self {
        assert!(delta < d, "Delta must be strictly less than d");
        assert!(
            !(d == 0 || dp == 0 || delta == 0 || tau == 0),
            "Parameters must be strictly positive"
        );
        Self { d, dp, delta, tau }
    }

    #[must_use]
    #[inline]
    pub const fn d(&self) -> u16 {
        self.d
    }

    #[must_use]
    #[inline]
    pub const fn dp(&self) -> u16 {
        self.dp
    }

    #[must_use]
    #[inline]
    pub const fn delta(&self) -> u16 {
        self.delta
    }

    #[must_use]
    #[inline]
    pub const fn tau(&self) -> u16 {
        self.tau
    }
}

/// The secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey(Polynomial);

impl SecretKey {
    #[must_use]
    #[inline]
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
    /// # use homomorph::SecretKey;
    /// #
    /// // INSECURE!!! Only for demonstration purposes
    /// let s = vec![5, 14, 8];
    ///
    /// let sk = SecretKey::from_bytes(&s);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Polynomial::from_bytes(bytes))
    }

    #[must_use]
    #[inline]
    /// Generates a random secret key of the given degree
    fn random(d: u16) -> Self {
        Self(Polynomial::random(d as usize))
    }

    #[must_use]
    #[inline]
    pub(crate) const fn get_polynomial(&self) -> &Polynomial {
        &self.0
    }

    #[must_use]
    #[inline]
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
    /// # use homomorph::{Context, Parameters};
    /// #
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    /// context.generate_secret_key();
    ///
    /// let key_bytes = context.get_secret_key().unwrap().to_bytes();
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        self.get_polynomial().to_bytes()
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
pub struct PublicKey(Box<[Polynomial]>);

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
    /// # use homomorph::PublicKey;
    /// #
    /// // INSECURE!!! Only for demonstration purposes
    /// let p = vec![vec![4, 7, 5], vec![1, 2, 3], vec![5, 4, 6]];
    ///
    /// let pk = PublicKey::from_bytes(&p);
    /// ```
    pub fn from_bytes(bytes_vec: &[Vec<u8>]) -> Self {
        let mut list: Vec<Polynomial> = Vec::with_capacity(bytes_vec.len());
        for bytes in bytes_vec {
            list.push(Polynomial::from_bytes(bytes));
        }
        Self(list.into_boxed_slice())
    }

    #[must_use]
    /// Generates a random public key
    fn random(dp: u16, delta: u16, tau: u16, secret_key: &SecretKey) -> Self {
        let list = (0..tau)
            .map(|_| {
                let q = Polynomial::random(dp as usize);
                let sq = secret_key.clone().get_polynomial().mul(&q);
                let r = Polynomial::random(delta as usize);
                let rx = r.mul(&Polynomial::monomial(1));
                sq.add(&rx)
            })
            .collect::<Vec<_>>();

        Self(list.into_boxed_slice())
    }

    #[must_use]
    #[inline]
    pub(crate) const fn get_polynomials(&self) -> &[Polynomial] {
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
    /// # use homomorph::{Context, Parameters};
    /// #
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    /// context.generate_secret_key();
    /// context.generate_public_key().unwrap();
    ///
    /// let key_bytes = context.get_public_key().unwrap().to_bytes();
    /// ```
    pub fn to_bytes(&self) -> Vec<Vec<u8>> {
        let mut bytes_outer: Vec<Vec<u8>> = Vec::with_capacity(self.get_polynomials().len());
        for pol in self.get_polynomials() {
            bytes_outer.push(pol.to_bytes());
        }
        bytes_outer
    }
}

/// The cipher context.
#[derive(Clone, Debug)]
pub struct Context {
    parameters: Parameters,
    secret_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
}

impl Context {
    #[must_use]
    #[inline]
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
    /// # use homomorph::{Context, Parameters};
    /// #
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// ```
    pub const fn new(parameters: Parameters) -> Self {
        Self {
            parameters,
            secret_key: None,
            public_key: None,
        }
    }

    #[must_use]
    #[inline]
    pub const fn parameters(&self) -> &Parameters {
        &self.parameters
    }

    #[must_use]
    #[inline]
    /// Returns a reference to the secret key.
    ///
    /// ## Returns
    ///
    /// A reference to the secret key.
    ///
    /// ## Examples
    ///
    /// ```
    /// # use homomorph::{Context, Parameters};
    /// #
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// let secret_key = context.get_secret_key().unwrap();
    /// ```
    pub const fn get_secret_key(&self) -> Option<&SecretKey> {
        self.secret_key.as_ref()
    }

    #[must_use]
    #[inline]
    /// Returns a reference to the public key.
    ///
    /// ## Returns
    ///
    /// A reference to the public key.
    ///
    /// ## Examples
    ///
    /// ```
    /// # use homomorph::{Context, Parameters};
    /// #
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    /// context.generate_public_key().unwrap();
    /// let public_key = context.get_public_key().unwrap();
    /// ```
    pub const fn get_public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    #[inline]
    /// Generates a secret key.
    ///
    /// ## Note
    ///
    /// Clears the public key if it was generated before.
    ///
    /// ## Examples
    ///
    /// ```
    /// # use homomorph::{Context, Parameters};
    /// #
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    ///
    /// context.generate_secret_key();
    /// ```
    pub fn generate_secret_key(&mut self) {
        self.secret_key = Some(SecretKey::random(self.parameters().d()));
        self.public_key = None;
    }

    #[inline]
    /// Generates a public key out of the private key.
    ///
    /// ## Errors
    ///
    /// Returns an error if the secret key has not been generated yet.
    ///
    /// ## Examples
    ///
    /// ```
    /// # use homomorph::{Context, Parameters};
    /// #
    /// let params = Parameters::new(6, 3, 2, 5);
    /// let mut context = Context::new(params);
    /// context.generate_secret_key();
    ///
    /// context.generate_public_key().unwrap();
    /// ```
    pub fn generate_public_key(&mut self) -> Result<(), SecretKeyUnset> {
        self.public_key = Some(PublicKey::random(
            self.parameters().dp(),
            self.parameters().delta(),
            self.parameters().tau(),
            self.get_secret_key().ok_or(SecretKeyUnset)?,
        ));

        Ok(())
    }

    #[inline]
    /// Explicitly sets the secret key.
    ///
    /// ## Arguments
    ///
    /// * `secret_key` - The secret key.
    ///
    /// ## Examples
    ///
    /// ```
    /// # use homomorph::{Context, Parameters, SecretKey};
    /// #
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    ///
    /// // INSECURE!!! Only for demonstration purposes
    /// let s = vec![5, 14, 8];
    /// let sk = SecretKey::from_bytes(&s);
    ///
    /// context.set_secret_key(sk);
    /// ```
    pub fn set_secret_key(&mut self, secret_key: SecretKey) {
        self.secret_key = Some(secret_key);
    }

    #[inline]
    /// Explicitly sets the public key.
    ///
    /// ## Arguments
    ///
    /// * `public_key` - The public key.
    ///
    /// ## Examples
    ///
    /// ```
    /// # use homomorph::{Context, Parameters, PublicKey};
    /// #
    /// let mut context = Context::new(Parameters::new(6, 3, 2, 5));
    ///
    /// // INSECURE!!! Only for demonstration purposes
    /// let p = vec![vec![4, 7, 5], vec![1, 2, 3], vec![5, 4, 6]];
    /// let pk = PublicKey::from_bytes(&p);
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
    const fn test_parameters_delta_panic() {
        let _ = Parameters::new(6, 3, 6, 5);
    }

    #[test]
    #[should_panic = "Parameters must be strictly positive"]
    #[allow(clippy::missing_const_for_fn)]
    const fn test_parameters_null_panic() {
        let _ = Parameters::new(6, 0, 2, 5);
    }

    #[test]
    fn test_secret_key() {
        let s = vec![5, 14, 8];
        let sk = SecretKey::from_bytes(&s);

        let bytes = sk.to_bytes();
        let sk2 = SecretKey::from_bytes(&bytes);

        assert_eq!(sk, sk2);
    }

    #[test]
    fn test_public_key() {
        let p = vec![vec![4, 7, 5], vec![1, 2, 3], vec![5, 4, 6]];
        let pk = PublicKey::from_bytes(&p);

        let bytes = pk.to_bytes();
        let pk2 = PublicKey::from_bytes(&bytes);

        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_context() {
        let params = Parameters::new(64, 32, 8, 32);
        let mut context = Context::new(params);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
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
        context
            .generate_public_key()
            .expect("Secret key not generated yet.");
    }
}
