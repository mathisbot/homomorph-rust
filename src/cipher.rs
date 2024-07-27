use crate::polynomial::Polynomial;
use crate::{PublicKey, SecretKey};

use core::ptr::copy_nonoverlapping as memcpy;
use rand::Rng;
use std::ops::Deref;

/// This trait is used to convert a type to a byte array and back
///
/// It is notably useful to convert a type to a byte array to encrypt it
///
/// ## Safety
///
/// As it is easy to misuse this trait, it is marked as unsafe.
/// For example, converting a `Vec` to a byte array needs to be done with care :
/// heap data also needs to be converted to a byte array, which is not done by default
pub unsafe trait ByteConvertible {
    fn to_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Self;
}

unsafe impl<T: Copy + Sized> ByteConvertible for T {
    fn to_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(self as *const T as *const u8, core::mem::size_of::<T>())
        }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() != core::mem::size_of::<T>() {
            panic!("Invalid size of bytes for conversion");
        }

        let mut data = core::mem::MaybeUninit::uninit();
        unsafe {
            memcpy(
                bytes.as_ptr(),
                data.as_mut_ptr() as *mut u8,
                core::mem::size_of::<T>(),
            );
        }
        unsafe { data.assume_init() }
    }
}

/// This struct is used to store encrypted data
#[derive(Debug, Clone)]
pub struct Ciphered<T: ByteConvertible> {
    phantom: core::marker::PhantomData<T>,
    c_data: Vec<crate::polynomial::Polynomial>,
}

impl<T: ByteConvertible> Ciphered<T> {
    /// This function is used to create a new `Ciphered` object
    ///
    /// This function should only be used in unsafe contexts
    /// when it is really needed to operate on raw data,
    /// such as when defining homomorphic operations
    ///
    /// ## Safety
    ///
    /// The bits represented by the polynomials must be valid
    pub unsafe fn new_from_raw(c_data: Vec<Polynomial>) -> Self {
        Self {
            phantom: core::marker::PhantomData,
            c_data,
        }
    }

    // u8 is used instead of bool because they are the same size
    // while u8 can store 8 times more information
    fn part(tau: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut part: Vec<u8> = Vec::with_capacity((tau + 7) / 8);

        for _ in 0..(tau + 7) / 8 {
            part.push(rng.gen());
        }

        part
    }

    fn cipher_bit(x: bool, pk: &PublicKey) -> Polynomial {
        let tau = pk.len();
        let random_part = Self::part(tau);

        let mut sum = Polynomial::null();
        for i in 0..tau {
            let random = random_part[i / 8] & (1 << (i % 8));
            if random != 0 {
                sum = sum.add(&pk[i]);
            }
        }

        // Save computation if x is false
        // This does not give hints about the value of x has sum+0 is exactly the same as sum
        if x {
            sum.add(&Polynomial::monomial(0))
        } else {
            sum
        }
    }

    /// This function is used to encrypt data
    ///
    /// ## Arguments
    ///
    /// * `data` - The data to encrypt
    /// * `pk` - The public key to use for encryption
    pub fn cipher(data: &T, pk: &PublicKey) -> Self {
        let c_data = data
            .to_bytes()
            .iter()
            .flat_map(|&byte| (0..8).map(move |i| Self::cipher_bit((byte >> i) & 1 == 1, pk)))
            .collect::<Vec<_>>();

        Self {
            phantom: core::marker::PhantomData,
            c_data,
        }
    }

    fn decipher_bit(poly: &Polynomial, sk: &SecretKey) -> bool {
        let remainder = poly.rem(sk);
        remainder.evaluate(false)
    }

    /// This function is used to decrypt data
    ///
    /// ## Arguments
    ///
    /// * `sk` - The secret key to use for decryption
    pub fn decipher(&self, sk: &SecretKey) -> T {
        let deciphered_bits: Vec<bool> = self
            .iter()
            .map(|poly| Self::decipher_bit(poly, sk))
            .collect();

        let mut bytes = vec![0u8; (deciphered_bits.len() + 7) / 8];
        for (i, &bit) in deciphered_bits.iter().enumerate() {
            let byte_index = i / 8;
            let bit_index = i % 8;
            if bit {
                bytes[byte_index] |= 1 << bit_index;
            }
        }

        let mut original_data = core::mem::MaybeUninit::uninit();
        // If the ciphered data is longer than the size of the original data, the rest is ignored
        // e.g. overflow when adding two numbers
        unsafe {
            memcpy(
                bytes.as_ptr(),
                original_data.as_mut_ptr() as *mut u8,
                core::mem::size_of::<T>(),
            );
        }

        unsafe { original_data.assume_init() }
    }
}

impl<T> Deref for Ciphered<T>
where
    T: ByteConvertible,
{
    type Target = Vec<Polynomial>;

    fn deref(&self) -> &Self::Target {
        &self.c_data
    }
}

/// This trait is used to define homomorphic operations
pub trait HomomorphicOperation<T: ByteConvertible> {
    /// ## Safety
    ///
    /// The function `apply` is marked as unsafe as it handles raw bits of data.
    /// You must ensure this function will result in valid ciphered data.
    unsafe fn apply(a: &Ciphered<T>, b: &Ciphered<T>) -> Ciphered<T>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Context, Parameters};

    #[test]
    fn test_cipher() {
        let parameters = Parameters::new(64, 32, 8, 32);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key();
        let sk = context.get_secret_key().unwrap();
        let pk = context.get_public_key().unwrap();

        let data = 0b10001010u8;
        let ciphered = Ciphered::cipher(&data, pk);
        let decrypted = ciphered.decipher(sk);
        assert_eq!(data, decrypted);

        let data = usize::MAX;
        let ciphered = Ciphered::cipher(&data, pk);
        let decrypted = ciphered.decipher(sk);
        assert_eq!(data, decrypted);

        let data = "Hello, World!";
        let ciphered = Ciphered::cipher(&data, pk);
        let decrypted = ciphered.decipher(sk);
        assert_eq!(data, decrypted);
    }
}
