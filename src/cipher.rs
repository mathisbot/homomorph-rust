use crate::polynomial::Polynomial;
use crate::{PublicKey, SecretKey};

use alloc::vec::Vec;
use core::ops::Deref;
use core::ptr::copy_nonoverlapping as memcpy;

/// This trait is used to convert a type to a byte array and back
///
/// This is the main trait that structures need to implement to be used with the `Ciphered` struct
///
/// ## Safety
///
/// Entirely converting a struct to a byte array and back has to be done with care.
/// For example, when converting a `Vec` to a byte array, heap data also needs to be
/// converted to a byte array.
pub unsafe trait ByteConvertible {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Self;
}

// All types that implement Copy and Sized can be converted to bytes
// by simply reading stack data as bytes
unsafe impl<T: Copy + Sized> ByteConvertible for T {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(size_of::<T>());
        unsafe {
            memcpy(
                self as *const T as *const u8,
                bytes.as_mut_ptr(),
                size_of::<T>(),
            );
            bytes.set_len(size_of::<T>());
        }
        bytes
    }

    /// This function is used to convert a byte array to a type
    ///
    /// ## Panics
    ///
    /// This function will panic if the byte array is too small.
    ///
    /// ## Note
    ///
    /// If the byte array is too big, data will be truncated.
    /// This can happen with overflows when adding two unsigned integers for example.
    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < size_of::<T>() {
            panic!(
                "Invalid size of bytes for conversion: {} instead of {}",
                bytes.len(),
                size_of::<T>()
            );
        }

        let mut data = core::mem::MaybeUninit::uninit();
        unsafe {
            memcpy(bytes.as_ptr(), data.as_mut_ptr() as *mut u8, size_of::<T>());
            data.assume_init()
        }
    }
}

/// This struct is used to create and store encrypted data
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
    /// i.e. generated by the `Ciphered::cipher` function
    /// and processed with extreme care.
    pub unsafe fn new_from_raw(c_data: Vec<Polynomial>) -> Self {
        Self {
            phantom: core::marker::PhantomData,
            c_data,
        }
    }

    // u8 is used instead of bool because they are the same size
    // while u8 can store 8 times more information
    fn part(tau: usize) -> Vec<u8> {
        let num_elements = (tau + 7) / 8;
        let mut part: Vec<u8> = Vec::with_capacity(num_elements);

        let bytes = unsafe { core::slice::from_raw_parts_mut(part.as_mut_ptr(), num_elements) };
        getrandom::getrandom(bytes).unwrap();
        unsafe { part.set_len(num_elements) };

        part
    }

    // See https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#system
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

        // This does not give hints about the value of x has sum+0 is exactly the same as sum
        if x {
            sum.add(&Polynomial::monomial(0))
        } else {
            sum
        }
    }

    /// Ciphers data
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

    // See https://github.com/mathisbot/homomorph-rust?tab=readme-ov-file#system
    fn decipher_bit(poly: &Polynomial, sk: &SecretKey) -> bool {
        let remainder = poly.rem(sk);
        remainder.evaluate(false)
    }

    /// Deciphers data
    ///
    /// ## Arguments
    ///
    /// * `self` - The ciphered data to decrypt
    /// * `sk` - The secret key to use for decryption
    pub fn decipher(&self, sk: &SecretKey) -> T {
        let deciphered_bits: Vec<bool> = self
            .iter()
            .map(|poly| Self::decipher_bit(poly, sk))
            .collect();

        let bytes = deciphered_bits
            .chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u8, |byte, (i, &bit)| byte | ((bit as u8) << i))
            })
            .collect::<Vec<_>>();

        ByteConvertible::from_bytes(&bytes)
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

        #[derive(Copy, Clone, Debug, PartialEq)]
        struct MyStruct {
            a: usize,
            b: usize,
        }
        let data = MyStruct { a: 42, b: 69 };
        let ciphered = Ciphered::cipher(&data, pk);
        let decrypted = ciphered.decipher(sk);
        assert_eq!(data, decrypted);
    }
}
