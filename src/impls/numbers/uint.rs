use crate::{
    Ciphered, CipheredBit, HomomorphicAddition, HomomorphicMultiplication, HomomorphicOperation2,
};

use alloc::vec::Vec;

fn homomorph_add_internal(a: &[CipheredBit], b: &[CipheredBit]) -> Vec<CipheredBit> {
    let longest = a.len().max(b.len());
    let mut result = Vec::with_capacity(longest + 1);
    let mut carry = CipheredBit::zero();

    // Avoid borrowing issues
    let null_bit = CipheredBit::zero();

    for i in 0..longest {
        let p1 = a.get(i).unwrap_or(&null_bit);
        let p2 = b.get(i).unwrap_or(&null_bit);
        let s = p1.xor(p2).xor(&carry);

        // This is too long and can be simplified :
        // carry = p1.bit_xor(&p2).bit_and(&carry).bit_or(&p1.bit_and(&p2));
        // c <- (p1+p2)*c + p1*p2 + p1*p2*(p1+p2)*c
        // c <- c*(p1+p2)*(1+p1*p2) + p1*p2
        let p1_p2 = p1.and(p2);
        carry = p1
            .xor(p2)
            .and(&carry)
            .and(&CipheredBit::one().xor(&p1_p2))
            .xor(&p1_p2);

        result.push(s);
    }
    result.push(carry);

    result
}

macro_rules! impl_homomorphic_addition_uint {
    ($($t:ty),+) => {
        $(
            impl HomomorphicOperation2<$t> for HomomorphicAddition {
                /// Perform a homomorphic addition on two ciphered numbers.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least `21*sizeof::<T>()`.
                unsafe fn apply(a: &Ciphered<$t>, b: &Ciphered<$t>) -> Ciphered<$t> {
                    Ciphered::new_from_raw(homomorph_add_internal(a, b))
                }
            }
        )+
    }
}

impl_homomorphic_addition_uint!(u8, u16, u32, usize, u64, u128);

// https://en.m.wikipedia.org/wiki/Binary_multiplier#Unsigned_integers
fn homomorph_mul_internal(a: &[CipheredBit], b: &[CipheredBit]) -> Vec<CipheredBit> {
    // We stop before overflow as overflowed bits will be thrown away on decryption
    let max_len = a.len().max(b.len());

    // TODO: Remove this line when the algorithm is implemented
    #[allow(unused_mut, unused_variables)]
    let mut result: Vec<CipheredBit> = vec![CipheredBit::zero(); max_len];

    // Avoid borrowing issues
    let null_bit = CipheredBit::zero();

    let mut partial_products = Vec::with_capacity(max_len);
    for i in 0..max_len {
        let mut pi = Vec::with_capacity(max_len);
        let ai = a.get(i).unwrap_or(&null_bit);
        for j in 0..max_len {
            pi.push(ai.and(b.get(j).unwrap_or(&null_bit)));
        }
        partial_products.push(pi);
    }

    // TODO: Implement the rest of the algorithm
    todo!("Homormophic multiplication for uint");
    #[allow(unreachable_code)]
    result
}

macro_rules! impl_homomorphic_multiplication_uint {
    ($($t:ty),+) => {
        $(
            impl HomomorphicOperation2<$t> for HomomorphicMultiplication {
                /// Perform a homomorphic multiplication on two ciphered numbers.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least TBD.
                unsafe fn apply(a: &Ciphered<$t>, b: &Ciphered<$t>) -> Ciphered<$t> {
                    Ciphered::new_from_raw(homomorph_mul_internal(a, b))
                }
            }
        )+
    }
}

impl_homomorphic_multiplication_uint!(u8, u16, u32, usize, u64, u128);

#[cfg(test)]
mod tests {
    use crate::{Ciphered, HomomorphicAddition, HomomorphicMultiplication, HomomorphicOperation2};
    use crate::{Context, Parameters};

    use rand::{thread_rng, Rng};

    #[test]
    fn test_homomorphic_addition() {
        let parameters = Parameters::new(64, 16, 1, 16);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a = Ciphered::cipher(&22u8, pk);
        let b = Ciphered::cipher(&20u8, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(42, d);

        let a_raw = thread_rng().gen::<u16>() / 2;
        let b_raw = thread_rng().gen::<u16>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(a_raw + b_raw, d);
    }

    #[test]
    #[ignore = "Long test"]
    fn test_homomorphic_addition_extensive() {
        let parameters = Parameters::new(256, 128, 1, 128);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a_raw = {
            let mut buffer = [0u8; 8];
            getrandom::getrandom(&mut buffer).expect("Failed to generate random bytes");
            u64::from_le_bytes(buffer)
        } / 2;
        let b_raw = {
            let mut buffer = [0u8; 8];
            getrandom::getrandom(&mut buffer).expect("Failed to generate random bytes");
            u64::from_le_bytes(buffer)
        } / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(a_raw + b_raw, d);
    }

    #[test]
    #[ignore = "Long test"]
    fn test_successive_homomorphic_addition() {
        let parameters = Parameters::new(256, 128, 1, 128);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a_raw = {
            let mut buffer = [0u8; 1];
            getrandom::getrandom(&mut buffer).expect("Failed to generate random bytes");
            u8::from_le_bytes(buffer)
        } / 2;
        let b_raw = {
            let mut buffer = [0u8; 1];
            getrandom::getrandom(&mut buffer).expect("Failed to generate random bytes");
            u8::from_le_bytes(buffer)
        } / 2;
        let c_raw = {
            let mut buffer = [0u8; 1];
            getrandom::getrandom(&mut buffer).expect("Failed to generate random bytes");
            u8::from_le_bytes(buffer)
        } / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = Ciphered::cipher(&c_raw, pk);
        let d = unsafe { HomomorphicAddition::apply(&a, &b) };
        let e = unsafe { HomomorphicAddition::apply(&d, &c) };
        let f = e.decipher(sk);
        assert_eq!(a_raw + b_raw + c_raw, f);
    }

    #[test]
    #[should_panic = "not yet implemented: Homormophic multiplication for uint"]
    fn test_homomorphic_multiplication() {
        let parameters = Parameters::new(512, 64, 1, 64);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a = Ciphered::cipher(&6u8, pk);
        let b = Ciphered::cipher(&7u8, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(42, d);

        let a_raw = thread_rng().gen::<u16>() / 2;
        let b_raw = thread_rng().gen::<u16>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(a_raw * b_raw, d);
    }
}
