use crate::prelude::*;
use crate::impls::numbers::{
    HomomorphicAddition, HomomorphicAndGate, HomomorphicMultiplication, HomomorphicNotGate,
    HomomorphicOrGate, HomomorphicXorGate,
};

use alloc::vec::Vec;

macro_rules! impl_homomorphic_gates_uint {
    ($($t:ty),+) => {
        $(
            impl HomomorphicOperation2<$t> for HomomorphicAndGate {
                /// Perform a homomorphic AND gate on two ciphered numbers.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least 2.
                unsafe fn apply(a: &Ciphered<$t>, b: &Ciphered<$t>) -> Ciphered<$t> {
                    Ciphered::new_from_raw(a.iter().zip(b.iter()).map(|(a, b)| a.and(b)).collect())
                }
            }

            impl HomomorphicOperation2<$t> for HomomorphicOrGate {
                /// Perform a homomorphic OR gate on two ciphered numbers.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least 2.
                unsafe fn apply(a: &Ciphered<$t>, b: &Ciphered<$t>) -> Ciphered<$t> {
                    Ciphered::new_from_raw(a.iter().zip(b.iter()).map(|(a, b)| a.or(b)).collect())
                }
            }

            impl HomomorphicOperation2<$t> for HomomorphicXorGate {
                /// Perform a homomorphic XOR gate on two ciphered numbers.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least 1.
                unsafe fn apply(a: &Ciphered<$t>, b: &Ciphered<$t>) -> Ciphered<$t> {
                    Ciphered::new_from_raw(a.iter().zip(b.iter()).map(|(a, b)| a.xor(b)).collect())
                }
            }

            impl HomomorphicOperation1<$t> for HomomorphicNotGate {
                /// Perform a homomorphic NOT gate on a ciphered number.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least 1.
                unsafe fn apply(a: &mut Ciphered<$t>) -> &mut Ciphered<$t> {
                    *a = Ciphered::new_from_raw(a.iter().map(|a| a.not()).collect());
                    a
                }
            }
        )+
    }
}

impl_homomorphic_gates_uint!(u8, u16, u32, usize, u64, u128);

fn homomorph_add_internal(a: &[CipheredBit], b: &[CipheredBit]) -> Vec<CipheredBit> {
    debug_assert_eq!(a.len(), b.len());

    let mut result = Vec::with_capacity(a.len());
    let mut carry = CipheredBit::zero();

    let one_bit = CipheredBit::one();

    for (i, (cb1, cb2)) in a.iter().zip(b.iter()).enumerate() {
        let s = cb1.xor(cb2).xor(&carry);

        result.push(s);

        // Ignore last carry
        if i + 1 >= a.len() {
            break;
        }

        // carry = p1.xor(&p2).and(&carry).or(&p1.and(&p2));
        // This is too long and can be simplified :
        // c <- (p1+p2)*c + p1*p2 + p1*p2*(p1+p2)*c
        // c <- c*(p1+p2)*(1+p1*p2) + p1*p2
        let cb1_cb2 = cb1.and(cb2);
        carry = carry
            .and(&cb1.xor(cb2))
            .and(&one_bit.xor(&cb1_cb2))
            .xor(&cb1_cb2);
    }

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

/// `a` and `b` must have the same length, equal to the number of bits
///
/// From <https://en.m.wikipedia.org/wiki/Binary_multiplier#Unsigned_integers>
fn homomorph_mul_internal(a: &[CipheredBit], b: &[CipheredBit]) -> Vec<CipheredBit> {
    // We stop before overflow as overflowed bits will be thrown away on decryption
    let length = a.len();
    let mut result = vec![CipheredBit::zero(); length];

    let partial_products = a
        .iter()
        .map(|ai| b.iter().map(|bj| ai.and(bj)).collect::<Vec<_>>())
        .collect::<Vec<_>>();

    let mut carries = Vec::with_capacity((length - 1) * length * (length + 1) / 6);

    // Compiler hints
    assert_eq!(result.len(), length);
    assert_eq!(partial_products.len(), length);

    // TODO: Optimize this
    let mut offset = 0;
    for i in 0..length {
        let current_length = i * (i + 1) / 2;

        // Apply partial products
        for (j, pj) in partial_products.iter().enumerate().take(i + 1) {
            let pp = &pj[i - j];
            if i + 1 < length {
                carries.push(pp.and(&result[i]));
            }
            result[i] = result[i].xor(pp);
        }
        // Propagate carry
        assert!(offset + current_length <= carries.len()); // Compiler hint
        for j in 0..current_length {
            if i + 1 < length {
                let t = result[i].and(&carries[offset + j]);
                carries.push(t);
            }
            result[i] = result[i].xor(&carries[offset + j]);
        }

        offset += current_length;
    }
    // All subsequent carries are thrown away

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
    use crate::prelude::*;
    use crate::impls::numbers::{
        HomomorphicAddition, HomomorphicAndGate, HomomorphicMultiplication, HomomorphicNotGate,
        HomomorphicOrGate, HomomorphicXorGate,
    };

    use rand::{thread_rng, Rng};

    #[test]
    fn test_homomorphic_and_gate() {
        let parameters = Parameters::new(32, 8, 8, 8);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();
        let pk = context.get_public_key().unwrap();

        let a = Ciphered::cipher(&0b1010_u8, pk);
        let b = Ciphered::cipher(&0b1100_u8, pk);
        let c = unsafe { HomomorphicAndGate::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(0b1000, d);
    }

    #[test]
    fn test_homomorphic_or_gate() {
        let parameters = Parameters::new(32, 8, 8, 8);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();
        let pk = context.get_public_key().unwrap();

        let a = Ciphered::cipher(&0b1010_u8, pk);
        let b = Ciphered::cipher(&0b1100_u8, pk);
        let c = unsafe { HomomorphicOrGate::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(0b1110, d);
    }

    #[test]
    fn test_homomorphic_xor_gate() {
        let parameters = Parameters::new(32, 16, 16, 16);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();
        let pk = context.get_public_key().unwrap();

        let a = Ciphered::cipher(&0b1010_u8, pk);
        let b = Ciphered::cipher(&0b1100_u8, pk);
        let c = unsafe { HomomorphicXorGate::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(0b0110, d);
    }

    #[test]
    fn test_homomorphic_not_gate() {
        let parameters = Parameters::new(32, 16, 16, 16);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();
        let pk = context.get_public_key().unwrap();

        let mut a = Ciphered::cipher(&0b0000_1010_u8, pk);
        unsafe { HomomorphicNotGate::apply(&mut a) };
        let d = a.decipher(sk);
        assert_eq!(0b1111_0101, d);

        let mut a = Ciphered::cipher(&0b0000_1100_u8, pk);
        unsafe { HomomorphicNotGate::apply(&mut a) };
        let d = a.decipher(sk);
        assert_eq!(0b1111_0011, d);
    }

    #[test]
    fn test_homomorphic_addition() {
        let parameters = Parameters::new(64, 16, 1, 16);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();
        let pk = context.get_public_key().unwrap();

        // Normal addition
        let a = Ciphered::cipher(&22_u8, pk);
        let b = Ciphered::cipher(&20_u8, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(42, d);

        // Random case
        let a_raw = thread_rng().gen::<u16>() / 2;
        let b_raw = thread_rng().gen::<u16>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(a_raw + b_raw, d);

        // Wrapping overflow
        let a = Ciphered::cipher(&255_u8, pk);
        let b = Ciphered::cipher(&240_u8, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(239, d);
    }

    #[test]
    #[ignore = "long test"]
    fn test_homomorphic_addition_extensive() {
        let parameters = Parameters::new(256, 128, 1, 128);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a_raw = thread_rng().gen::<u64>() / 2;
        let b_raw = thread_rng().gen::<u64>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(a_raw + b_raw, d);
    }

    #[test]
    #[ignore = "long test"]
    #[allow(clippy::many_single_char_names)]
    fn test_successive_homomorphic_addition() {
        let parameters = Parameters::new(256, 128, 1, 128);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a_raw = thread_rng().gen::<u8>() / 2;
        let b_raw = thread_rng().gen::<u8>() / 2;
        let c_raw = thread_rng().gen::<u8>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = Ciphered::cipher(&c_raw, pk);
        let d = unsafe { HomomorphicAddition::apply(&a, &b) };
        let e = unsafe { HomomorphicAddition::apply(&d, &c) };
        let f = e.decipher(sk);
        assert_eq!(a_raw + b_raw + c_raw, f);
    }

    #[test]
    fn test_homomorphic_multiplication() {
        let parameters = Parameters::new(128, 64, 1, 64);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        // Normal case
        let a = Ciphered::cipher(&6_u8, pk);
        let b = Ciphered::cipher(&7_u8, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(42, d);

        // Multiplication by 0
        let a = Ciphered::cipher(&0_u8, pk);
        let b = Ciphered::cipher(&151_u8, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(0, d);

        // Random case
        let a_raw = thread_rng().gen::<u8>() % 13;
        let b_raw = thread_rng().gen::<u8>() % 20;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(a_raw * b_raw, d);

        // Wrapping overflow
        let a = Ciphered::cipher(&255_u8, pk);
        let b = Ciphered::cipher(&240_u8, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(16, d);
    }
}
