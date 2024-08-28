use crate::prelude::*;
use homomorph_impls::numbers::{
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
            .and(&CipheredBit::one().xor(&cb1_cb2))
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

// TODO: Remove these two lines
#[allow(unreachable_code)]
#[allow(unused_variables)]
// https://en.m.wikipedia.org/wiki/Binary_multiplier#Unsigned_integers
fn homomorph_mul_internal(a: &[CipheredBit], b: &[CipheredBit], size: usize) -> Vec<CipheredBit> {
    todo!("Homormophic multiplication for uint");

    // We stop before overflow as overflowed bits will be thrown away on decryption
    let max_len = size;

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

    // TODO: Fix this broken carry
    let mut carry: Vec<Vec<CipheredBit>> = Vec::with_capacity(max_len);
    carry.push(Vec::with_capacity(0));
    for i in 0..max_len {
        if i + 1 < max_len {
            carry.push(Vec::with_capacity(i + carry[i].len()));
        }
        // Apply partial products
        for j in 0..i {
            if i + 1 < max_len {
                carry[i + 1].push(partial_products[i][i - j].and(&result[i]));
            }
            result[i] = result[i].xor(&partial_products[i][i - j]);
        }
        // Propagate carry
        for j in 0..carry[i].len() {
            if i + 1 < max_len {
                let t = result[i].and(&carry[i][j]);
                carry[i + 1].push(t);
            }
            result[i] = result[i].xor(&carry[i][j]);
        }
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
                    Ciphered::new_from_raw(homomorph_mul_internal(a, b, <$t>::BITS as usize))
                }
            }
        )+
    }
}

impl_homomorphic_multiplication_uint!(u8, u16, u32, usize, u64, u128);

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use homomorph_impls::numbers::{
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

        let a = Ciphered::cipher(&22_u8, pk);
        let b = Ciphered::cipher(&20_u8, pk);
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
    #[should_panic = "not yet implemented: Homormophic multiplication for uint"]
    fn test_homomorphic_multiplication() {
        let parameters = Parameters::new(1024, 8, 1, 4);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a = Ciphered::cipher(&6_u8, pk);
        let b = Ciphered::cipher(&7_u8, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(42, d);

        let a = Ciphered::cipher(&0_u8, pk);
        let b = Ciphered::cipher(&151_u8, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(0, d);

        let a_raw = thread_rng().gen::<u16>() / 2;
        let b_raw = thread_rng().gen::<u16>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(a_raw * b_raw, d);
    }
}
