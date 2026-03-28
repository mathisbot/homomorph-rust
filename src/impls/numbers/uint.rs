use super::common;
use crate::impls::numbers::{
    HomomorphicAddition, HomomorphicAndGate, HomomorphicMultiplication, HomomorphicNotGate,
    HomomorphicOrGate, HomomorphicXorGate,
};
use crate::prelude::*;

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
                    common::gate_and(a, b)
                }
            }

            impl HomomorphicOperation2<$t> for HomomorphicOrGate {
                /// Perform a homomorphic OR gate on two ciphered numbers.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least 2.
                unsafe fn apply(a: &Ciphered<$t>, b: &Ciphered<$t>) -> Ciphered<$t> {
                    common::gate_or(a, b)
                }
            }

            impl HomomorphicOperation2<$t> for HomomorphicXorGate {
                /// Perform a homomorphic XOR gate on two ciphered numbers.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least 1.
                unsafe fn apply(a: &Ciphered<$t>, b: &Ciphered<$t>) -> Ciphered<$t> {
                    common::gate_xor(a, b)
                }
            }

            impl HomomorphicOperation1<$t> for HomomorphicNotGate {
                /// Perform a homomorphic NOT gate on a ciphered number.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least 1.
                unsafe fn apply(a: &mut Ciphered<$t>) -> &mut Ciphered<$t> {
                    common::gate_not(a)
                }
            }
        )+
    }
}

impl_homomorphic_gates_uint!(u8, u16, u32, usize, u64, u128);

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
                    common::add(a, b)
                }
            }
        )+
    }
}

impl_homomorphic_addition_uint!(u8, u16, u32, usize, u64, u128);

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
                    common::mul_unsigned(a, b)
                }
            }
        )+
    }
}

impl_homomorphic_multiplication_uint!(u8, u16, u32, usize, u64, u128);

#[cfg(test)]
mod tests {
    use crate::impls::numbers::{
        HomomorphicAddition, HomomorphicAndGate, HomomorphicMultiplication, HomomorphicNotGate,
        HomomorphicOrGate, HomomorphicXorGate,
    };
    use crate::prelude::*;

    use rand::{RngExt as _, rng};

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
        let a_raw = rng().random::<u16>() / 2;
        let b_raw = rng().random::<u16>() / 2;

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

        let a_raw = rng().random::<u64>() / 2;
        let b_raw = rng().random::<u64>() / 2;

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

        let a_raw = rng().random::<u8>() / 2;
        let b_raw = rng().random::<u8>() / 2;
        let c_raw = rng().random::<u8>() / 2;

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
        let a_raw = rng().random::<u8>() % 13;
        let b_raw = rng().random::<u8>() % 20;

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
