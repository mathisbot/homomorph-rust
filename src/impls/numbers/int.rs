use crate::prelude::*;
use homomorph_impls::numbers::{
    HomomorphicAddition, HomomorphicAndGate, HomomorphicMultiplication, HomomorphicNotGate,
    HomomorphicOrGate, HomomorphicXorGate,
};

macro_rules! impl_homomorphic_gates_int {
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

impl_homomorphic_gates_int!(i8, i16, i32, isize, i64, i128);

macro_rules! impl_homomorphic_addition_int {
    ($($t:ty),+) => {
        $(
            impl HomomorphicOperation2<$t> for HomomorphicAddition {
                /// Perform a homomorphic addition on two ciphered numbers.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least `21*sizeof::<T>()`.
                unsafe fn apply(_a: &Ciphered<$t>, _b: &Ciphered<$t>) -> Ciphered<$t> {
                    todo!("Homormophic addition for int");
                }
            }
        )+
    }
}

impl_homomorphic_addition_int!(i8, i16, i32, isize, i64, i128);

macro_rules! impl_homomorphic_multiplication_int {
    ($($t:ty),+) => {
        $(
            // https://en.m.wikipedia.org/wiki/Binary_multiplier#Signed_integers
            impl HomomorphicOperation2<$t> for HomomorphicMultiplication {
                /// Perform a homomorphic multiplication on two ciphered numbers.
                ///
                /// ## Safety
                ///
                /// `d/delta` on cipher must have been at least TBD.
                unsafe fn apply(_a: &Ciphered<$t>, _b: &Ciphered<$t>) -> Ciphered<$t> {
                    todo!("Homormophic multiplication for int");
                }
            }
        )+
    }
}

impl_homomorphic_multiplication_int!(i8, i16, i32, isize, i64, i128);

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

        let a = Ciphered::cipher(&0b1010_i8, pk);
        let b = Ciphered::cipher(&0b1100_i8, pk);
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

        let a = Ciphered::cipher(&0b1010_i8, pk);
        let b = Ciphered::cipher(&0b1100_i8, pk);
        let c = unsafe { HomomorphicOrGate::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(0b1110, d);
    }

    #[test]
    fn test_homomorphic_xor_gate() {
        let parameters = Parameters::new(16, 8, 8, 8);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();
        let pk = context.get_public_key().unwrap();

        let a = Ciphered::cipher(&0b1010_i8, pk);
        let b = Ciphered::cipher(&0b1100_i8, pk);
        let c = unsafe { HomomorphicXorGate::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(0b0110, d);
    }

    #[test]
    fn test_homomorphic_not_gate() {
        let parameters = Parameters::new(16, 8, 8, 8);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();
        let pk = context.get_public_key().unwrap();

        let mut a = Ciphered::cipher(&0b0000_1010_i8, pk);
        unsafe { HomomorphicNotGate::apply(&mut a) };
        let d = a.decipher(sk);
        assert_eq!(-11, d);

        let mut a = Ciphered::cipher(&0b0000_1100_i8, pk);
        unsafe { HomomorphicNotGate::apply(&mut a) };
        let d = a.decipher(sk);
        assert_eq!(-13, d);
    }

    #[test]
    #[should_panic = "not yet implemented: Homormophic addition for int"]
    fn test_homomorphic_addition() {
        let parameters = Parameters::new(64, 16, 1, 16);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a = Ciphered::cipher(&22_i8, pk);
        let b = Ciphered::cipher(&-20_i8, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(d, 2);

        let a_raw = thread_rng().gen::<i16>() / 2;
        let b_raw = thread_rng().gen::<i16>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(d, a_raw + b_raw);
    }

    #[test]
    #[ignore = "long test"]
    #[should_panic = "not yet implemented: Homormophic addition for int"]
    fn test_homomorphic_addition_extensive() {
        let parameters = Parameters::new(256, 128, 1, 128);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a_raw = thread_rng().gen::<i64>() / 2;
        let b_raw = thread_rng().gen::<i64>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(d, a_raw + b_raw);
    }

    #[test]
    #[ignore = "long test"]
    #[should_panic = "not yet implemented: Homormophic addition for int"]
    #[allow(clippy::many_single_char_names)]
    fn test_successive_homomorphic_addition() {
        let parameters = Parameters::new(256, 128, 1, 128);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a_raw = thread_rng().gen::<i8>() / 2;
        let b_raw = thread_rng().gen::<i8>() / 2;
        let c_raw = thread_rng().gen::<i8>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = Ciphered::cipher(&c_raw, pk);
        let d = unsafe { HomomorphicAddition::apply(&a, &b) };
        let e = unsafe { HomomorphicAddition::apply(&d, &c) };
        let f = e.decipher(sk);
        assert_eq!(f, a_raw + b_raw + c_raw);
    }

    #[test]
    #[should_panic = "not yet implemented: Homormophic multiplication for int"]
    fn test_homomorphic_multiplication() {
        let parameters = Parameters::new(512, 64, 1, 64);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key().unwrap();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a = Ciphered::cipher(&6_i8, pk);
        let b = Ciphered::cipher(&-7_i8, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(d, -42);

        let a_raw = thread_rng().gen::<i16>() / 2;
        let b_raw = thread_rng().gen::<i16>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicMultiplication::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(d, a_raw * b_raw);
    }
}
