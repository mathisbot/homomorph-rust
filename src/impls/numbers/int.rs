use crate::impls::numbers::{HomomorphicAddition, HomomorphicMultiplication};
use crate::operations::HomomorphicOperation2;
use crate::Ciphered;

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
    use crate::impls::numbers::{HomomorphicAddition, HomomorphicMultiplication};
    use crate::operations::HomomorphicOperation2;
    use crate::{Ciphered, Context, Parameters};

    use rand::{thread_rng, Rng};

    #[test]
    #[should_panic = "not yet implemented: Homormophic addition for int"]
    fn test_homomorphic_addition() {
        let parameters = Parameters::new(64, 16, 1, 16);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key();
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
        context.generate_public_key();
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
        context.generate_public_key();
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
        context.generate_public_key();
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
