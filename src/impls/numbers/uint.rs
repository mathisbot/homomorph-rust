use crate::{Ciphered, HomomorphicAddition, HomomorphicOperation, Polynomial};

fn homomorph_add_internal(a: &[Polynomial], b: &[Polynomial]) -> Vec<Polynomial> {
    let longest = a.len().max(b.len());
    let mut result = Vec::with_capacity(longest + 1);
    let mut carry = Polynomial::null();

    let null_pol = Polynomial::null();
    for i in 0..longest {
        let p1 = a.get(i).unwrap_or(&null_pol);
        let p2 = b.get(i).unwrap_or(&null_pol);
        let s = p1.add(p2).add(&carry);

        // This is too long and can be simplified :
        // carry = p1.bit_xor(&p2).bit_and(&carry).bit_or(&p1.bit_and(&p2));
        // c <- (p1+p2)*c + p1*p2 + p1*p2*(p1+p2)*c
        // c <- c*(p1+p2)*(1+p1*p2) + p1*p2
        let p1_p2 = p1.mul(p2);
        carry = p1
            .add(p2)
            .mul(&carry)
            .mul(&Polynomial::monomial(0).add(&p1_p2))
            .add(&p1_p2);

        result.push(s);
    }
    result.push(carry);

    result
}

macro_rules! impl_homomorphic_addition_uint {
    ($($t:ty),+) => {
        $(
            impl HomomorphicOperation<$t> for HomomorphicAddition {
                unsafe fn apply(a: &Ciphered<$t>, b: &Ciphered<$t>) -> Ciphered<$t> {
                    Ciphered::new_from_raw(homomorph_add_internal(a, b))
                }
            }
        )+
    }
}

impl_homomorphic_addition_uint!(u8, u16, u32, usize, u64, u128);

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use crate::cipher::HomomorphicOperation;
    use crate::Ciphered;
    use crate::HomomorphicAddition;
    use crate::{Context, Parameters};

    #[test]
    fn test_homomorphic_addition() {
        let parameters = Parameters::new(128, 32, 1, 32);
        let mut context = Context::new(parameters);
        context.generate_secret_key();
        context.generate_public_key();
        let pk = context.get_public_key().unwrap();
        let sk = context.get_secret_key().unwrap();

        let a = Ciphered::cipher(&22usize, pk);
        let b = Ciphered::cipher(&20usize, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(d, 42);

        let a_raw = thread_rng().gen::<usize>() / 2;
        let b_raw = thread_rng().gen::<usize>() / 2;

        let a = Ciphered::cipher(&a_raw, pk);
        let b = Ciphered::cipher(&b_raw, pk);
        let c = unsafe { HomomorphicAddition::apply(&a, &b) };
        let d = c.decipher(sk);
        assert_eq!(d, a_raw + b_raw);
    }
}