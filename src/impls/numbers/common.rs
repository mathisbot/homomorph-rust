use crate::prelude::*;

use alloc::vec::Vec;

pub(super) fn gate_and<T: crate::Encode + crate::Decode<()>>(
    a: &Ciphered<T>,
    b: &Ciphered<T>,
) -> Ciphered<T> {
    // Safety: output is built from valid bitwise homomorphic operations.
    unsafe { Ciphered::new_from_raw(a.iter().zip(b.iter()).map(|(a, b)| a.and(b)).collect()) }
}

pub(super) fn gate_or<T: crate::Encode + crate::Decode<()>>(
    a: &Ciphered<T>,
    b: &Ciphered<T>,
) -> Ciphered<T> {
    // Safety: output is built from valid bitwise homomorphic operations.
    unsafe { Ciphered::new_from_raw(a.iter().zip(b.iter()).map(|(a, b)| a.or(b)).collect()) }
}

pub(super) fn gate_xor<T: crate::Encode + crate::Decode<()>>(
    a: &Ciphered<T>,
    b: &Ciphered<T>,
) -> Ciphered<T> {
    // Safety: output is built from valid bitwise homomorphic operations.
    unsafe { Ciphered::new_from_raw(a.iter().zip(b.iter()).map(|(a, b)| a.xor(b)).collect()) }
}

pub(super) fn gate_not<T: crate::Encode + crate::Decode<()>>(
    a: &mut Ciphered<T>,
) -> &mut Ciphered<T> {
    // Safety: output is built from valid bitwise homomorphic operations.
    *a = unsafe { Ciphered::new_from_raw(a.iter().map(CipheredBit::not).collect()) };
    a
}

pub(super) fn add_internal(a: &[CipheredBit], b: &[CipheredBit]) -> Vec<CipheredBit> {
    let mut result = Vec::with_capacity(a.len());
    let mut carry = CipheredBit::zero();

    let one_bit = CipheredBit::one();

    for (i, (cb1, cb2)) in a.iter().zip(b.iter()).enumerate() {
        let s = cb1.xor(cb2).xor(&carry);
        result.push(s);

        if i + 1 >= a.len() {
            break;
        }

        let c_p1_p2 = cb1.xor(cb2).and(&carry);
        carry = c_p1_p2.xor(&cb1.and(cb2).and(&c_p1_p2.xor(&one_bit)));
    }

    result
}

pub(super) fn add<T: crate::Encode + crate::Decode<()>>(
    a: &Ciphered<T>,
    b: &Ciphered<T>,
) -> Ciphered<T> {
    // Safety: output is built from valid bitwise homomorphic operations.
    unsafe { Ciphered::new_from_raw(add_internal(a, b)) }
}

pub(super) fn mul_unsigned_internal(a: &[CipheredBit], b: &[CipheredBit]) -> Vec<CipheredBit> {
    // We stop before overflow as overflowed bits are discarded on decryption.
    let length = a.len();
    let mut result = vec![CipheredBit::zero(); length];

    let partial_products = a
        .iter()
        .map(|ai| b.iter().map(|bj| ai.and(bj)).collect::<Vec<_>>())
        .collect::<Vec<_>>();

    let mut carries = Vec::with_capacity((length - 1) * length * (length + 1) / 6);

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
        debug_assert!(offset + current_length <= carries.len());
        for j in 0..current_length {
            if i + 1 < length {
                let t = result[i].and(&carries[offset + j]);
                carries.push(t);
            }
            result[i] = result[i].xor(&carries[offset + j]);
        }

        offset += current_length;
    }

    result
}

pub(super) fn mul_unsigned<T: crate::Encode + crate::Decode<()>>(
    a: &Ciphered<T>,
    b: &Ciphered<T>,
) -> Ciphered<T> {
    // Safety: output is built from valid bitwise homomorphic operations.
    unsafe { Ciphered::new_from_raw(mul_unsigned_internal(a, b)) }
}

pub(super) fn mul_signed_internal(a: &[CipheredBit], b: &[CipheredBit]) -> Vec<CipheredBit> {
    let length = a.len();
    let mut result = vec![CipheredBit::zero(); length];

    let mut partial_products = a
        .iter()
        .map(|ai| b.iter().map(|bj| ai.and(bj)).collect::<Vec<_>>())
        .collect::<Vec<_>>();

    let one_bit = CipheredBit::one();
    partial_products[0][length - 1] = partial_products[0][length - 1].xor(&one_bit);
    partial_products[length - 1][0] = partial_products[length - 1][0].xor(&one_bit);

    let mut carries = Vec::with_capacity((length - 1) * length * (length + 1) / 6);

    let mut offset = 0;
    for i in 0..length {
        let current_length = i * (i + 1) / 2;

        for (j, pj) in partial_products.iter().enumerate().take(i + 1) {
            let pp = &pj[i - j];
            if i + 1 < length {
                carries.push(pp.and(&result[i]));
            }
            result[i] = result[i].xor(pp);
        }

        debug_assert!(offset + current_length <= carries.len());
        for j in 0..current_length {
            if i + 1 < length {
                let t = result[i].and(&carries[offset + j]);
                carries.push(t);
            }
            result[i] = result[i].xor(&carries[offset + j]);
        }

        offset += current_length;
    }

    result
}

pub(super) fn mul_signed<T: crate::Encode + crate::Decode<()>>(
    a: &Ciphered<T>,
    b: &Ciphered<T>,
) -> Ciphered<T> {
    // Safety: output is built from valid bitwise homomorphic operations.
    unsafe { Ciphered::new_from_raw(mul_signed_internal(a, b)) }
}
