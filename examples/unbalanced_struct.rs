//! This example runs perfectly on bare metal
//! (assuming there's an `alloc` crate)
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use homomorph::impls::numbers::HomomorphicAddition;
use homomorph::prelude::*;

// Notice that Rust will optimize the struct by reorganizing the fields in memory.
// This will not have any influence on the order of the fiels in `Ciphered<Unbalanced>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
struct Unbalanced {
    x: u8,
    y: u64,
    z: u8,
}

struct UnbalancedAdd;

impl HomomorphicOperation2<Unbalanced> for UnbalancedAdd {
    /// ## Safety
    ///
    /// `d/delta` on cipher must have been at least `21*sizeof::<u64>()`.
    unsafe fn apply(a: &Ciphered<Unbalanced>, b: &Ciphered<Unbalanced>) -> Ciphered<Unbalanced> {
        // Even if Rust has optimized the order of the fields in memory, they will remain
        // in the same order in the `Ciphered<Unbalanced>` struct.

        // Unwrap the first `Unbalanced`
        let (ax, a) = a.split_at(u8::BITS as usize);
        let (ay, az) = a.split_at(u64::BITS as usize);
        let ax: Ciphered<u8> = Ciphered::new_from_raw(ax.to_vec());
        let ay: Ciphered<u64> = Ciphered::new_from_raw(ay.to_vec());
        let az: Ciphered<u8> = Ciphered::new_from_raw(az.to_vec());

        // Unwrap the second `Unbalanced`
        let (bx, b) = b.split_at(u8::BITS as usize);
        let (by, bz) = b.split_at(u64::BITS as usize);
        let bx: Ciphered<u8> = Ciphered::new_from_raw(bx.to_vec());
        let by: Ciphered<u64> = Ciphered::new_from_raw(by.to_vec());
        let bz: Ciphered<u8> = Ciphered::new_from_raw(bz.to_vec());

        // Perform the already implemented homomorphic addition over `Coordinate`
        let x = HomomorphicAddition::apply(&ax, &bx);
        let y = HomomorphicAddition::apply(&ay, &by);
        let z = HomomorphicAddition::apply(&az, &bz);

        // Merge the results
        // Notice that here, the final size of the vector is not 8*sizeof::<Unbalanced>
        // but actually smaller.
        let mut res = Vec::with_capacity(x.len() + y.len() + z.len());
        res.extend_from_slice(&x);
        res.extend_from_slice(&y);
        res.extend_from_slice(&z);

        Ciphered::new_from_raw(res)
    }
}

fn main() {
    const PARAMS: Parameters = Parameters::new(128, 32, 1, 32);
    let mut context = Context::new(PARAMS);
    context.generate_secret_key();
    context.generate_public_key().unwrap();
    let sk = context.get_secret_key().unwrap();
    let pk = context.get_public_key().unwrap();

    let a = Ciphered::cipher(&Unbalanced { x: 1, y: 2, z: 3 }, pk);
    let b = Ciphered::cipher(&Unbalanced { x: 4, y: 5, z: 6 }, pk);
    let c = unsafe { UnbalancedAdd::apply(&a, &b) };
    let d = Ciphered::decipher(&c, sk);

    assert_eq!(Unbalanced { x: 5, y: 7, z: 9 }, d);
}
