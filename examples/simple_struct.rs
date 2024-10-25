//! This example runs perfectly on bare metal
//! (assuming there's an `alloc` crate)
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use homomorph::prelude::*;
use homomorph::impls::numbers::HomomorphicAddition;

type Coordinate = u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
struct Vec3 {
    x: Coordinate,
    y: Coordinate,
    z: Coordinate,
}

struct Vec3Add;

impl HomomorphicOperation2<Vec3> for Vec3Add {
    /// ## Safety
    ///
    /// `d/delta` on cipher must have been at least `21*sizeof::<Coordinates>()`.
    unsafe fn apply(a: &Ciphered<Vec3>, b: &Ciphered<Vec3>) -> Ciphered<Vec3> {
        // Unwrap the first `Vec3`
        let (ax, a) = a.split_at(Coordinate::BITS as usize);
        let (ay, az) = a.split_at(Coordinate::BITS as usize);
        let ax: Ciphered<Coordinate> = Ciphered::new_from_raw(ax.to_vec());
        let ay: Ciphered<Coordinate> = Ciphered::new_from_raw(ay.to_vec());
        let az: Ciphered<Coordinate> = Ciphered::new_from_raw(az.to_vec());

        // Unwrap the second `Vec3`
        let (bx, b) = b.split_at(Coordinate::BITS as usize);
        let (by, bz) = b.split_at(Coordinate::BITS as usize);
        let bx: Ciphered<Coordinate> = Ciphered::new_from_raw(bx.to_vec());
        let by: Ciphered<Coordinate> = Ciphered::new_from_raw(by.to_vec());
        let bz: Ciphered<Coordinate> = Ciphered::new_from_raw(bz.to_vec());

        // Perform the already implemented homomorphic addition over `Coordinate`
        let x = HomomorphicAddition::apply(&ax, &bx);
        let y = HomomorphicAddition::apply(&ay, &by);
        let z = HomomorphicAddition::apply(&az, &bz);

        // Merge the results
        let mut res = Vec::with_capacity(x.len() + y.len() + z.len());
        res.extend_from_slice(&x);
        res.extend_from_slice(&y);
        res.extend_from_slice(&z);

        Ciphered::new_from_raw(res)
    }
}

fn main() {
    const PARAMS: Parameters = Parameters::new(64, 32, 1, 32);
    let mut context = Context::new(PARAMS);
    context.generate_secret_key();
    context.generate_public_key().unwrap();
    let sk = context.get_secret_key().unwrap();
    let pk = context.get_public_key().unwrap();

    let a = Ciphered::cipher(&Vec3 { x: 1, y: 2, z: 3 }, pk);
    let b = Ciphered::cipher(&Vec3 { x: 4, y: 5, z: 6 }, pk);
    let c = unsafe { Vec3Add::apply(&a, &b) };
    let d = Ciphered::decipher(&c, sk);

    assert_eq!(Vec3 { x: 5, y: 7, z: 9 }, d);
}
