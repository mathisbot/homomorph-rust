//! This example runs perfectly on bare metal
//! (assuming there's an `alloc` crate)
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use homomorph::prelude::*;

type Coordinate = u16;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Vec3 {
    x: Coordinate,
    y: Coordinate,
    z: Coordinate,
}

// If you don't want to implement `ByteConvertible` for your struct,
// use repr(C) and derive Copy
unsafe impl ByteConvertible for Vec3 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(3 * size_of::<Coordinate>());
        bytes.extend_from_slice(&self.x.to_le_bytes());
        bytes.extend_from_slice(&self.y.to_le_bytes());
        bytes.extend_from_slice(&self.z.to_le_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() != 3 * size_of::<Coordinate>() {
            panic!(
                "Invalid size of bytes for conversion: {} instead of {}",
                bytes.len(),
                3 * size_of::<Coordinate>()
            );
        }

        let x = u16::from_le_bytes([bytes[0], bytes[1]]);
        let y = u16::from_le_bytes([bytes[2], bytes[3]]);
        let z = u16::from_le_bytes([bytes[4], bytes[5]]);
        Vec3 { x, y, z }
    }
}

struct Vec3Add;

impl HomomorphicOperation2<Vec3> for Vec3Add {
    /// ## Safety
    ///
    /// `d/delta` on cipher must have been at least `21*sizeof::<Coordinates>()`.
    unsafe fn apply(a: &Ciphered<Vec3>, b: &Ciphered<Vec3>) -> Ciphered<Vec3> {
        // Unwrap the first `Vec3`
        let (ax, a) = a.split_at(Coordinate::BITS as usize);
        let ax: Ciphered<Coordinate> = Ciphered::new_from_raw(ax.to_vec());
        let (ay, az) = a.split_at(Coordinate::BITS as usize);
        let ay: Ciphered<Coordinate> = Ciphered::new_from_raw(ay.to_vec());
        let az: Ciphered<Coordinate> = Ciphered::new_from_raw(az.to_vec());

        // Unwrap the second `Vec3`
        let (bx, b) = b.split_at(Coordinate::BITS as usize);
        let bx: Ciphered<Coordinate> = Ciphered::new_from_raw(bx.to_vec());
        let (by, bz) = b.split_at(Coordinate::BITS as usize);
        let by: Ciphered<Coordinate> = Ciphered::new_from_raw(by.to_vec());
        let bz: Ciphered<Coordinate> = Ciphered::new_from_raw(bz.to_vec());

        // Perform already implemented homomorphic addition over `Coordinate` (`uint` is already implemented)
        let x = homomorph_impls::numbers::HomomorphicAddition::apply(&ax, &bx);
        let y = homomorph_impls::numbers::HomomorphicAddition::apply(&ay, &by);
        let z = homomorph_impls::numbers::HomomorphicAddition::apply(&az, &bz);

        assert_eq!(x.len(), Coordinate::BITS as usize);
        assert_eq!(y.len(), Coordinate::BITS as usize);
        assert_eq!(z.len(), Coordinate::BITS as usize);

        // Merge the results
        let mut res = Vec::with_capacity(8 * size_of::<Vec3>());
        res.extend_from_slice(x.as_slice());
        res.extend_from_slice(y.as_slice());
        res.extend_from_slice(z.as_slice());

        Ciphered::new_from_raw(res)
    }
}

fn main() {
    let params = Parameters::new(64, 32, 1, 32);
    let mut context = Context::new(params);
    context.generate_secret_key();
    context.generate_public_key();
    let sk = context.get_secret_key().unwrap();
    let pk = context.get_public_key().unwrap();

    let a = Ciphered::cipher(&Vec3 { x: 1, y: 2, z: 3 }, pk);
    let b = Ciphered::cipher(&Vec3 { x: 9, y: 8, z: 7 }, pk);
    let c = unsafe { Vec3Add::apply(&a, &b) };
    let d = Ciphered::decipher(&c, sk);

    assert_eq!(
        Vec3 {
            x: 10,
            y: 10,
            z: 10
        },
        d
    );
}
