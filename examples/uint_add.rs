use rand::{thread_rng, Rng};
use std::time::Instant;

use homomorph::prelude::*;
use homomorph_impls::numbers::HomomorphicAddition;

const NUMBER_OF_TESTS: usize = 1_000;

fn benchmark<F>(mut closure: F, name: &str, count: u32)
where
    F: FnMut(),
{
    let start = Instant::now();
    closure();
    let elapsed = start.elapsed();
    println!(
        "Time needed to {}: {:?} ({:?} per)",
        name,
        elapsed,
        elapsed / count
    );
}

fn main() {
    let mut rng = thread_rng();

    // Create a new context
    let params = Parameters::new(128, 128, 1, 128);
    let mut context = Context::new(params);
    context.generate_secret_key();
    context.generate_public_key();
    let sk = context.get_secret_key().unwrap();
    let pk = context.get_public_key().unwrap();

    // Generate random data
    let data1: Vec<_> = (0..NUMBER_OF_TESTS).map(|_| rng.gen::<u32>() / 2).collect();
    let data2: Vec<_> = (0..NUMBER_OF_TESTS).map(|_| rng.gen::<u32>() / 2).collect();

    let mut encrypted_data1: Vec<Ciphered<_>> = Vec::with_capacity(NUMBER_OF_TESTS);
    let mut encrypted_data2: Vec<Ciphered<_>> = Vec::with_capacity(NUMBER_OF_TESTS);

    let mut decrypted_data1: Vec<_> = Vec::with_capacity(NUMBER_OF_TESTS);
    let mut decrypted_data2: Vec<_> = Vec::with_capacity(NUMBER_OF_TESTS);

    let mut encrypted_data_add: Vec<Ciphered<_>> = Vec::with_capacity(NUMBER_OF_TESTS);
    let mut decrypted_data_add: Vec<_> = Vec::with_capacity(NUMBER_OF_TESTS);

    // Encrypt the data
    benchmark(
        || {
            for i in 0..NUMBER_OF_TESTS {
                encrypted_data1.push(Ciphered::cipher(&data1[i], pk));
                encrypted_data2.push(Ciphered::cipher(&data2[i], pk));
            }
        },
        "encrypt",
        2 * NUMBER_OF_TESTS as u32,
    );

    // Decrypt the data
    benchmark(
        || {
            for i in 0..NUMBER_OF_TESTS {
                decrypted_data1.push(Ciphered::decipher(&encrypted_data1[i], sk));
                decrypted_data2.push(Ciphered::decipher(&encrypted_data2[i], sk));
            }
        },
        "decrypt",
        2 * NUMBER_OF_TESTS as u32,
    );
    for i in 0..NUMBER_OF_TESTS {
        assert_eq!(decrypted_data1[i], data1[i]);
        assert_eq!(decrypted_data2[i], data2[i]);
    }

    // Perform the homomorphic operation
    benchmark(
        || {
            for i in 0..NUMBER_OF_TESTS {
                encrypted_data_add.push(unsafe {
                    HomomorphicAddition::apply(&encrypted_data1[i], &encrypted_data2[i])
                });
            }
        },
        "add",
        NUMBER_OF_TESTS as u32,
    );

    // Decrypt the result
    benchmark(
        || {
            for ec in &encrypted_data_add {
                decrypted_data_add.push(Ciphered::decipher(ec, sk));
            }
        },
        "decrypt added",
        NUMBER_OF_TESTS as u32,
    );
    for i in 0..NUMBER_OF_TESTS {
        assert_eq!(
            data1[i] + data2[i],
            decrypted_data_add[i],
            "Error at index {}: {} != {}",
            i,
            data1[i] + data2[i],
            decrypted_data_add[i]
        );
    }
}
