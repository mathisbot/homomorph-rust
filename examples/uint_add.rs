use rand::{self, Rng};
use std::time::Instant;

use homomorph::{Ciphered, Context, HomomorphicAddition, HomomorphicOperation, Parameters};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const NUMBER_OF_TESTS: usize = 1_000;

fn main() {
    let mut rng = rand::thread_rng();

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

    // Encrypt the data
    let start = Instant::now();
    let encrypted_data1: Vec<Ciphered<_>> = data1
        .iter()
        .map(|&data| Ciphered::cipher(&data, pk))
        .collect();
    let elapsed = start.elapsed();
    println!(
        "Time needed to encrypt {} data: {:?}",
        NUMBER_OF_TESTS, elapsed
    );
    println!(
        "Time needed to encrypt 1 data: {:?}",
        elapsed / NUMBER_OF_TESTS as u32
    );
    let encrypted_data2: Vec<Ciphered<_>> = data2
        .iter()
        .map(|&data| Ciphered::cipher(&data, pk))
        .collect();

    // Decrypt the data
    let start = Instant::now();
    let decrypted_data: Vec<_> = encrypted_data1
        .iter()
        .map(|data| Ciphered::decipher(data, sk))
        .collect();
    let elapsed = start.elapsed();
    println!(
        "Time needed to decrypt {} data: {:?}",
        NUMBER_OF_TESTS, elapsed
    );
    println!(
        "Time needed to decrypt 1 data: {:?}",
        elapsed / NUMBER_OF_TESTS as u32
    );
    for i in 0..NUMBER_OF_TESTS {
        assert_eq!(decrypted_data[i], data1[i]);
    }

    // Perform the homomorphic operation
    let mut encrypted_data3: Vec<Ciphered<_>> = Vec::with_capacity(NUMBER_OF_TESTS);
    let start = Instant::now();
    for i in 0..NUMBER_OF_TESTS {
        encrypted_data3
            .push(unsafe { HomomorphicAddition::apply(&encrypted_data1[i], &encrypted_data2[i]) })
    }
    let elapsed = start.elapsed();
    println!(
        "Time needed to perform {} homomorphic additions on encrypted data: {:?}",
        NUMBER_OF_TESTS, elapsed
    );
    println!(
        "Time needed to perform 1 homomorphic addition on encrypted data: {:?}",
        elapsed / NUMBER_OF_TESTS as u32
    );

    // Decrypt the result
    let start = Instant::now();
    let decrypted_data_add: Vec<_> = encrypted_data3
        .iter()
        .map(|data| Ciphered::decipher(data, sk))
        .collect();
    let elapsed = start.elapsed();
    println!(
        "Time needed to decrypt {} processed data: {:?}",
        NUMBER_OF_TESTS, elapsed
    );
    println!(
        "Time needed to decrypt 1 data: {:?}",
        elapsed / NUMBER_OF_TESTS as u32
    );

    // Check if the results are correct
    let data3: Vec<_> = data1
        .iter()
        .zip(data2.iter())
        .map(|(&data1, &data2)| data1 + data2)
        .collect();
    for i in 0..NUMBER_OF_TESTS {
        assert_eq!(decrypted_data_add[i], data3[i]);
    }
}
