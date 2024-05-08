use rand::{self, Rng};
use std::time::Instant;
use rayon::prelude::*;

use homomorph::{self, Data, EncryptedData};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const DATA_SIZE: usize = 10_000;

fn main() {
    let mut rng = rand::thread_rng();

    // Create a new context with the following parameters
    let params = homomorph::Parameters::new(512, 128, 16, 256);
    let mut context = homomorph::Context::new(params);
    context.generate_secret_key();
    context.generate_public_key();
    
    // Generate random data
    let data1: Vec<Data> = (0..DATA_SIZE).map(|_| Data::from_usize(rng.gen::<usize>())).collect();
    let data2: Vec<Data> = (0..DATA_SIZE).map(|_| Data::from_usize(rng.gen::<usize>())).collect();

    // Encrypt the data
    let start = Instant::now();
    let encrypted_data1: Vec<EncryptedData> = data1.par_iter().map(|data| data.encrypt(&context)).collect();
    let elapsed = start.elapsed();
    println!("Time needed to encrypt {} data: {:?}", DATA_SIZE, elapsed);
    println!("Time needed to encrypt 1 data: {:?}", elapsed / DATA_SIZE as u32);
    let encrypted_data2: Vec<EncryptedData> = data2.par_iter().map(|data| data.encrypt(&context)).collect();

    // Perform the homomorphic operation
    let mut encrypted_data3: Vec<EncryptedData> = Vec::with_capacity(DATA_SIZE);
    let start = Instant::now();
    // Unparallelized operations for benchmarking
    for i in 0..DATA_SIZE {
        encrypted_data3.push(encrypted_data1[i].add_as_uint(&encrypted_data2[i]))
    }
    let elapsed = start.elapsed();
    println!("Time needed to perform {} homomorphic operations on encrypted data: {:?}", DATA_SIZE, elapsed);
    println!("Time needed to perform 1 homomorphic operation on encrypted data: {:?}", elapsed / DATA_SIZE as u32);

    // Decrypt the result
    let start = Instant::now();
    let decrypted_data: Vec<Data> = encrypted_data3.par_iter().map(|data| data.decrypt(&context)).collect();
    let elapsed = start.elapsed();
    println!("Time needed to decrypt {} data: {:?}", DATA_SIZE, elapsed);
    println!("Time needed to decrypt 1 data: {:?}", elapsed / DATA_SIZE as u32);

    // Check if the result is correct
    let data3: Vec<Data> = data1.par_iter().zip(data2.par_iter()).map(|(data1, data2)| data1.add_as_uint(&data2)).collect();
    for i in 0..DATA_SIZE {
        assert_eq!(decrypted_data[i].to_usize(), data3[i].to_usize());
    }
}
