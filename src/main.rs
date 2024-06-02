use rand::{self, Rng};
use std::time::Instant;
use rayon::prelude::*;

use homomorph::{self, Data, EncryptedData};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const DATA_SIZE: usize = 100;

fn main() {
    let mut rng = rand::thread_rng();

    // Create a new context with the following parameters
    let params = homomorph::Parameters::new(512, 128, 8, 256);
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
        encrypted_data3.push(unsafe { encrypted_data1[i].add_as_uint(&encrypted_data2[i]) })
    }
    let elapsed = start.elapsed();
    println!("Time needed to perform {} homomorphic additions on encrypted data: {:?}", DATA_SIZE, elapsed);
    println!("Time needed to perform 1 homomorphic addition on encrypted data: {:?}", elapsed / DATA_SIZE as u32);

    // let mut encrypted_data4: Vec<EncryptedData> = Vec::with_capacity(DATA_SIZE);
    // let start = Instant::now();
    // // Unparallelized operations for benchmarking
    // for i in 0..DATA_SIZE {
    //     encrypted_data4.push(unsafe { encrypted_data1[i].mul_as_uint(&encrypted_data2[i]) })
    // }
    // let elapsed = start.elapsed();
    // println!("Time needed to perform {} homomorphic multiplications on encrypted data: {:?}", DATA_SIZE, elapsed);
    // println!("Time needed to perform 1 homomorphic multiplication on encrypted data: {:?}", elapsed / DATA_SIZE as u32);

    // Decrypt the result
    let start = Instant::now();
    let decrypted_data_add: Vec<Data> = encrypted_data3.par_iter().map(|data| data.decrypt(&context)).collect();
    let elapsed = start.elapsed();
    println!("Time needed to decrypt {} data: {:?}", DATA_SIZE, elapsed);
    println!("Time needed to decrypt 1 data: {:?}", elapsed / DATA_SIZE as u32);
    // let decrypted_data_mul: Vec<Data> = encrypted_data4.par_iter().map(|data| data.decrypt(&context)).collect();

    // Check if the results are correct
    let data3: Vec<Data> = data1.par_iter().zip(data2.par_iter()).map(|(data1, data2)| data1.add_as_uint(&data2)).collect();
    // let data4: Vec<Data> = data1.par_iter().zip(data2.par_iter()).map(|(data1, data2)| data1.mul_as_uint(&data2)).collect();
    for i in 0..DATA_SIZE {
        assert_eq!(decrypted_data_add[i].to_usize(), data3[i].to_usize());
        // assert_eq!(decrypted_data_mul[i].to_usize(), data4[i].to_usize());
    }
}
