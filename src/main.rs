use homomorph;
use rand::{self, Rng};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let params = homomorph::Parameters::new(256, 256, 128, 256);
    let mut context = homomorph::Context::new(params);

    let mut rng = rand::thread_rng();
    const N: usize = 1024;
    for _ in 0..N {
        context.generate_secret_key(&mut rng);
        context.generate_public_key(&mut rng);

        let data = homomorph::Data::from_usize(rng.gen::<usize>());
        let encrypted_data = data.encrypt(&context.get_public_key().unwrap());
        let decrypted_data = encrypted_data.decrypt(&context.get_secret_key().unwrap());
        if data.to_usize() != decrypted_data.to_usize() {
            println!("Expected : {} -- Got : {}", data.to_usize(), decrypted_data.to_usize());
        }
    }
}
