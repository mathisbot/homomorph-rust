use homomorph;
use rand::{self, Rng};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let params = homomorph::Parameters::new(512, 128, 16, 256);
    let mut context = homomorph::Context::new(params);
    let mut rng = rand::thread_rng();
    context.generate_secret_key(&mut rng);
    context.generate_public_key(&mut rng);

    const N: usize = 10000;
    for _ in 0..N {
        let data1 = homomorph::Data::from_usize(rng.gen::<usize>());
        let data2 = homomorph::Data::from_usize(rng.gen::<usize>());
        let encrypted_data1 = data1.encrypt(&context.get_public_key().unwrap());
        let encrypted_data2 = data2.encrypt(&context.get_public_key().unwrap());
        let data3 = data1 + data2;
        let encrypted_data3 = encrypted_data1 + encrypted_data2;
        let decrypted_data = encrypted_data3.decrypt(&context.get_secret_key().unwrap());
        assert_eq!(data3.to_usize(), decrypted_data.to_usize());
    }
}
