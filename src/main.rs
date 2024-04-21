use homomorph;
use rand::{self, Rng};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let params = homomorph::Parameters::new(512, 128, 16, 256);
    let mut context = homomorph::Context::new(params);
    context.generate_secret_key();
    context.generate_public_key();
    
    const N: usize = 100;
    let mut rng = rand::thread_rng();
    for _ in 0..N {
        let data1 = homomorph::Data::from_usize(rng.gen::<usize>());
        let data2 = homomorph::Data::from_usize(rng.gen::<usize>());

        let encrypted_data1 = data1.encrypt(&context);
        let encrypted_data2 = data2.encrypt(&context);

        let data3 = data1 + data2;
        let encrypted_data3 = encrypted_data1 + encrypted_data2;

        let decrypted_data = encrypted_data3.decrypt(&context);
        assert_eq!(data3.to_usize(), decrypted_data.to_usize());
    }
}
