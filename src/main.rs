use homomorph;
use rand::{self, Rng};

fn main() {
    let params = homomorph::Parameters::new(128, 128, 64, 128);
    let mut context = homomorph::Context::new(params);

    let mut rng = rand::thread_rng();
    const N: usize = 128;
    for i in 0..N {
        context.generate_secret_key(&mut rng);
        context.generate_public_key(&mut rng);

        let data = homomorph::Data::from_usize(rng.gen());
        let encrypted_data = data.encrypt(&context.get_public_key().unwrap(), &mut rng);
        let decrypted_data = encrypted_data.decrypt(&context.get_secret_key().unwrap());
        if data.to_usize() != decrypted_data.to_usize() {
            println!("O : {} -- D : {}", data.to_usize(), decrypted_data.to_usize());
        } else {
            println!("OK {}", i);
        }
    }
}
