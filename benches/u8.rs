use criterion::{criterion_group, criterion_main, Criterion};
use homomorph::prelude::*;
use homomorph::impls::numbers::HomomorphicMultiplication;

type Number = u8;

fn criterion_mul(c: &mut Criterion) {
    const PARAMETERS: Parameters = Parameters::new(128, 128, 1, 128);
    let mut context = Context::new(PARAMETERS);
    context.generate_secret_key();
    context.generate_public_key().unwrap();
    let sk = context.get_secret_key().unwrap();
    let pk = context.get_public_key().unwrap();

    // Note that the number doesn't matter, the benchmark won't change
    let n1: Number = 6;
    let n2: Number = 7;

    let c1 = Ciphered::cipher(&n1, pk);
    let c2 = Ciphered::cipher(&n2, pk);

    let mut c3 = None;
    c.bench_function("mul", |b| {
        b.iter(|| c3 = Some(unsafe { HomomorphicMultiplication::apply(&c1, &c2) }))
    });
    let c4 = c3.unwrap();

    // Decipher after an operation can be significantly slower than deciphering before
    // because usually the operation skyrockets the degree of the polynomial
    let mut d = 0;
    c.bench_function("decipher after mul", |b| b.iter(|| d = c4.decipher(sk)));
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(core::time::Duration::from_secs(10));
    targets = criterion_mul
);
criterion_main!(benches);
