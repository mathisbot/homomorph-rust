use criterion::{criterion_group, criterion_main, Criterion};
use homomorph::prelude::*;
use homomorph_impls::numbers::HomomorphicAddition;

type Number = u32;

fn criterion_cipher(c: &mut Criterion) {
    const PARAMETERS: Parameters = Parameters::new(128, 128, 64, 128);
    let mut context = Context::new(PARAMETERS);
    context.generate_secret_key();
    context.generate_public_key().unwrap();
    let sk = context.get_secret_key().unwrap();
    let pk = context.get_public_key().unwrap();

    // Note that the number doesn't matter, the benchmark won't change
    let n1: Number = 42;

    let mut c1 = None;
    c.bench_function("cipher", |b| {
        b.iter(|| c1 = Some(Ciphered::cipher(&n1, pk)))
    });
    let c1 = c1.unwrap();

    let mut d = 0;
    c.bench_function("decipher", |b| b.iter(|| d = c1.decipher(sk)));

    assert_eq!(n1, d);
}

fn criterion_add(c: &mut Criterion) {
    const PARAMETERS: Parameters = Parameters::new(128, 128, 4, 128);
    let mut context = Context::new(PARAMETERS);
    context.generate_secret_key();
    context.generate_public_key().unwrap();
    let sk = context.get_secret_key().unwrap();
    let pk = context.get_public_key().unwrap();

    // Note that the number doesn't matter, the benchmark won't change
    let n1: Number = 22;
    let n2: Number = 20;

    let c1 = Ciphered::cipher(&n1, pk);
    let c2 = Ciphered::cipher(&n2, pk);

    let mut c3 = None;
    c.bench_function("add", |b| {
        b.iter(|| c3 = Some(unsafe { HomomorphicAddition::apply(&c1, &c2) }))
    });
    let c3 = c3.unwrap();

    // Decipher after an operation can be significantly slower than deciphering before
    // because usually the operation skyrockets the degree of the polynomial
    let mut d = 0;
    c.bench_function("decipher after add", |b| b.iter(|| d = c3.decipher(sk)));

    assert_eq!(n1 + n2, d);
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(core::time::Duration::from_secs(10));
    targets = criterion_cipher, criterion_add
);
criterion_main!(benches);
