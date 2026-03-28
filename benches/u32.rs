use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use homomorph::impls::numbers::HomomorphicAddition;
use homomorph::prelude::*;

type Number = u32;

fn criterion_cipher(c: &mut Criterion) {
    const PARAMETERS: Parameters = Parameters::new(128, 128, 64, 128);
    let mut context = Context::new(PARAMETERS);
    context.generate_secret_key();
    context.generate_public_key().unwrap();
    // Note that the number doesn't matter, the benchmark won't change
    let n1: Number = black_box(42);

    let mut c1 = None;
    c.bench_function("cipher", |b| {
        b.iter(|| c1 = Some(context.encrypt(&n1).unwrap()))
    });
    let c1 = c1.unwrap();

    let mut d = 0;
    c.bench_function("decipher", |b| b.iter(|| d = context.decrypt(&c1).unwrap()));
}

fn criterion_add(c: &mut Criterion) {
    const PARAMETERS: Parameters = Parameters::new(128, 128, 4, 128);
    let mut context = Context::new(PARAMETERS);
    context.generate_secret_key();
    context.generate_public_key().unwrap();
    // Note that the number doesn't matter, the benchmark won't change
    let n1: Number = black_box(22);
    let n2: Number = black_box(20);

    let c1 = context.encrypt(&n1).unwrap();
    let c2 = context.encrypt(&n2).unwrap();

    let mut c3 = None;
    c.bench_function("add", |b| {
        b.iter(|| c3 = Some(context.apply2::<HomomorphicAddition, _>(&c1, &c2).unwrap()))
    });
    let c3 = c3.unwrap();

    // Decipher after an operation can be significantly slower than deciphering before
    // because usually the operation skyrockets the degree of the polynomial
    let mut d = 0;
    c.bench_function("decipher after add", |b| {
        b.iter(|| d = context.decrypt(&c3).unwrap())
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(core::time::Duration::from_secs(10));
    targets = criterion_cipher, criterion_add
);
criterion_main!(benches);
