use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use homomorph::impls::numbers::HomomorphicMultiplication;
use homomorph::prelude::*;

type Number = u8;

fn criterion_mul(c: &mut Criterion) {
    const PARAMETERS: Parameters = Parameters::new(128, 128, 1, 128);
    let mut context = Context::new(PARAMETERS);
    context.generate_secret_key();
    context.generate_public_key().unwrap();
    // Note that the number doesn't matter, the benchmark won't change
    let n1: Number = black_box(6);
    let n2: Number = black_box(7);

    let c1 = context.encrypt(&n1).unwrap();
    let c2 = context.encrypt(&n2).unwrap();

    let mut c3 = None;
    c.bench_function("mul", |b| {
        b.iter(|| {
            c3 = Some(
                context
                    .apply2::<HomomorphicMultiplication, _>(&c1, &c2)
                    .unwrap(),
            )
        })
    });
    let c4 = c3.unwrap();

    // Decipher after an operation can be significantly slower than deciphering before
    // because usually the operation skyrockets the degree of the polynomial
    let mut d = 0;
    c.bench_function("decipher after mul", |b| {
        b.iter(|| d = context.decrypt(&c4).unwrap())
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(core::time::Duration::from_secs(10));
    targets = criterion_mul
);
criterion_main!(benches);
