use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqc_iiot::{Falcon, Kyber};

fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("key generation", |b| {
        b.iter(|| {
            let kyber = Kyber::new();
            let _ = kyber.generate_keypair().unwrap();
        })
    });
}

fn bench_encapsulation(c: &mut Criterion) {
    c.bench_function("encapsulation", |b| {
        b.iter(|| {
            let kyber = Kyber::new();
            let (pk, _) = kyber.generate_keypair().unwrap();
            let _ = kyber.encapsulate(&pk).unwrap();
        })
    });
}

fn bench_signature(c: &mut Criterion) {
    c.bench_function("signature", |b| {
        b.iter(|| {
            let falcon = Falcon::new();
            let message = black_box(b"Benchmark message");
            let _ = falcon.sign(message, &[]).unwrap();
        })
    });
}

fn bench_key_generation_kyber512(c: &mut Criterion) {
    c.bench_function("key generation kyber512", |b| {
        b.iter(|| {
            let kyber = Kyber::new_kyber512();
            let _ = kyber.generate_keypair().unwrap();
        })
    });
}

fn bench_key_generation_kyber1024(c: &mut Criterion) {
    c.bench_function("key generation kyber1024", |b| {
        b.iter(|| {
            let kyber = Kyber::new_kyber1024();
            let _ = kyber.generate_keypair().unwrap();
        })
    });
}

fn bench_verification(c: &mut Criterion) {
    c.bench_function("verification", |b| {
        b.iter(|| {
            let falcon = Falcon::new();
            let message = black_box(b"Benchmark message");
            let signature = falcon.sign(message, &[]).unwrap();
            let _ = falcon.verify(message, &signature, &[]).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_encapsulation,
    bench_signature,
    bench_key_generation_kyber512,
    bench_key_generation_kyber1024,
    bench_verification
);
criterion_main!(benches);
