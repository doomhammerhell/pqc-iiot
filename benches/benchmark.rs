use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqc_iiot::crypto::traits::{PqcKEM, PqcSignature};
use pqc_iiot::{Falcon, Kyber, KyberSecurityLevel};

fn bench_key_generation(c: &mut Criterion) {
    let kyber = Kyber::new();
    c.bench_function("key generation", |b| {
        b.iter(|| {
            let _ = kyber.generate_keypair().unwrap();
        })
    });
}

fn bench_encapsulation(c: &mut Criterion) {
    let kyber = Kyber::new();
    let (pk, _) = kyber.generate_keypair().unwrap();

    c.bench_function("encapsulation", |b| {
        b.iter(|| {
            let _ = kyber.encapsulate(&pk).unwrap();
        })
    });
}

fn bench_signature(c: &mut Criterion) {
    let falcon = Falcon::new();
    let (_pk, sk) = falcon.generate_keypair().unwrap();
    let message = black_box(b"Benchmark message");

    c.bench_function("signature", |b| {
        b.iter(|| {
            let _ = falcon.sign(&sk, message).unwrap();
        })
    });
}

fn bench_key_generation_kyber512(c: &mut Criterion) {
    let kyber = Kyber::new_with_level(KyberSecurityLevel::Kyber512);

    c.bench_function("key generation kyber512", |b| {
        b.iter(|| {
            let _ = kyber.generate_keypair().unwrap();
        })
    });
}

fn bench_key_generation_kyber1024(c: &mut Criterion) {
    let kyber = Kyber::new_with_level(KyberSecurityLevel::Kyber1024);

    c.bench_function("key generation kyber1024", |b| {
        b.iter(|| {
            let _ = kyber.generate_keypair().unwrap();
        })
    });
}

fn bench_verification(c: &mut Criterion) {
    let falcon = Falcon::new();
    let (pk, sk) = falcon.generate_keypair().unwrap();
    let message = black_box(b"Benchmark message");
    let signature = falcon.sign(&sk, message).unwrap();

    c.bench_function("verification", |b| {
        b.iter(|| {
            black_box(falcon.verify(&pk, message, &signature).unwrap());
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
