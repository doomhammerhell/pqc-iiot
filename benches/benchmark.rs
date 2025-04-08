extern crate test;

use pqc_iiot::{Falcon, Kyber};
use test::Bencher;

#[bench]
fn bench_key_generation(b: &mut Bencher) {
    let kyber = Kyber::new();
    b.iter(|| {
        let _ = kyber.generate_keypair().unwrap();
    });
}

#[bench]
fn bench_encapsulation(b: &mut Bencher) {
    let kyber = Kyber::new();
    let (pk, _sk) = kyber.generate_keypair().unwrap();
    b.iter(|| {
        let _ = kyber.encapsulate(&pk).unwrap();
    });
}

#[bench]
fn bench_decapsulation(b: &mut Bencher) {
    let kyber = Kyber::new();
    let (pk, sk) = kyber.generate_keypair().unwrap();
    let (ct, _ss) = kyber.encapsulate(&pk).unwrap();
    b.iter(|| {
        let _ = kyber.decapsulate(&sk, &ct).unwrap();
    });
}

#[bench]
fn bench_signature(b: &mut Bencher) {
    let falcon = Falcon::new();
    let (_pk, sk) = falcon.generate_keypair().unwrap();
    let message = b"Benchmark message";
    b.iter(|| {
        let _ = falcon.sign(message, &sk).unwrap();
    });
}

#[bench]
fn bench_verification(b: &mut Bencher) {
    let falcon = Falcon::new();
    let (pk, sk) = falcon.generate_keypair().unwrap();
    let message = b"Benchmark message";
    let signature = falcon.sign(message, &sk).unwrap();
    b.iter(|| {
        assert!(falcon.verify(message, &signature, &pk).is_ok());
    });
}
