use std::time::{Duration, Instant};
use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, Fr};
use ark_ec::PrimeGroup;
use std::ops::Mul;
use ark_std::UniformRand;
use crate::protocols::spmac_bls12_381::SpMacEq;
use crate::protocols::spseq_bls12_381::SpsEqSignature;

pub fn start_benchmarking() {
    println!("Benchmarking SPS-EQ and SP-MAC");
    println!("\n\nSPS.EQ.Sign:\n");
    bench_sps_eq_sign_all();

    println!("\n\nSP.Mac:\n");
    bench_sp_mac_all();

    // println!("\n\nSPS.EQ.Verify:\n");
    // bench_sps_eq_verify_all();
    //
    // println!("\n\nSP.Mac.Verify:\n");
    // bench_sp_mac_verify_all();

}

fn bench_sp_mac_verify_all() {
    let mut l = 2;
    bench_sp_mac_verify(l, "2^1");

    l = 8;
    bench_sp_mac_verify(l, "2^3");

    l = 32;
    bench_sp_mac_verify(l, "2^5");

    l = 128;
    bench_sp_mac_verify(l, "2^7");

    l = 512;
    bench_sp_mac_verify(l, "2^9");

    l = 2048;
    bench_sp_mac_verify(l, "2^11");

    // l = 8192;
    // bench_sp_mac_verify(l, "2^13");
}

fn bench_sp_mac_all() {
    let mut l = 2;
    bench_sp_mac(l, "2^1");

    l = 8;
    bench_sp_mac(l, "2^3");

    l = 32;
    bench_sp_mac(l, "2^5");

    l = 128;
    bench_sp_mac(l, "2^7");

    l = 512;
    bench_sp_mac(l, "2^9");

    l = 2048;
    bench_sp_mac(l, "2^11");

    // l = 8192;
    // bench_sp_mac(l, "2^13");
}

fn bench_sps_eq_sign_all() {
    let mut l = 2;
    bench_sps_eq_sign(l, "2^1");

    l = 8;
    bench_sps_eq_sign(l, "2^3");

    l = 32;
    bench_sps_eq_sign(l, "2^5");

    l = 128;
    bench_sps_eq_sign(l, "2^7");

    l = 512;
    bench_sps_eq_sign(l, "2^9");

    l = 2048;
    bench_sps_eq_sign(l, "2^11");

    // l = 8192;
    // bench_sps_eq_sign(l, "2^13");
}

fn bench_sps_eq_verify_all() {
    let mut l = 2;
    // bench_sps_eq_verify(l, "2^1");
    //
    // l = 8;
    // bench_sps_eq_verify(l, "2^3");
    //
    // l = 32;
    // bench_sps_eq_verify(l, "2^5");
    //
    // l = 128;
    // bench_sps_eq_verify(l, "2^7");

    l = 512;
    bench_sps_eq_verify(l, "2^9");

    l = 2048;
    bench_sps_eq_verify(l, "2^11");

    // l = 8192;
    // bench_sps_eq_verify(l, "2^13");
}

fn bench_sp_mac(l: usize, l_desc: &str) {
    let key_pair = SpsEqSignature::generate_key_test(l);
    let mut rng = ark_std::test_rng();
    let messages = vec![G1::generator().mul(ScalarField::rand(&mut rng)); l];

    let times = 200;

    let mut total_time = Duration::new(0, 0);
    for i in 0..times {
        let loop_start = Instant::now();

        SpMacEq::mac_test(&key_pair.sk, &messages);

        let loop_time = loop_start.elapsed();
        total_time += loop_time;
        // if i % 1000 == 0 {//.mod_floor(&_times_limit) == 0 {
        //     println!("{:?} x 1000 processed", total_processed);
        //     total_processed += 1;
        // }
    }

    let average_time = total_time / times;
    let millis = average_time.as_secs_f64() * 1000.0;
    println!("Average execution time for l={:?}: {:.2} milliseconds", l_desc, millis);
}


fn bench_sp_mac_verify(l: usize, l_desc: &str) {
    let key_pair = SpsEqSignature::generate_key_test(l);
    let mut rng = ark_std::test_rng();
    let messages = vec![G1::generator().mul(ScalarField::rand(&mut rng)); l];

    let times = 200;

    let mac = SpMacEq::mac_test(&key_pair.sk, &messages);

    let mut total_time = Duration::new(0, 0);
    for i in 0..times {
        let loop_start = Instant::now();

        //SpMacEq::mac_test(&key_pair.sk, &messages);
        SpMacEq::verify(&key_pair.sk, &mac, &messages);

        let loop_time = loop_start.elapsed();
        total_time += loop_time;
        // if i % 1000 == 0 {//.mod_floor(&_times_limit) == 0 {
        //     println!("{:?} x 1000 processed", total_processed);
        //     total_processed += 1;
        // }
    }

    let average_time = total_time / times;
    let millis = average_time.as_secs_f64() * 1000.0;
    println!("Average execution time for l={:?}: {:.2} milliseconds", l_desc, millis);
}


fn bench_sps_eq_sign(l: usize, l_desc: &str) {
    let key_pair = SpsEqSignature::generate_key_test(l);
    let mut rng = ark_std::test_rng();
    let messages = vec![G1::generator().mul(ScalarField::rand(&mut rng)); l];

    let times = 200;

    let mut total_time = Duration::new(0, 0);
    for i in 0..times {
        let loop_start = Instant::now();

        SpsEqSignature::sign_test(&key_pair.sk, &messages);

        let loop_time = loop_start.elapsed();
        total_time += loop_time;
        // if i % 1000 == 0 {//.mod_floor(&_times_limit) == 0 {
        //     println!("{:?} x 1000 processed", total_processed);
        //     total_processed += 1;
        // }
    }

    let average_time = total_time / times;
    let millis = average_time.as_secs_f64() * 1000.0;
    println!("Average execution time for l={:?}: {:.2} milliseconds", l_desc, millis);
}

fn bench_sps_eq_verify(l: usize, l_desc: &str) {
    let key_pair = SpsEqSignature::generate_key_test(l);
    let mut rng = ark_std::test_rng();
    let messages = vec![G1::generator().mul(ScalarField::rand(&mut rng)); l];

    let times = 200;

    let sig = SpsEqSignature::sign_test(&key_pair.sk, &messages);

    let mut total_time = Duration::new(0, 0);
    for i in 0..times {
        let loop_start = Instant::now();

        //SpsEqSignature::sign_test(&key_pair.sk, &messages);
        SpsEqSignature::verify(&key_pair.vk, &sig, &messages);

        let loop_time = loop_start.elapsed();
        total_time += loop_time;
        // if i % 1000 == 0 {//.mod_floor(&_times_limit) == 0 {
        //     println!("{:?} x 1000 processed", total_processed);
        //     total_processed += 1;
        // }
    }

    let average_time = total_time / times;
    let millis = average_time.as_secs_f64() * 1000.0;
    println!("Average execution time for l={:?}: {:.2} milliseconds", l_desc, millis);
}