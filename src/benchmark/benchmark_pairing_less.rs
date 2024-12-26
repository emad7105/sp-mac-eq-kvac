use crate::benchmark::benchmark_utils::*;
use crate::protocols::kvac_pairing_less_bls12_381_g1::KvacPLBLS12;
use std::time::Instant;

const ITERATIONS: usize = 20;

pub fn start_benchmarking() {
    println!("Pairingless benchmark...\n");
    // S: attributes
    // D: subset, the first half of S (|s| = |D|/2)
    let S_sizes = vec![2usize.pow(4), 2usize.pow(6), 2usize.pow(8), 2usize.pow(10), 2usize.pow(12)];
    let D_sizes: Vec<usize> = S_sizes.iter().map(|&size| size / 2).collect();

    println!("(S_size, D_size): [Average execution time], [Output size]");

    benchmark_issue_cred(&S_sizes, &D_sizes);
    benchmark_obtain_cred(&S_sizes, &D_sizes);
    benchmark_show_cred(&S_sizes, &D_sizes);
    benchmark_verify_cred(&S_sizes, &D_sizes);
}

pub fn benchmark_issue_cred(S_sizes: &[usize], D_sizes: &[usize]) {
    println!("\nIssue_cred():\n------------");

    // 0. key gens
    let isk = KvacPLBLS12::gen_isk();
    let pp = KvacPLBLS12::gen_public_params(&isk);

    for (s_size, d_size) in S_sizes.iter().zip(D_sizes.iter()) {
        // println!("S_size: {}, D_size: {}", s_size, d_size);

        let S = prepare_set_S(s_size.clone());
        let D = prepare_set_D(d_size.clone(), &S);

        let mut total_time_ms = 0.0;
        let mut pre_cred_size = 0;
        let mut pre_cred_size_kb = 0.0;

        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let pre_cred = KvacPLBLS12::issue_cred(&pp, &S, &isk);
            let duration = start.elapsed();
            total_time_ms += duration.as_secs_f64() * 1000.0; // Convert to milliseconds

            pre_cred_size = KvacPLBLS12::size_of_pre_cred(&pre_cred);
            pre_cred_size_kb = pre_cred_size as f64 / 1024.0;
        }

        let average_time_ms = total_time_ms / ITERATIONS as f64;
        // println!("Average execution time: {:.3} ms", average_time_ms);
        println!("({}, {}): {:.3} ms, pre_cred: {} bytes ({:.3} KB)", s_size, d_size, average_time_ms, pre_cred_size, pre_cred_size_kb);
    }
}

pub fn benchmark_obtain_cred(S_sizes: &[usize], D_sizes: &[usize]) {
    println!("\nObtain_cred():\n------------");

    // 0. key gens
    let isk = KvacPLBLS12::gen_isk();
    let pp = KvacPLBLS12::gen_public_params(&isk);

    for (s_size, d_size) in S_sizes.iter().zip(D_sizes.iter()) {
        // println!("S_size: {}, D_size: {}", s_size, d_size);

        let S = prepare_set_S(s_size.clone());
        let D = prepare_set_D(d_size.clone(), &S);

        let mut total_time_ms = 0.0;
        let pre_cred = KvacPLBLS12::issue_cred(&pp, &S, &isk);
        let mut cred_size = 0;
        let mut cred_size_kb = 0.0;

        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let cred = KvacPLBLS12::obtain_cred(&pp, &pre_cred, &S);
            let duration = start.elapsed();
            total_time_ms += duration.as_secs_f64() * 1000.0; // Convert to milliseconds

            cred_size = KvacPLBLS12::size_of_credential(&cred);
            cred_size_kb = cred_size as f64 / 1024.0;
        }

        let average_time_ms = total_time_ms / ITERATIONS as f64;
        // println!("Average execution time: {:.3} ms", average_time_ms);
        println!("({}, {}): {:.3} ms, cred: {} bytes ({:.3} KB)", s_size, d_size, average_time_ms, cred_size, cred_size_kb);
    }
}

pub fn benchmark_show_cred(S_sizes: &[usize], D_sizes: &[usize]) {
    println!("\nShow_cred():\n------------");

    // 0. key gens
    let isk = KvacPLBLS12::gen_isk();
    let pp = KvacPLBLS12::gen_public_params(&isk);

    for (s_size, d_size) in S_sizes.iter().zip(D_sizes.iter()) {
        // println!("S_size: {}, D_size: {}", s_size, d_size);

        let S = prepare_set_S(s_size.clone());
        let D = prepare_set_D(d_size.clone(), &S);

        let mut total_time_ms = 0.0;
        let pre_cred = KvacPLBLS12::issue_cred(&pp, &S, &isk);
        let cred = KvacPLBLS12::obtain_cred(&pp, &pre_cred, &S);
        let mut show_size = 0;
        let mut show_size_kb = 0.0;

        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let show = KvacPLBLS12::show_cred(&pp, &cred, &S, &D);
            let duration = start.elapsed();
            total_time_ms += duration.as_secs_f64() * 1000.0; // Convert to milliseconds

            show_size = KvacPLBLS12::size_of_show(&show);
            show_size_kb = show_size as f64 / 1024.0;
        }

        let average_time_ms = total_time_ms / ITERATIONS as f64;
        // println!("Average execution time: {:.3} ms", average_time_ms);
        println!("({}, {}): {:.3} ms, show: {} bytes ({:.3} KB)", s_size, d_size, average_time_ms, show_size, show_size_kb);
    }
}


pub fn benchmark_verify_cred(S_sizes: &[usize], D_sizes: &[usize]) {
    println!("\nVerify_cred():\n------------");

    // 0. key gens
    let isk = KvacPLBLS12::gen_isk();
    let pp = KvacPLBLS12::gen_public_params(&isk);

    for (s_size, d_size) in S_sizes.iter().zip(D_sizes.iter()) {
        // println!("S_size: {}, D_size: {}", s_size, d_size);

        let S = prepare_set_S(s_size.clone());
        let D = prepare_set_D(d_size.clone(), &S);

        let mut total_time_ms = 0.0;
        let pre_cred = KvacPLBLS12::issue_cred(&pp, &S, &isk);
        let cred = KvacPLBLS12::obtain_cred(&pp, &pre_cred, &S);
        let show = KvacPLBLS12::show_cred(&pp, &cred, &S, &D);


        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let result = KvacPLBLS12::verify(&pp, &show, &D, &isk);
            let duration = start.elapsed();
            total_time_ms += duration.as_secs_f64() * 1000.0; // Convert to milliseconds
        }

        let average_time_ms = total_time_ms / ITERATIONS as f64;
        // println!("Average execution time: {:.3} ms", average_time_ms);
        println!("({}, {}): {:.3} ms", s_size, d_size, average_time_ms);
    }
}