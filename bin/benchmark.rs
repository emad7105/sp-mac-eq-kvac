
use sp_mac_eq_kvac::benchmark;

fn main() {
    println!("Benchmarking...");

    // benchmark::benchmark_spmac_spseq::start_benchmarking();
    benchmark::benchmark_pairing_less_bls12_381_g1::start_benchmarking();
    benchmark::benchmark_pairing_less_ed25519::start_benchmarking();
    // benchmark::benchmark_paring_based::start_benchmarking()
}