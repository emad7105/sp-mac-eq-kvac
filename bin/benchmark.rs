
use sp_mac_eq_kvac::benchmark;

fn main() {
    println!("Benchmarking...");

    benchmark::benchmark_spmac_spseq::start_benchmarking();
    // benchmark::benchmark_pairing_less::start_benchmarking();
    // benchmark::benchmark_paring_based::start_benchmarking()
}