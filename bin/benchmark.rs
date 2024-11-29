
use sp_mac_eq_kvac::benchmark;

fn main() {
    println!("Benchmarking...");

    benchmark::benchmark_pairing_less::start_benchmarking();
}