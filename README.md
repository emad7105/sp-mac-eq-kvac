# Keyed-Verification Anonymous Credentials with Highly Efficient Partial Disclosure
This repository provides implementations for:  
- Both KVAC protocols in the paper [ref]
- ``SPS-EQ``: Structure-preserving signatures on equivalence classes (SPS-EQ)
- ``SP-MAC-EQ``: Structure-preserving message authentication codes on equivalence classes (SP-MAC-EQ)

The current implementation uses the curves:
- ``BLS12-381``
- ``Ed25517``
- ``Secp256k1``.  

All implementations can be found in: ``src/protocols``

# Benchmark
To run the benchmarks, it is better to build the project with "release" tag:

```shell
cargo build --release
./target/release/benchmark
```