# Keyed-Verification Anonymous Credentials with Highly Efficient Partial Disclosure
This repository provides implementations for:  
- Both KVAC protocols in the [paper](https://eprint.iacr.org/2025/41).
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

# Team 
* [Omid Mirzamohammadi](https://www.esat.kuleuven.be/cosic/people/person/?u=u0159898)
* [Emad Heydari Beni](https://heydari.be)
* [Jan Bobolz](https://jan-bobolz.de/)
* [Mahdi Sedaghat](https://mahdi171.github.io/)
* Aysajan Abidin
* Dave Singelee
* [Bart Preneel](https://www.esat.kuleuven.be/cosic/people/person/?u=u0003308)
