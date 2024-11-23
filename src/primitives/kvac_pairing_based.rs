use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, Fr, FrConfig};
use std::ops::{AddAssign, Mul};
use ark_ec::pairing::Pairing;
use ark_ec::Group;
use ark_ff::{Field, Fp, Fp256, MontBackend};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use rand::{CryptoRng, Rng};
use ark_std::{UniformRand, Zero};
use ark_std::One;
use std::ops::Neg;
use ark_std::iterable::Iterable;
use std::collections::HashSet;
use crate::primitives::spmac_bls12_381::SpMacEq;


pub struct KvacPB {}


impl KvacPB {
    pub fn key_gen() {
        // let mut rng = ark_std::rand::thread_rng(); // todo
        //
        // SpMacEq::generate_key(2);
        //
        //
        // let x = ScalarField::rand(&mut rng);
    }

    pub fn gen_pp() {}
}