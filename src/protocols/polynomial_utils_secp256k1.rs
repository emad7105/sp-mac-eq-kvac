use std::collections::HashSet;
use std::ops::{Add, Mul, Neg};
use ark_ec::PrimeGroup;
use ark_secp256k1::{Fr as ScalarField, Projective as G};
use ark_std::{One, UniformRand, Zero};
use ark_secp256k1::FrConfig;
use ark_ff::{Fp, Fp256, MontBackend};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_poly::univariate::DensePolynomial;


pub fn evaluate_f_at_v_without_interpolation(x_set: &[ScalarField], v: &ScalarField) -> ScalarField {
    // ∏ (v - x_i)
    let mut prod = ScalarField::one();

    for xi in x_set {
        prod = prod * (v - xi);
    }

    prod
}

pub fn evaluate_f_at_secret_point(f_coeffs: &[ScalarField], Yj: &[G]) -> G {
    let mut eval = G::zero();
    for j in 0..f_coeffs.len() {
        let Y_j: &G = Yj.get(j).expect("missing Yj");
        let f_coeff: &ScalarField = f_coeffs.get(j).expect("missing coeff");
        eval = eval.add(&Y_j.mul(*f_coeff));
    }
    eval
}

pub fn construct_f(x_set: &[ScalarField]) -> DensePolynomial<Fp<MontBackend<FrConfig, 4>, 4>> {
    // Initialize the polynomial f(x) = 1
    let mut f = DensePolynomial::from_coefficients_slice(&[ScalarField::one()]);

    // Multiply (x - x_i) for each s_i in S
    for xi in x_set {
        let poly_si = DensePolynomial::from_coefficients_slice(&[xi.neg(), ScalarField::one()]); // (x - x_i)
        // f = &f * &poly_si; // Multiply the polynomials
        f = (&f).naive_mul(&poly_si);
    }

    f
}


/// to calcluate the vec that is S\D
pub fn difference<S: Eq + std::hash::Hash + Clone>(s: &[S], d: &[S]) -> Vec<S> {
    let d_set: HashSet<_> = d.iter().collect();
    s.iter().filter(|x| !d_set.contains(x)).cloned().collect()
}