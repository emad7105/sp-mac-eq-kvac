use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, Fr};
use std::ops::Mul;
use ark_ec::pairing::Pairing;
use ark_ec::Group;
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use rand::{CryptoRng, Rng};
use ark_std::UniformRand;
use ark_std::One;
use std::ops::Neg;


pub struct Kvac {}

pub struct PublicParams {
    R: G1,
    X: G1,
    Vj: Vec<G1>,
    t: usize,
}

pub struct SecretKeys {
    x: ScalarField,
    v: ScalarField,
}


impl Kvac {
    pub fn gen_isk() -> SecretKeys {
        let mut rng = ark_std::rand::thread_rng(); // todo

        let x = ScalarField::rand(&mut rng);
        let v = ScalarField::rand(&mut rng);

        SecretKeys {
            x,
            v,
        }
    }

    pub fn gen_public_params(isk: &SecretKeys, t: usize) -> PublicParams {
        let mut rng = ark_std::rand::thread_rng();
        let r = ScalarField::rand(&mut rng);
        let G = G1::generator();
        // rG
        let R = G.mul(r);
        // rxG
        let X = R.mul(&isk.x);
        // {v_j*G} for j in [0...t]
        let mut Vj = vec![];
        for j in 0..t {
            let v_power_j = isk.v.pow([j as u64]);
            let vjG = G.mul(v_power_j);
            Vj.push(vjG);
        }

        PublicParams{
         R, X, Vj, t
        }
    }

    pub fn construct_f(x_set: &[ScalarField]) -> Vec<ScalarField> {
        // Initialize the polynomial f(x) = 1
        let mut f = DensePolynomial::from_coefficients_slice(&[ScalarField::one()]);

        // Multiply (x - x_i) for each s_i in S
        for xi in x_set {
            let poly_si = DensePolynomial::from_coefficients_slice(&[xi.neg(), ScalarField::one()]); // (x - x_i)
            // f = &f * &poly_si; // Multiply the polynomials
            f = (&f).naive_mul(&poly_si);
        }

        f.coeffs
    }
}


#[cfg(test)]
mod spmaceq_mac_tests {
    use crate::primitives::kvac::Kvac;
    use crate::primitives::kvac::ScalarField;

    #[test]
    fn test_construct_f() {
        let s = vec![ScalarField::from(2u64), ScalarField::from(10u64), ScalarField::from(3u64)];
        let s_permuted = vec![ScalarField::from(3u64), ScalarField::from(10u64), ScalarField::from(2u64)];

        let f_coeffs1 = Kvac::construct_f(&s);
        let f_coeffs2 = Kvac::construct_f(&s_permuted);

        assert_eq!(f_coeffs1, f_coeffs2);
    }

    #[test]
    fn test_key_gens() {
        let keys = Kvac::gen_isk();
        let public_params = Kvac::gen_public_params(&keys, 10);
    }
}