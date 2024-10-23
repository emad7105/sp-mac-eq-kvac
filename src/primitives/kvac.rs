use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, Fr, FrConfig};
use std::ops::Mul;
use ark_ec::pairing::Pairing;
use ark_ec::Group;
use ark_ff::{Field, Fp, Fp256, MontBackend};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use rand::{CryptoRng, Rng};
use ark_std::UniformRand;
use ark_std::One;
use std::ops::Neg;
use ark_std::iterable::Iterable;


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

pub struct PoK {

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

    /// Outputs (tau, {Y_j} for j in [|S|], PoK)
    pub fn issue_cred(pp: &PublicParams, S: &[ScalarField], isk: SecretKeys) -> (G1, Vec<G1>,PoK)  {

        // 1. parse (x,v) from isk
        // 2. y <--Z_p
        let mut rng = ark_std::rand::thread_rng();
        let y = ScalarField::rand(&mut rng);
        // 3. C <- y * f_S(v)G
        // calculate f_S = (x-s1)*(x-s2)...(x-sn) the vanishing polynomial
        let f_S = Kvac::construct_f(S);
        // f_S(v)
        let f_S_evaluated_at_v = f_S.evaluate(&isk.v);
        // y * f_S(v) G
        let G = G1::generator();
        let x: Fp256<MontBackend<FrConfig, 4>>  = y * f_S_evaluated_at_v;
        let C = G.mul(x);
        // tau = x*C
        let tau = C.mul(isk.x);
        // (Y_j = y*V_j) for j in [|S|]
        let mut Yj = vec![];
        for i in 0..S.len() {
            let V_j: &G1 = pp.Vj.get(i).expect("Vj is missing");
            let yV_j = V_j.mul(&y);
            Yj.push(yV_j);
        }

        // todo: PoK

        (tau, Yj, PoK{})
    }
}


#[cfg(test)]
mod spmaceq_mac_tests {
    use ark_std::UniformRand;
    use crate::primitives::kvac::Kvac;
    use crate::primitives::kvac::ScalarField;

    #[test]
    fn test_construct_f() {
        let s = vec![ScalarField::from(2u64), ScalarField::from(10u64), ScalarField::from(3u64)];
        let s_permuted = vec![ScalarField::from(3u64), ScalarField::from(10u64), ScalarField::from(2u64)];

        let f1 = Kvac::construct_f(&s);
        let f2 = Kvac::construct_f(&s_permuted);

        assert_eq!(f1.coeffs, f2.coeffs);
    }

    #[test]
    fn test_key_gens() {
        let keys = Kvac::gen_isk();
        let public_params = Kvac::gen_public_params(&keys, 10);
    }

    #[test]
    fn test_Kvac_flow() {
        let secret_keys = Kvac::gen_isk();
        let public_params = Kvac::gen_public_params(&secret_keys, 20);

        let S = prepare_set_S(20);

        Kvac::issue_cred(&public_params, &S, secret_keys);
    }

    // this prepares a random set S of attributes for testing purposes
    fn prepare_set_S(size: usize) -> Vec<ScalarField> {
        let mut rng = ark_std::rand::thread_rng();
        let mut S = vec![];
        for i in 0..size {
            let r = ScalarField::rand(&mut rng);
            S.push(r);
        }
        S
    }

    // for calculating f_{S\D}
    fn pick_subset_excluding_first(S: Vec<ScalarField>, D: usize) -> Vec<ScalarField> {
        // Take the subset excluding the first D elements
        let subset = &S[D..];
        subset.into()
    }
}