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


pub struct Kvac {}

pub struct PublicParams {
    R: G1,
    X: G1,
    V: G1,
    // Vj: Vec<G1>,
    // t: usize,
}

pub struct SecretKeys {
    x: ScalarField,
    v: ScalarField,
}

pub struct PreCredential {
    tau: G1,
    Yj: Vec<G1>,
    pok: PoK,
}


pub struct Credential {
    C: G1,
    tau: G1,
    Yj: Vec<G1>,
}

pub struct PoK {}

pub struct Show {
    tau_prime: G1,
    W: G1,
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
        // vG
        let V = G.mul(&isk.v);
        // {v_j*G} for j in [0...t]
        // let mut Vj = vec![];
        // for j in 0..t {
        //     let v_power_j = isk.v.pow([j as u64]);
        //     let vjG = G.mul(v_power_j);
        //     Vj.push(vjG);
        // }

        PublicParams {
            R,
            X,
            V,//Vj, t
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

    pub fn evaluate_f_at_secret_point(f_coeffs: &[ScalarField], Yj: &[G1]) -> G1 {
        let mut eval = G1::zero();
        for i in 1..f_coeffs.len() {
            let f_coeff: &ScalarField = f_coeffs.get(i).expect("missing coeff");
            let Y_j: &G1 = Yj.get(i.clone() - 1).expect("missing Yj");
            eval.add_assign(Y_j.mul(f_coeff));
        }
        eval
    }

    /// Outputs (tau, {Y_j} for j in [|S|], PoK)
    pub fn issue_cred(pp: &PublicParams, S: &[ScalarField], isk: &SecretKeys) -> PreCredential {

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
        let yf: Fp256<MontBackend<FrConfig, 4>> = y * f_S_evaluated_at_v;
        let C = G.mul(yf);
        // tau = x*C
        let tau = C.mul(&isk.x);
        // (Y_j = y*V_jG) for j in [|S|]
        let mut Yj = vec![];
        for j in 0..S.len() {
            let v_power_j = isk.v.pow([j as u64]);
            let yvj: Fp256<MontBackend<FrConfig, 4>> = v_power_j * y.clone();
            let yvjG = G.mul(yvj);
            Yj.push(yvjG);
        }

        // todo: PoK

        PreCredential {
            tau,
            Yj,
            pok: PoK {},
        }
    }

    pub fn obtain_cred(pp: &PublicParams, pre_cred: &PreCredential, pok: &PoK, S: &[ScalarField]) -> Credential {
        // C <-- y * f_S(v) G
        let f = Kvac::construct_f(&S);
        let C_recalculated = Kvac::evaluate_f_at_secret_point(&f.coeffs, &pre_cred.Yj);

        // Check PoK
        // todo

        Credential {
            C: C_recalculated,
            tau: pre_cred.tau.clone(),
            Yj: pre_cred.Yj.to_vec(),
        }
    }


    /// to calcluate the vec that is S\D
    fn difference<S: Eq + std::hash::Hash + Clone>(s: &[S], d: &[S]) -> Vec<S> {
        let d_set: HashSet<_> = d.iter().collect();
        s.iter().filter(|x| !d_set.contains(x)).cloned().collect()
    }

    pub fn show_cred(pp: &PublicParams, cred: &Credential, S: &[ScalarField], D: &[ScalarField]) -> Show {
        // miu <-- Zp
        let mut rng = ark_std::rand::thread_rng();
        let miu = ScalarField::rand(&mut rng);

        // S\D
        let S_without_D = Kvac::difference(S, D);
        // f_{S\D}
        let f = Kvac::construct_f(&S_without_D);
        let yf = Kvac::evaluate_f_at_secret_point(&f.coeffs, &cred.Yj);

        // W <-- miu_y_f
        let W = yf.mul(miu);

        // Tau' <-- tau * miu
        let tau_prime = cred.tau.mul(miu.clone());

        Show {
            tau_prime,
            W,
        }
    }

    pub fn verify(pp: &PublicParams, show: &Show, D: &[ScalarField], isk: &SecretKeys ) -> bool {
        // xWf_D(v) == tau_prime
        // f_D(x)
        let f_D = Kvac::construct_f(D);
        // f_D(v)
        let f_D_evaluated_at_v = f_D.evaluate(&isk.v);
        // Wf_D(v)
        let Wf_D_evaluated_at_v  = show.W.mul(f_D_evaluated_at_v);
        // xWf_D(v)
        let xWf_D_evaluated_at_v = Wf_D_evaluated_at_v.mul(&isk.x);

        // (xWf_D(v) == tau_prime) && (tau_prime != 0G)
        xWf_D_evaluated_at_v.eq(&show.tau_prime) && (!show.tau_prime.eq(&G1::zero()))
    }
}


#[cfg(test)]
mod spmaceq_mac_tests {
    use std::ops::Mul;
    use ark_bls12_381::FrConfig;
    use ark_ec::Group;
    use ark_ff::{Fp256, MontBackend};
    use ark_poly::Polynomial;
    use ark_std::UniformRand;
    use crate::primitives::kvac_pairing_less::Kvac;
    use crate::primitives::kvac_pairing_less::ScalarField;
    use crate::primitives::kvac_pairing_less::G1;

    #[test]
    fn test_kvac_full_flow_test() {
        // 0. key gens
        let isk = Kvac::gen_isk();
        let pp = Kvac::gen_public_params(&isk, 20);

        // attribute sets
        let S = prepare_set_S(20);
        let D: Vec<ScalarField> = S.iter().take(8).cloned().collect();

        // 1. KVAC.issue_cred(pp, S, isk, ipar)
        let pre_cred = Kvac::issue_cred(&pp, &S, &isk);

        // 2. KVAC.obtain_cred(pp, PreCred, S, ipar)
        let cred = Kvac::obtain_cred(&pp, &pre_cred, &pre_cred.pok, &S);

        // 3. KVAC.show_cred(pp, Cred, S, D)
        let show = Kvac::show_cred(&pp, &cred, &S, &D);

        // 4. KVAC.verify(pp, Show, D, isk)
        let result = Kvac::verify(&pp, &show, &D, &isk);

        assert_eq!(result, true);
    }

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
    fn test_evaluations() {
        let secret_keys = Kvac::gen_isk();
        let public_params = Kvac::gen_public_params(&secret_keys, 20);

        let S = prepare_set_S(20);

        let pre_cred = Kvac::issue_cred(&public_params, &S, &secret_keys);

        // expected C
        let mut rng = ark_std::rand::thread_rng();
        let y = ScalarField::rand(&mut rng);
        let f_S = Kvac::construct_f(&S);
        let f_S_evaluated_at_v = f_S.evaluate(&secret_keys.v);
        let G = G1::generator();
        let x: Fp256<MontBackend<FrConfig, 4>> = y * f_S_evaluated_at_v;
        let C_expected = G.mul(x);

        let C = Kvac::evaluate_f_at_secret_point(&f_S.coeffs, &pre_cred.Yj);

        // bad test
        //assert_eq!(C, C_expected)
    }

    #[test]
    fn test_Kvac_flow() {
        let secret_keys = Kvac::gen_isk();
        let public_params = Kvac::gen_public_params(&secret_keys, 20);

        let S = prepare_set_S(20);

        let pre_cred = Kvac::issue_cred(&public_params, &S, &secret_keys);
        let credential = Kvac::obtain_cred(&public_params, &pre_cred, &pre_cred.pok, &S);
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