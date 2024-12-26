use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, Fr, FrConfig};
use std::ops::{AddAssign, Mul, Sub};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, Fp, Fp256, MontBackend, PrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use rand::{CryptoRng, Rng};
use ark_std::{UniformRand, Zero};
use ark_std::One;
use std::ops::Neg;
use ark_std::iterable::Iterable;
use std::collections::HashSet;
use crate::protocols::kvac_pairing_less_bls12_381_g1::KvacPLBLS12;
use crate::protocols::spmac_bls12_381::SpMacEq;
use std::ops::Add;
use ark_serialize::CanonicalSerialize;
use sha2::{Sha256,Digest};


pub struct Dvsc {}

pub struct Witness {
    v: ScalarField
}

pub struct PoK {
    c: ScalarField,
    s_v: ScalarField
}

pub struct DvscSetupParams {
    G: G1,
    G_prime: G1,
}

pub struct DvscSk {
    pub sk: ScalarField
}

pub struct DvscPublicParam {
    Vj: Vec<G1>,
    pok: PoK
}

pub struct Commitment {
    pub fs_evaluated_at_v_G: G1,
    pub G_prime: G1,
}

impl Dvsc{

    pub fn setup() -> DvscSetupParams {
        let G = G1::generator();

        let mut rng = ark_std::rand::thread_rng(); // todo
        let r = ScalarField::rand(&mut rng);
        let G_prime = G.mul(r);

        DvscSetupParams {G, G_prime}
    }

    pub fn key_gen(pp: &DvscSetupParams, t: usize) -> (DvscSk, DvscPublicParam){
        let G = &pp.G;
        // v <-- Zp
        let mut rng = ark_std::rand::thread_rng(); // todo
        let v = ScalarField::rand(&mut rng);



        // {v_j*G} for j in [0...t]
        let mut Vj = vec![];
        for j in 0..t {
            let v_power_j = v.pow([j as u64]);
            let vjG = G.mul(v_power_j);
            Vj.push(vjG);
        }

        let witness = Witness {v};
        let pok = Dvsc::pok(&witness, &Vj, t);

        (DvscSk{sk:v}, DvscPublicParam{ Vj, pok })
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

    pub fn evaluate_f_at_v_without_interpolation(x_set: &[ScalarField], v: &ScalarField) -> ScalarField {
        // ∏ (v - x_i)
        let mut prod = ScalarField::one();

        for xi in x_set {
            prod = prod * (v - xi);
        }

        prod
    }

    pub fn evaluate_f_at_secret_point(f_coeffs: &[ScalarField], Yj: &[G1]) -> G1 {
        let mut eval = G1::zero();
        for j in 0..f_coeffs.len() {
            let Y_j: &G1 = Yj.get(j).expect("missing Yj");
            let f_coeff: &ScalarField = f_coeffs.get(j).expect("missing coeff");
            eval = eval.add(&Y_j.mul(*f_coeff));
        }
        eval
    }

    pub fn pok(witness: &Witness, Vj: &[G1], t: usize) -> PoK {
        let mut rng = rand::thread_rng();
        let r_v = ScalarField::rand(&mut rng);

        let mut ai = vec![];
        for j in 0..(t-1) {
            let rVj = Vj.get(j).expect("Missing Vj").mul(&r_v);
            ai.push(rVj);
        }

        let  c = Dvsc::hash_to_fr(&Vj, &ai);
        let s_v = &r_v + &((&c)*(&witness.v));

        PoK {
            s_v: s_v,
            c: c,
        }
    }

    pub fn pok_verify(pok: &PoK, Vj: &[G1], t: usize) -> bool {
        let mut a = vec![];
        for j in 0..(t-1) {
            let sVj = Vj.get(j).expect("missing Vj").mul(&pok.s_v);
            let cVj = Vj.get(j).expect("missing Vj").mul(&pok.c);
            let ai = sVj.sub(cVj);
            a.push(ai);
        }

        let c_verifier = Dvsc::hash_to_fr(&Vj, &a);

        pok.c == c_verifier
    }

    pub fn hash_to_fr(Vj: &[G1Projective], a: &[G1Projective]) -> Fr {
        let mut hasher = Sha256::new();

        // Serialize each point and feed it to the hash
        for v in Vj {
            // Convert to affine coordinates
            let affine = v.into_affine();

            // Serialize the affine point
            let mut serialized = Vec::new();
            affine.serialize_uncompressed(&mut serialized).unwrap();

            // Update the hash with the serialized data
            hasher.update(serialized);
        }

        for ai in a {
            // Convert to affine coordinates
            let affine = ai.into_affine();

            // Serialize the affine point
            let mut serialized = Vec::new();
            affine.serialize_uncompressed(&mut serialized).unwrap();

            // Update the hash with the serialized data
            hasher.update(serialized);
        }

        // Finalize the hash
        let hash_bytes = hasher.finalize();

        // Convert hash bytes to a scalar field element
        // Interpret the hash as a big integer and reduce modulo the field order
        let hash_bigint = Fr::from_le_bytes_mod_order(&hash_bytes);

        hash_bigint
    }


    /// to calcluate the vec that is S\D
    pub fn difference<S: Eq + std::hash::Hash + Clone>(s: &[S], d: &[S]) -> Vec<S> {
        let d_set: HashSet<_> = d.iter().collect();
        s.iter().filter(|x| !d_set.contains(x)).cloned().collect()
    }


    pub fn commit(pp: &DvscSetupParams, ipar: &DvscPublicParam, S: &[ScalarField]) -> Commitment {
        let f = Dvsc::construct_f(&S);
        let f_evaluated_at_v = Dvsc::evaluate_f_at_secret_point(&f.coeffs, &ipar.Vj);

        // todo check Pok in ipar.pok
        // proof verification is omitted from Benchmarks
        //let result = Dvsc::pok_verify(&ipar.pok, &ipar.Vj, ipar.Vj.len());
        //println!("PoK result: {:?}", result);

        Commitment {
            fs_evaluated_at_v_G: f_evaluated_at_v,
            G_prime: pp.G_prime.clone(),
        }
    }

    pub fn randomize(pp: &DvscSetupParams, ipar: &DvscPublicParam, C: &Commitment, miu: &ScalarField) -> Commitment {
        let C1 = C.fs_evaluated_at_v_G.mul(miu);
        let C2 = C.G_prime.mul(miu);

        Commitment {
            fs_evaluated_at_v_G: C1,
            G_prime: C2,
        }
    }

    pub fn open_subset(pp: &DvscSetupParams, ipar: &DvscPublicParam, miu: &ScalarField, S: &[ScalarField], D: &[ScalarField]) -> Commitment {
        let S_bar_D = Dvsc::difference(&S, &D);

        let f_S_bar_D = Dvsc::construct_f(&S_bar_D);
        let f_S_bar_D_evaluated_at_v = Dvsc::evaluate_f_at_secret_point(&f_S_bar_D.coeffs, &ipar.Vj);

        let C = Commitment{
            fs_evaluated_at_v_G: f_S_bar_D_evaluated_at_v,
            G_prime: pp.G_prime.clone(),
        };

        Dvsc::randomize(&pp, &ipar, &C, &miu)
    }


    pub fn verify_subset(pp: &DvscSetupParams, ipar: &DvscPublicParam, sk: &DvscSk, C_prime: &Commitment, W: &Commitment, D: &[ScalarField]) -> bool {
        // let f_D = Dvsc::construct_f(&D);
        // let f_D_evaluated_at_v = f_D.evaluate(&sk.sk);
        let f_D_evaluated_at_v = Dvsc::evaluate_f_at_v_without_interpolation(&D, &sk.sk);

        let WW2 = W.fs_evaluated_at_v_G.mul(f_D_evaluated_at_v);

        WW2.eq(&C_prime.fs_evaluated_at_v_G) && W.G_prime.eq(&C_prime.G_prime)
    }
}


#[cfg(test)]
mod Dvsc_tests {
    use std::ops::{Add, Mul};
    use crate::protocols::dvsc::Dvsc;
    use crate::protocols::dvsc::ScalarField;
    use crate::protocols::dvsc::G1;
    use ark_std::UniformRand;
    use ark_poly::Polynomial;
    use ark_ec::PrimeGroup;
    use ark_ff::Field;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::DenseUVPolynomial;
    use ark_std::Zero;

    #[test]
    fn dvsc_full() {
        // setup + keygen
        let pp = Dvsc::setup();
        let (sk, ipar) = Dvsc::key_gen(&pp, 40);

        // S & D
        let S = prepare_set_S(20);
        let D = pick_subset_excluding_first(&S, 8);

        // Commit (S) --> C
        let C = Dvsc::commit(&pp, &ipar, &S);

        // Randomize (C) --> C_prime
        let mut rng = rand::thread_rng(); // todo
        let miu = ScalarField::rand(&mut rng);
        let C_prime = Dvsc::randomize(&pp, &ipar, &C, &miu);

        // Open_subset (D)
        let W = Dvsc::open_subset(&pp, &ipar, &miu, &S, &D);

        // verify subset
        let result = Dvsc::verify_subset(&pp, &ipar, &sk, &C_prime, &W, &D);

        assert_eq!(result, true);
    }

    #[test]
    pub fn test_subsets() {
        let S = prepare_set_S(20);
        let D = pick_subset_excluding_first(&S, 8);

        let f_S = Dvsc::construct_f(&S);
        let f_D = Dvsc::construct_f(&D);

        let f_S_not_D = &f_S / &f_D;

        let f_new_S = f_S_not_D.naive_mul(&f_D);

        assert_eq!(f_new_S.coeffs, f_S.coeffs);
    }

    #[test]
    pub fn test_eval_at_secret_point() {
        let S = prepare_set_S(20);

        // secret point v
        let setup_pp = Dvsc::setup();
        let (sk,pp) = Dvsc::key_gen(&setup_pp, 50);
        let v = sk.sk;

        // f_S(x)
        let f_S = Dvsc::construct_f(&S);

        // normal evaluation f_S(v)
        let normal_evaluation_fv = f_S.evaluate(&v);
        let generator = G1::generator();
        let normal_evaluation_fvG = generator.mul(normal_evaluation_fv);

        let secret_evaluation_fvG = Dvsc::evaluate_f_at_secret_point(&f_S.coeffs, &pp.Vj);

        assert!(normal_evaluation_fvG.eq(&secret_evaluation_fvG));
    }

    #[test]
    fn test_Vjs() {
        // f(x) = 3 + 2x + 5x^2
        // f(11) = 630
        let f = DensePolynomial::from_coefficients_slice(&[
            ScalarField::from(3),
            ScalarField::from(2),
            ScalarField::from(5)
        ]);
        let v = ScalarField::from(11);
        let f_11 = f.evaluate(&v);
        println!("f(v)=f(11): {:?}", f_11);
        let G = G1::generator();
        let f_11G = G.mul(f_11);

        let mut Vjs = vec![];
        for j in 0..3 {
            let v_power_j = v.pow([j as u64]);
            let v_power_j_G = G.mul(v_power_j);
            Vjs.push(v_power_j_G)
        }

        // evaluate
        let mut resultG = G1::zero();
        for j in 0..3 {
            let Vj: &G1 = Vjs.get(j).expect("no vj found");
            let coeff_j = f.coeffs.get(j).expect("no coeff found");

            resultG = resultG.add(&Vj.mul(*coeff_j));
        }

        println!("f(v)=f(11)G evaluated at secret point: {:?}", resultG);
        // assert_eq!(result, f_11);
        assert_eq!(resultG.eq(&f_11G), true);

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
    fn pick_subset_excluding_first(S: &[ScalarField], D: usize) -> Vec<ScalarField> {
        // Take the subset excluding the first D elements
        let subset = &S[D..];
        subset.into()
    }
}