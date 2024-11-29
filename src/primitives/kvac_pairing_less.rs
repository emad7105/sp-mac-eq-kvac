use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, Fr, FrConfig};
use std::ops::{AddAssign, Mul, Sub};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, Group};
use ark_ff::{BigInteger, Field, Fp, Fp256, MontBackend, PrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use rand::{CryptoRng, Rng};
use ark_std::{UniformRand, Zero};
use ark_std::One;
use std::ops::Neg;
use ark_std::iterable::Iterable;
use std::collections::HashSet;
use ark_serialize::CanonicalSerialize;
use sha2::Sha256;
use crate::primitives::dvsc::Dvsc;
use sha2::Digest;


pub struct KvacPL {}

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

pub struct Witness {
    x: ScalarField,
    v: ScalarField
}

pub struct PoK {
    c: ScalarField,
    s_x: ScalarField,
    s_v: ScalarField,
}

pub struct Show {
    tau_prime: G1,
    W: G1,
}


impl KvacPL {
    pub fn gen_isk() -> SecretKeys {
        let mut rng = ark_std::rand::thread_rng(); // todo

        let x = ScalarField::rand(&mut rng);
        let v = ScalarField::rand(&mut rng);

        SecretKeys {
            x,
            v,
        }
    }

    pub fn gen_public_params(isk: &SecretKeys) -> PublicParams {
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

    /// Outputs (tau, {Y_j} for j in [|S|], PoK)
    pub fn issue_cred(pp: &PublicParams, S: &[ScalarField], isk: &SecretKeys) -> PreCredential {

        // 1. parse (x,v) from isk
        // 2. y <--Z_p
        let mut rng = ark_std::rand::thread_rng();
        let y = ScalarField::rand(&mut rng);
        // 3. C <- y * f_S(v)G
        // calculate f_S = (x-s1)*(x-s2)...(x-sn) the vanishing polynomial
        let f_S = Dvsc::construct_f(S);
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
        for j in 0..(S.len()+1) {
            let v_power_j = isk.v.pow([j as u64]);
            let yvj: Fp256<MontBackend<FrConfig, 4>> = v_power_j * y.clone();
            let yvjG = G.mul(yvj);
            Yj.push(yvjG);
        }

        let witness = Witness{
            x: isk.x.clone(),
            v: isk.v.clone(),
        };
        let pok = KvacPL::pok(&witness, &C, &pp.R, &pp.X, &Yj, &S, &tau, &pp.V);

        PreCredential {
            tau,
            Yj,
            pok: pok,
        }
    }

    pub fn obtain_cred(pp: &PublicParams, pre_cred: &PreCredential, S: &[ScalarField]) -> Credential {
        // C <-- y * f_S(v) G
        let f = Dvsc::construct_f(&S);
        let C_recalculated = Dvsc::evaluate_f_at_secret_point(&f.coeffs, &pre_cred.Yj);

        // Check PoK
        let result = KvacPL::pok_verify(&pre_cred.pok, &pp.V, &C_recalculated, &pp.R, &pp.X, &pre_cred.Yj, &S, &pre_cred.tau);
        assert!(result);
        // println!("PoK result: {:?}", result);

        Credential {
            C: C_recalculated,
            tau: pre_cred.tau.clone(),
            Yj: pre_cred.Yj.to_vec(),
        }
    }

    pub fn show_cred(pp: &PublicParams, cred: &Credential, S: &[ScalarField], D: &[ScalarField]) -> Show {
        // miu <-- Zp
        let mut rng = ark_std::rand::thread_rng();
        let miu = ScalarField::rand(&mut rng);

        // S\D
        let S_without_D = Dvsc::difference(S, D);
        // f_{S\D}
        let f = Dvsc::construct_f(&S_without_D);
        let yf = Dvsc::evaluate_f_at_secret_point(&f.coeffs, &cred.Yj);

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
        let f_D = Dvsc::construct_f(D);
        // f_D(v)
        let f_D_evaluated_at_v = f_D.evaluate(&isk.v);
        // Wf_D(v)
        let Wf_D_evaluated_at_v  = show.W.mul(f_D_evaluated_at_v);
        // xWf_D(v)
        let xWf_D_evaluated_at_v = Wf_D_evaluated_at_v.mul(&isk.x);

        // (xWf_D(v) == tau_prime) && (tau_prime != 0G)
        xWf_D_evaluated_at_v.eq(&show.tau_prime) && (!show.tau_prime.eq(&G1::zero()))
    }

    pub fn pok (witness: &Witness, C: &G1, R: &G1, X:&G1, Yi: &[G1], S: &[ScalarField], tau: &G1, V: &G1) -> PoK{
        let mut rng = ark_std::rand::thread_rng();
        let r_x = ScalarField::rand(&mut rng);
        let r_v = ScalarField::rand(&mut rng);

        let s_size = S.len();

        let a1 = C.mul(&r_x);
        let a2 = R.mul(&r_x);
        let mut ai = vec![];
        for i in 0..(s_size-1) {
            let a = Yi.get(i).expect("Yi missing").mul(&r_v);
            ai.push(a);
        }

        let mut hash_input_points = vec![*V,*C,*X,*R, a1, a2, *tau];
        hash_input_points.append(&mut ai);
        let mut Yj = (&Yi[0..s_size]).to_vec();
        hash_input_points.append(&mut Yj);

        let c = KvacPL::hash_to_fr(&hash_input_points, &S);

        let s_x = &r_x + &((&c)*(&witness.x));
        let s_v = &r_v + &((&c)*(&witness.v));

        PoK{
            c: c,
            s_x: s_x,
            s_v: s_v
        }
    }

    pub fn pok_verify(pok: &PoK, V: &G1, C: &G1, R: &G1, X: &G1, Yj: &[G1], S: &[ScalarField], tau: &G1) -> bool {
        let a1 = C.mul(&pok.s_x).sub(&tau.mul(&pok.c));
        let a2 = R.mul(&pok.s_x).sub(&X.mul(&pok.c));

        let s_size = S.len();

        let mut a_i = vec![];
        for i in 0..(s_size-1) {
            let svYj = Yj.get(i).expect("missing Yj").mul(&pok.s_v);
            let cYjplus1 = Yj.get(&i+1).expect("missing Yj+1").mul(&pok.c);
            let aj = svYj.sub(cYjplus1);
            a_i.push(aj);
        }

        let mut hash_input_points = vec![*V,*C,*X,*R, a1, a2, *tau];
        hash_input_points.append(&mut a_i);
        let mut Yj_s_slice = (&Yj[0..s_size]).to_vec();
        hash_input_points.append(&mut Yj_s_slice);

        let c_verifier = KvacPL::hash_to_fr(&hash_input_points, &S);

        pok.c == c_verifier
    }

    pub fn hash_to_fr(points: &[G1Projective], scalar_fields: &[ScalarField]) -> Fr {
        let mut hasher = Sha256::new();

        // Serialize each point and feed it to the hash
        for point in points {
            // Convert to affine coordinates
            let affine = point.into_affine();

            // Serialize the affine point
            let mut serialized = Vec::new();
            affine.serialize_uncompressed(&mut serialized).unwrap();

            // Update the hash with the serialized data
            hasher.update(serialized);
        }

        // Serialize each scalar field element and feed it to the hash
        for scalar in scalar_fields {
            // Convert scalar to its big integer representation and then to bytes
            let scalar_bigint = scalar.into_bigint(); // Use `into_bigint` for Arkworks Scalars
            let scalar_bytes = scalar_bigint.to_bytes_le();

            // Update the hash with the scalar bytes
            hasher.update(scalar_bytes);
        }

        // Finalize the hash
        let hash_bytes = hasher.finalize();

        // Convert hash bytes to a scalar field element
        // Interpret the hash as a big integer and reduce modulo the field order
        let hash_bigint = Fr::from_le_bytes_mod_order(&hash_bytes);

        hash_bigint
    }

    pub fn size_of_pre_cred(pre_cred: &PreCredential) -> usize {
        let mut buffer = Vec::new();

        // Serialize `tau` and get its size
        pre_cred.tau.serialize_compressed(&mut buffer).unwrap();
        let size_tau = buffer.len();
        buffer.clear();

        // Serialize each element in `Yj` and sum their sizes
        let size_yj: usize = pre_cred.Yj.iter().map(|y| {
            y.serialize_compressed(&mut buffer).unwrap();
            let size = buffer.len();
            buffer.clear();
            size
        }).sum();

        // Serialize `PoK` fields and sum their sizes
        pre_cred.pok.c.serialize_compressed(&mut buffer).unwrap();
        let size_c = buffer.len();
        buffer.clear();

        pre_cred.pok.s_x.serialize_compressed(&mut buffer).unwrap();
        let size_s_x = buffer.len();
        buffer.clear();

        pre_cred.pok.s_v.serialize_compressed(&mut buffer).unwrap();
        let size_s_v = buffer.len();
        buffer.clear();

        // Total size is the sum of all parts
        size_tau + size_yj + size_c + size_s_x + size_s_v
    }

    pub fn size_of_credential(credential: &Credential) -> usize {
        let mut buffer = Vec::new();

        // Serialize `C` and get its size
        credential.C.serialize_compressed(&mut buffer).unwrap();
        let size_c = buffer.len();
        buffer.clear();

        // Serialize `tau` and get its size
        credential.tau.serialize_compressed(&mut buffer).unwrap();
        let size_tau = buffer.len();
        buffer.clear();

        // Serialize each element in `Yj` and sum their sizes
        let size_yj: usize = credential.Yj.iter().map(|y| {
            y.serialize_compressed(&mut buffer).unwrap();
            let size = buffer.len();
            buffer.clear();
            size
        }).sum();

        // Total size is the sum of all parts
        size_c + size_tau + size_yj
    }


    pub fn size_of_show(show: &Show) -> usize {
        let mut buffer = Vec::new();

        // Serialize `tau_prime` and get its size
        show.tau_prime.serialize_compressed(&mut buffer).unwrap();
        let size_tau_prime = buffer.len();
        buffer.clear();

        // Serialize `W` and get its size
        show.W.serialize_compressed(&mut buffer).unwrap();
        let size_w = buffer.len();
        buffer.clear();

        // Total size is the sum of all parts
        size_tau_prime + size_w
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
    use crate::primitives::dvsc::Dvsc;
    use crate::primitives::kvac_pairing_less::KvacPL;
    use crate::primitives::kvac_pairing_less::ScalarField;
    use crate::primitives::kvac_pairing_less::G1;

    #[test]
    fn test_kvac_full_flow_test() {
        // 0. key gens
        let isk = KvacPL::gen_isk();
        let pp = KvacPL::gen_public_params(&isk);

        // attribute sets
        let S = prepare_set_S(20);
        let D: Vec<ScalarField> = S.iter().take(8).cloned().collect();

        // 1. KVAC.issue_cred(pp, S, isk, ipar)
        let pre_cred = KvacPL::issue_cred(&pp, &S, &isk);

        // 2. KVAC.obtain_cred(pp, PreCred, S, ipar)
        let cred = KvacPL::obtain_cred(&pp, &pre_cred, &S);

        // 3. KVAC.show_cred(pp, Cred, S, D)
        let show = KvacPL::show_cred(&pp, &cred, &S, &D);

        // 4. KVAC.verify(pp, Show, D, isk)
        let result = KvacPL::verify(&pp, &show, &D, &isk);

        assert_eq!(result, true);
    }

    #[test]
    fn test_construct_f() {
        let s = vec![ScalarField::from(2u64), ScalarField::from(10u64), ScalarField::from(3u64)];
        let s_permuted = vec![ScalarField::from(3u64), ScalarField::from(10u64), ScalarField::from(2u64)];

        let f1 = Dvsc::construct_f(&s);
        let f2 = Dvsc::construct_f(&s_permuted);

        assert_eq!(f1.coeffs, f2.coeffs);
    }

    #[test]
    fn test_key_gens() {
        let keys = KvacPL::gen_isk();
        let public_params = KvacPL::gen_public_params(&keys);
    }

    #[test]
    fn test_evaluations() {
        let secret_keys = KvacPL::gen_isk();
        let public_params = KvacPL::gen_public_params(&secret_keys);

        let S = prepare_set_S(20);

        let pre_cred = KvacPL::issue_cred(&public_params, &S, &secret_keys);

        // expected C
        let mut rng = ark_std::rand::thread_rng();
        let y = ScalarField::rand(&mut rng);
        let f_S = Dvsc::construct_f(&S);
        let f_S_evaluated_at_v = f_S.evaluate(&secret_keys.v);
        let G = G1::generator();
        let x: Fp256<MontBackend<FrConfig, 4>> = y * f_S_evaluated_at_v;
        let C_expected = G.mul(x);

        let C = Dvsc::evaluate_f_at_secret_point(&f_S.coeffs, &pre_cred.Yj);

        // bad test
        //assert_eq!(C, C_expected)
    }

    #[test]
    fn test_Kvac_flow() {
        let secret_keys = KvacPL::gen_isk();
        let public_params = KvacPL::gen_public_params(&secret_keys);

        let S = prepare_set_S(20);

        let pre_cred = KvacPL::issue_cred(&public_params, &S, &secret_keys);
        let credential = KvacPL::obtain_cred(&public_params, &pre_cred, &S);
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