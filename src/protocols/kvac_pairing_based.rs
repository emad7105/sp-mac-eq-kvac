use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, G2Projective, Fr, FrConfig};
use std::ops::{Add, AddAssign, Mul, Sub};
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
use std::future::poll_fn;
use ark_serialize::CanonicalSerialize;
use sha2::{Sha256,Digest};
use crate::protocols::dvsc;
use crate::protocols::dvsc::{Commitment, Dvsc, DvscPublicParam, DvscSetupParams, DvscSk};
use crate::protocols::spmac_bls12_381::SpMacEq;


pub struct KvacPB {}

pub struct KvacPBSecretKeys {
    sk_MEQ_x1: ScalarField,
    sk_MEQ_x2: ScalarField,

    sk_DVSC: DvscSk,
}

pub struct KvacPBPublicParams {
    ipar_MEQ_I: G1,
    ipar_MEQ_X1: G1,
    ipar_MEQ_X2: G1,

    setup_pp_DVSC: DvscSetupParams,
    ipar_DVSC: DvscPublicParam,
}

pub struct Witness {
    a_minus_1: ScalarField,
    x1: ScalarField,
    x2: ScalarField
}

pub struct PoK {
    c: ScalarField,
    s_a_minus_1: ScalarField,
    s_x1: ScalarField,
    s_x2: ScalarField,
}

pub struct PreCredential {
    tau: SpMacEq,
    pok: PoK,
}

pub struct Credential {
    // C: Commitment,
    tau: SpMacEq,
}

pub struct Show {
    tau_prime: SpMacEq,
    W: Commitment
}

impl KvacPB {
    pub fn key_gen(attribute_size: usize) -> (KvacPBSecretKeys, KvacPBPublicParams) {
        // generate MEQ keys
        let meq_sk = SpMacEq::generate_key(2);
        let x1: &ScalarField = meq_sk.get(0).expect("meq_sk missing entry");
        let x2: &ScalarField = meq_sk.get(1).expect("meq_sk missing entry");

        // generate DVSC keys
        let dvsc_setup_pp = Dvsc::setup();
        let (dvsc_sk, dvsc_ipar_pp) = Dvsc::key_gen(&dvsc_setup_pp, attribute_size);

        let mut rng = ark_std::rand::thread_rng(); // todo
        let r = ScalarField::rand(&mut rng);
        let G1_gen = G1::generator();
        let I = G1_gen.mul(r);
        let X1 = I.mul(x1);
        let X2 = I.mul(x2);

        let isk = KvacPBSecretKeys {
            sk_MEQ_x1: x1.clone(),
            sk_MEQ_x2: x2.clone(),

            sk_DVSC: dvsc_sk,
        };

        let ipar = KvacPBPublicParams {
            ipar_MEQ_I: I,
            ipar_MEQ_X1: X1,
            ipar_MEQ_X2: X2,

            setup_pp_DVSC: dvsc_setup_pp,
            ipar_DVSC: dvsc_ipar_pp
        };

        (isk, ipar)
    }

    pub fn issue_cred(pp: &KvacPBPublicParams, S: &[ScalarField], isk: &KvacPBSecretKeys) -> PreCredential {
        // 1. parse isk
        // 2. Commit (S) --> C=(C1,C2)
        let C = Dvsc::commit(&pp.setup_pp_DVSC, &pp.ipar_DVSC, S);

        // 3. a <-- Zp
        let mut rng = ark_std::rand::thread_rng(); // todo
        let a = ScalarField::rand(&mut rng);

        // 4. tau: (R, T) <-- MEQ.mac(C, a)
        let sk_meq = vec![isk.sk_MEQ_x1, isk.sk_MEQ_x2];
        let msg_to_mac = vec![C.fs_evaluated_at_v_G, C.G_prime]; // todo what is this a in step 4?
        let tau = SpMacEq::mac_with_a(&sk_meq, &msg_to_mac, &a);

        // 5. PoK todo
        let witness = Witness {
            x1: isk.sk_MEQ_x1.clone(),
            x2: isk.sk_MEQ_x2.clone(),
            a_minus_1: a.inverse().expect("inverse a failed"),
        };

        let pok = KvacPB::pok(&witness, &S, &pp.ipar_MEQ_X1, &pp.ipar_MEQ_X2,
                              &tau.R, &tau.T, &pp.ipar_MEQ_I, &C.fs_evaluated_at_v_G, &C.G_prime);

        // 6. PreCred := (tau, pok)
        PreCredential {
            tau,
            pok
        }
    }

    pub fn obtain_cred(pp: &KvacPBPublicParams, pre_cred: &PreCredential, S: &[ScalarField]) -> Credential {
        // 8 & 9: parsing
        // 10: Dvsc.commit(S) --> C
        let C = Dvsc::commit(&pp.setup_pp_DVSC, &pp.ipar_DVSC, &S);

        // 11: Pok checking
        let result = KvacPB::pok_verify(&pre_cred.pok, &S, &pp.ipar_MEQ_X1, &pp.ipar_MEQ_X2,
                           &pre_cred.tau.R, &pre_cred.tau.T, &pp.ipar_MEQ_I, &C.fs_evaluated_at_v_G, &C.G_prime);
        assert!(result);
        //println!("PoK result: {:?}", result);

        Credential {
            // C,
            tau: pre_cred.tau.clone()
        }
    }

    pub fn show_cred(pp: &KvacPBPublicParams, cred: &Credential, S: &[ScalarField], D: &[ScalarField]) -> Show {
        // 1. parsing
        // 2. miu <-- Zp
        let mut rng = ark_std::rand::thread_rng(); // todo
        let miu = ScalarField::rand(&mut rng);

        // 3. MEQ.ChangeRep(C, tau; miu)
        // let msg: Vec<G1> = vec![cred.C.fs_evaluated_at_v_G.clone(), cred.C.G_prime.clone()];
        // let msg: Vec<G1> = vec![];
        let tau_prime =  SpMacEq::change_representation_with_rand(&cred.tau, &miu, &mut rng);
        // let C1_prime = C_vec.get(0).expect("no C1 in commitment").clone();
        // let C2_prime  = C_vec.get(1).expect("no C2 in commitment").clone();
        // let C_prime = Commitment {
        //     fs_evaluated_at_v_G: C1_prime,
        //     G_prime: C2_prime,
        // };

        // 4. DVSC.OpenSubset (miu, S, D) --> W
        let W = Dvsc::open_subset(&pp.setup_pp_DVSC, &pp.ipar_DVSC, &miu, &S, &D);

        // 5. Show := (tau_prime, W)
        Show {
           tau_prime, W,
        }
    }

    pub fn verify(pp: &KvacPBPublicParams, show: &Show, D:&[ScalarField], isk: &KvacPBSecretKeys) -> bool {
        // 7. parsing isk
        // 8. parsing show
        let W1 = show.W.fs_evaluated_at_v_G;
        let W2 = show.W.G_prime;

        // 9. C_prime = (f_D(v)W1, W2)
        // let f_D = Dvsc::construct_f(D);
        // let f_D_evaluated_at_v = f_D.evaluate(&isk.sk_DVSC.sk);
        let f_D_evaluated_at_v = Dvsc::evaluate_f_at_v_without_interpolation(&D, &isk.sk_DVSC.sk);

        let f_D_evaluated_at_v_W1 = W1.mul(f_D_evaluated_at_v);
        let C_prime = vec![f_D_evaluated_at_v_W1, W2];

        // 10. MEQ.verify(sk_MEQ, C_prime, tau_prime)
        let spmac_sks = vec![isk.sk_MEQ_x1, isk.sk_MEQ_x2];
        SpMacEq::verify(&spmac_sks, &show.tau_prime, &C_prime)
    }

    pub fn pok(witness: &Witness, S: &[ScalarField], X1: &G1, X2: &G1, R: &G1, T: &G2, I: &G1, C1:&G1, C2:&G1 ) -> PoK {
        let mut rng = ark_std::rand::thread_rng(); // todo
        let r_a_minus_one = ScalarField::rand(&mut rng);
        let r_x1 = ScalarField::rand(&mut rng);
        let r_x2 = ScalarField::rand(&mut rng);

        let a1 = I.mul(&r_x1);
        let a2 = I.mul(&r_x2);
        let a3 = G2::generator().mul(&r_a_minus_one);
        let rx1C1 = C1.mul(&r_x1);
        let rx2C2 = C2.mul(&r_x2);
        let ra1R = R.mul(r_a_minus_one);
        let rx1C1_plus_rx2C2 = rx1C1.add(rx2C2);
        let a4 = rx1C1_plus_rx2C2.sub(ra1R);

        let hash_input_points_G1 = vec![a1, a2, a4, *X1, *X2, *I, *C1, *C2, *R];
        let hash_input_points_G2 = vec![a3, *T];
        let c = KvacPB::hash_to_fr(&hash_input_points_G1, &S,  &hash_input_points_G2);

        let s_a_minus_1 = &r_a_minus_one + &((&c)*(&witness.a_minus_1));
        let s_x1 = &r_x1 + &((&c)*(&witness.x1));
        let s_x2 = &r_x2 + &((&c)*(&witness.x2));

        PoK{
            c: c,
            s_a_minus_1: s_a_minus_1,
            s_x1: s_x1,
            s_x2: s_x2,
        }
    }

    pub fn pok_verify(pok: &PoK, S: &[ScalarField], X1: &G1, X2: &G1, R: &G1, T: &G2, I: &G1, C1:&G1, C2:&G1 ) -> bool {
        let a1 = I.mul(&pok.s_x1).sub(&X1.mul(&pok.c));
        let a2 = I.mul(&pok.s_x2).sub(&X2.mul(&pok.c));
        let a3 = G2::generator().mul(&pok.s_a_minus_1).sub(&T.mul(&pok.c));
        let a4 = C1.mul(&pok.s_x1).add(&C2.mul(&pok.s_x2)).sub(&R.mul(&pok.s_a_minus_1));

        let hash_input_points_G1 = vec![a1, a2, a4, *X1, *X2, *I, *C1, *C2, *R];
        let hash_input_points_G2 = vec![a3, *T];
        let c_verifier = KvacPB::hash_to_fr(&hash_input_points_G1, &S, &hash_input_points_G2);

        pok.c == c_verifier
    }

    /// Hashes a vector of `G1Projective` points into a scalar field element of type `Fr`
    pub fn hash_to_fr(points_G1: &[G1Projective], scalar_fields: &[ScalarField], points_G2: &[G2Projective]) -> Fr {
        let mut hasher = Sha256::new();

        // Serialize each point and feed it to the hash
        for point in points_G1 {
            // Convert to affine coordinates
            let affine = point.into_affine();

            // Serialize the affine point
            let mut serialized = Vec::new();
            affine.serialize_uncompressed(&mut serialized).unwrap();

            // Update the hash with the serialized data
            hasher.update(serialized);
        }

        // Serialize each point and feed it to the hash
        for point in points_G2 {
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

        // Serialize `tau` (SpMacEq) and its fields
        pre_cred.tau.R.serialize_compressed(&mut buffer).unwrap();
        let size_r = buffer.len();
        buffer.clear();

        pre_cred.tau.T.serialize_compressed(&mut buffer).unwrap();
        let size_t = buffer.len();
        buffer.clear();

        let size_tau = size_r + size_t;

        // Serialize `pok` (PoK) and its fields
        pre_cred.pok.c.serialize_compressed(&mut buffer).unwrap();
        let size_c = buffer.len();
        buffer.clear();

        pre_cred.pok.s_a_minus_1.serialize_compressed(&mut buffer).unwrap();
        let size_s_a_minus_1 = buffer.len();
        buffer.clear();

        pre_cred.pok.s_x1.serialize_compressed(&mut buffer).unwrap();
        let size_s_x1 = buffer.len();
        buffer.clear();

        pre_cred.pok.s_x2.serialize_compressed(&mut buffer).unwrap();
        let size_s_x2 = buffer.len();
        buffer.clear();

        let size_pok = size_c + size_s_a_minus_1 + size_s_x1 + size_s_x2;

        // Total size
        size_tau + size_pok
    }

    pub fn size_of_credential(credential: &Credential) -> usize {
        let mut buffer = Vec::new();

        // Serialize `Commitment` and its fields
        // credential.C.fs_evaluated_at_v_G.serialize_compressed(&mut buffer).unwrap();
        // let size_fs_evaluated = buffer.len();
        // buffer.clear();

        // credential.C.G_prime.serialize_compressed(&mut buffer).unwrap();
        // let size_g_prime = buffer.len();
        // buffer.clear();

        let size_commitment = 0;//size_fs_evaluated + size_g_prime;

        // Serialize `tau` (SpMacEq) and its fields
        credential.tau.R.serialize_compressed(&mut buffer).unwrap();
        let size_r = buffer.len();
        buffer.clear();

        credential.tau.T.serialize_compressed(&mut buffer).unwrap();
        let size_t = buffer.len();
        buffer.clear();

        let size_spmaceq = size_r + size_t;

        // Total size
        size_commitment + size_spmaceq
    }

    pub fn size_of_show(show: &Show) -> usize {
        let mut buffer = Vec::new();

        // Serialize `tau_prime` (SpMacEq) and its fields
        show.tau_prime.R.serialize_compressed(&mut buffer).unwrap();
        let size_r = buffer.len();
        buffer.clear();

        show.tau_prime.T.serialize_compressed(&mut buffer).unwrap();
        let size_t = buffer.len();
        buffer.clear();

        let size_tau_prime = size_r + size_t;

        // Serialize `W` (Commitment) and its fields
        show.W.fs_evaluated_at_v_G.serialize_compressed(&mut buffer).unwrap();
        let size_fs_evaluated = buffer.len();
        buffer.clear();

        show.W.G_prime.serialize_compressed(&mut buffer).unwrap();
        let size_g_prime = buffer.len();
        buffer.clear();

        let size_commitment = size_fs_evaluated + size_g_prime;

        // Total size
        size_tau_prime + size_commitment
    }

}


#[cfg(test)]
mod spmaceq_mac_tests {
    use std::ops::Mul;
    use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
    use crate::protocols::kvac_pairing_based::KvacPB;
    use ark_std::UniformRand;
    use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, Fr, FrConfig};
    use ark_ec::Group;
    use sha2::Sha256;
    use sha2::Digest;

    #[test]
    fn test_kvac_pb_full_flow_test() {
        // 0. setup
        // attribute sets
        let S = prepare_set_S(20);
        let D: Vec<ScalarField> = S.iter().take(8).cloned().collect();
        let (isk, pp) = KvacPB::key_gen(40);

        // 1. issue cred
        let pre_cred = KvacPB::issue_cred(&pp, &S, &isk);

        // 2. obtain cred
        let cred = KvacPB::obtain_cred(&pp, &pre_cred, &S);

        // 3. show cred
        let show = KvacPB::show_cred(&pp, &cred, &S, &D);

        // 5. verify
        let result = KvacPB::verify(&pp, &show, &D, &isk);

        assert_eq!(result, true)
    }

    #[test]
    fn hash_to_field() {
        let mut rng = ark_std::rand::thread_rng(); // todo
        let r = ScalarField::rand(&mut rng);

        let G = G1::generator();
        let A = G.mul(&r);
        let B = A.mul(&r);
        let C = B.mul(&r);
        let points = vec![A,B,C];

        let scalar_fields_G1 = vec![r, r, r];
        let scalar_fields_G2 = vec![G2::generator(), G2::generator()];


        let scalar_field_hash = KvacPB::hash_to_fr(&points, &scalar_fields_G1, &scalar_fields_G2);

        let D = C.mul(&scalar_field_hash);
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