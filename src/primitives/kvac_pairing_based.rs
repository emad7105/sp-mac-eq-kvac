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
use crate::primitives::dvsc;
use crate::primitives::dvsc::{Commitment, Dvsc, DvscPublicParam, DvscSetupParams, DvscSk};
use crate::primitives::spmac_bls12_381::SpMacEq;


pub struct KvacPB {}

pub struct KvacPBSecretKeys {
    sk_MEQ_x1: ScalarField,
    sk_MEQ_x2: ScalarField,

    sk_DVSC: DvscSk,
}

pub struct KvacPBPublicParams {
    sk_MEQ_I: G1,
    sk_MEQ_X1: G1,
    sk_MEQ_X2: G1,

    setup_pp_DVSC: DvscSetupParams,
    ipar_DVSC: DvscPublicParam,
}

pub struct PoK {

}

pub struct PreCredential {
    tau: SpMacEq,
    pok: PoK,
}

pub struct Credential {
    C: Commitment,
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
            sk_MEQ_I: I,
            sk_MEQ_X1: X1,
            sk_MEQ_X2: X2,

            setup_pp_DVSC: dvsc_setup_pp,
            ipar_DVSC: dvsc_ipar_pp
        };

        (isk, ipar)
    }

    pub fn issue_cred(pp: &KvacPBPublicParams, S: &[ScalarField], isk: &KvacPBSecretKeys, ipar: &KvacPBPublicParams) -> PreCredential {
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
        let pok = PoK {};

        // 6. PreCred := (tau, pok)
        PreCredential {
            tau,
            pok
        }
    }

    pub fn obtain_cred(pp: &KvacPBPublicParams, pre_cred: &PreCredential, S: &[ScalarField], ipar: &KvacPBPublicParams) -> Credential {
        // 8 & 9: parsing
        // 10: Dvsc.commit(S) --> C
        let C = Dvsc::commit(&pp.setup_pp_DVSC, &pp.ipar_DVSC, &S);

        // 11: Pok checking todo

        Credential {
            C,
            tau: pre_cred.tau.clone()
        }
    }

    pub fn show_cred(pp: &KvacPBPublicParams, cred: Credential, S: &[ScalarField], D: &[ScalarField]) -> Show {
        // 1. parsing
        // 2. miu <-- Zp
        let mut rng = ark_std::rand::thread_rng(); // todo
        let miu = ScalarField::rand(&mut rng);

        // 3. MEQ.ChangeRep(C, tau; miu)
        let msg: Vec<G1> = vec![cred.C.fs_evaluated_at_v_G.clone(), cred.C.G_prime.clone()];
        let (C_vec, tau_prime) =  SpMacEq::change_representation(&cred.tau, &msg, &mut rng);
        let C1_prime = C_vec.get(0).expect("no C1 in commitment").clone();
        let C2_prime  = C_vec.get(1).expect("no C2 in commitment").clone();
        let C_prime = Commitment {
            fs_evaluated_at_v_G: C1_prime,
            G_prime: C2_prime,
        };

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
        let f_D = Dvsc::construct_f(D);
        let f_D_evaluated_at_v = f_D.evaluate(&isk.sk_DVSC.sk);
        let f_D_evaluated_at_v_W1 = W1.mul(f_D_evaluated_at_v);
        let C_prime = vec![f_D_evaluated_at_v_W1, W2];

        // 10. MEQ.verify(sk_MEQ, C_prime, tau_prime)
        let spmac_sks = vec![isk.sk_MEQ_x1, isk.sk_MEQ_x2];
        SpMacEq::verify(&spmac_sks, &show.tau_prime, &C_prime)
    }
}