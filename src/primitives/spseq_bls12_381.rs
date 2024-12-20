use std::ops::Mul;
use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381};
use ark_std::UniformRand;
use ark_ec::Group;
use ark_std::Zero;
use ark_ff::fields::Field;
use ark_ec::pairing::{Pairing};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, Rng};


#[derive(Debug, PartialEq)]
pub struct SpsEqSignature {
    /// R point
    pub R: G1,
    /// S point
    pub S: G1,
    /// T point
    pub T: G2,
}

pub struct KeyPair {
    pub sk: Vec<ScalarField>,
    pub vk: Vec<G2>,
}

impl SpsEqSignature {
    pub fn generate_key(l: usize) -> KeyPair {
        let mut rng = ark_std::rand::thread_rng(); // todo

        let sk = vec![ScalarField::rand(&mut rng); l];
        let mut vk = vec![];
        for s in &sk {
            vk.push(G2::generator().mul(s));
        }

        KeyPair {
            sk, vk
        }
    }

    pub fn generate_key_test(l: usize) -> KeyPair {
        let mut rng = ark_std::test_rng(); // todo

        let sk = vec![ScalarField::rand(&mut rng); l];
        let mut vk = vec![];
        for s in &sk {
            vk.push(G2::generator().mul(s));
        }

        KeyPair {
            sk, vk
        }
    }

    pub fn to_bytes_sk(sk: Vec<ScalarField>) -> Vec<Vec<u8>> {
        let mut bytes = Vec::new();
        for s in sk {
            let mut compressed_bytes = Vec::new();
            s.serialize_compressed(&mut compressed_bytes).unwrap();
            bytes.push(compressed_bytes)
        }
        bytes
    }

    pub fn to_bytes_vk(vk: Vec<G2>) -> Vec<Vec<u8>> {
        let mut bytes = Vec::new();
        for s in vk {
            let mut compressed_bytes = Vec::new();
            s.serialize_compressed(&mut compressed_bytes).unwrap();
            bytes.push(compressed_bytes)
        }
        bytes
    }

    pub fn to_hex_sk(sk_bytes: &[Vec<u8>]) -> Vec<String> {
        let mut sk_hex = vec![];
        // let sk_bytes_clone = sk_bytes.to_vec().clone();
        for s_bytes in sk_bytes {
            let s = hex::encode(s_bytes);
            sk_hex.push(s)
        }
        sk_hex
    }

    pub fn to_hex_vk(vk_bytes: &[Vec<u8>]) -> Vec<String> {
        let mut vk_hex = vec![];
        // let sk_bytes_clone = sk_bytes.to_vec().clone();
        for v_bytes in vk_bytes {
            let k = hex::encode(v_bytes);
            vk_hex.push(k)
        }
        vk_hex
    }

    pub fn from_hex_sk(sk_hex: &[String]) -> Vec<Vec<u8>> {
        let mut sk_bytes = vec![];
        // let sk_bytes_clone = sk_bytes.to_vec().clone();
        for s_bytes in sk_hex {
            let s = hex::decode(s_bytes).unwrap();
            sk_bytes.push(s)
        }
        sk_bytes
    }

    pub fn from_hex_vk(vk_hex: &[String]) -> Vec<Vec<u8>> {
        let mut vk_bytes = vec![];
        // let sk_bytes_clone = sk_bytes.to_vec().clone();
        for v_bytes in vk_hex {
            let k = hex::decode(v_bytes).unwrap();
            vk_bytes.push(k)
        }
        vk_bytes
    }

    pub fn from_bytes_sk(sk_bytes: &[Vec<u8>]) -> Vec<ScalarField> {
        let mut sk = vec![];
        // let sk_bytes_clone = sk_bytes.to_vec().clone();
        for s_bytes in sk_bytes {
            let s = ScalarField::deserialize_compressed(&*(*s_bytes)).unwrap();
            sk.push(s)
        }
        sk
    }

    pub fn from_bytes_vk(vk_bytes: &[Vec<u8>]) -> Vec<G2> {
        let mut vk = vec![];
        // let sk_bytes_clone = sk_bytes.to_vec().clone();
        for v_bytes in vk_bytes {
            let k = G2::deserialize_compressed(&*(*v_bytes)).unwrap();
            vk.push(k)
        }
        vk
    }

    pub fn to_bytes(&self) -> Vec<Vec<u8>>{
        let mut output = vec![];
        let s_bytes = crate::primitives::hex_utils::g1_to_bytes(&self.S);
        let r_bytes = crate::primitives::hex_utils::g1_to_bytes(&self.R);
        let t_bytes = crate::primitives::hex_utils::g2_to_bytes(&self.T);

        output.push(s_bytes);
        output.push(r_bytes);
        output.push(t_bytes);

        output
    }

    pub fn from_bytes(hex: &[Vec<u8>]) -> Self {
        let s = crate::primitives::hex_utils::bytes_to_g1(hex.get(0).expect("wrong bytes"));
        let r = crate::primitives::hex_utils::bytes_to_g1(hex.get(1).expect("wrong bytes"));
        let t = crate::primitives::hex_utils::bytes_to_g2(hex.get(2).expect("wrong bytes"));

        SpsEqSignature {
            S:s,
            R:r,
            T:t,
        }
    }

    pub fn sign_test(sk: &[ScalarField], messages: &[G1]) -> SpsEqSignature {
        // let mut rng = ark_std::rand::thread_rng(); // todo
        let mut rng = ark_std::test_rng();

        let a = ScalarField::rand(&mut rng);
        // zero checking

        let mut R:G1 = G1::zero();
        for (m, key) in messages.into_iter().zip(sk) {
            R += m.mul(key);
        }
        R *= a;

        let mut S:G1 = G1::generator();
        S *= a.inverse().expect("It will never be zero");

        let mut T:G2 = G2::generator();
        T *= a.inverse().expect("It will never be zero");

        SpsEqSignature {
            S,
            R,
            T,
        }
    }

    pub fn sign<R: Rng + CryptoRng>(sk: &[ScalarField], messages: &[G1], rng: &mut R) -> SpsEqSignature {
        // let mut rng = ark_std::rand::thread_rng(); // todo

        let a = ScalarField::rand(rng);
        // zero checking

        let mut R:G1 = G1::zero();
        for (m, key) in messages.into_iter().zip(sk) {
            R += m.mul(key);
        }
        R *= a;

        let mut S:G1 = G1::generator();
        S *= a.inverse().expect("It will never be zero");

        let mut T:G2 = G2::generator();
        T *= a.inverse().expect("It will never be zero");

        SpsEqSignature {
            S,
            R,
            T,
        }
    }

    pub fn verify(vk: &[G2], signature: &SpsEqSignature, messages: &[G1]) -> bool {
        let mut lhs1 = Bls12_381::pairing(&messages[0], &vk[0]).0;
        for (m, vkey) in messages.into_iter().zip(vk).skip(1) {
            lhs1 = lhs1.mul(Bls12_381::pairing(m, vkey).0);
        }
        let rhs1 = Bls12_381::pairing(&signature.R, &signature.T).0;

        let lhs2 = Bls12_381::pairing(&signature.S, G2::generator()).0;
        let rhs2 = Bls12_381::pairing(G1::generator(), &signature.T).0;


        ( lhs1 == rhs1 ) && ( lhs2 == rhs2 )
    }

    pub fn change_representation<R: Rng + CryptoRng>(signature: &SpsEqSignature, messages: &[G1], rng: &mut R) -> (Vec<G1>, SpsEqSignature) {
        // let mut rng = ark_std::rand::thread_rng(); // todo
        let r1 = ScalarField::rand(rng);
        SpsEqSignature::change_representation_with_rand(signature, messages, &r1, rng)
    }

    pub fn change_representation_with_rand<R: Rng + CryptoRng>(signature: &SpsEqSignature, messages: &[G1], r1: &ScalarField, rng: &mut R) -> (Vec<G1>, SpsEqSignature) {
        // let mut rng = ark_std::rand::thread_rng(); // todo
        let r2 = ScalarField::rand(rng);

        // randomize message
        let rnd_messages: Vec<G1> = messages
            .to_owned()
            .into_iter()
            .map(|mut g| {
                g *= r1;
                g
            })
            .collect();

        // randomize signature
        let mut rnd_R:&G1 = &signature.R.mul(r1);
        //rnd_R = &rnd_R.mul(&r2);
        let binding = rnd_R.mul(&r2);
        rnd_R = &binding;

        let inverse_r2 = r2.inverse().expect("Inversion error");
        let rnd_S:&G1 = &signature.S.mul(&inverse_r2);
        let rnd_T:&G2 = &signature.T.mul(&inverse_r2);

        let rnd_signature = SpsEqSignature {
            S: rnd_S.clone(),
            R: rnd_R.clone(),
            T: rnd_T.clone(),
        };

        (rnd_messages, rnd_signature)
    }
}



#[cfg(test)]
mod spseq_sign_tests {
    use std::time::{Duration, Instant};
    use rand::rngs::OsRng;
    use super::*;

    #[test]
    fn full_test() {
        let l = 2;
        let key_pair = SpsEqSignature::generate_key(l);
        // println!("sk: {:?}", key_pair.sk);
        // println!("vk: {:?}", );
        // assert_eq!(result, 4);

        let messages = vec![G1::generator(), G1::zero()];
        let mut rng = OsRng;

        let signature = SpsEqSignature::sign(&key_pair.sk, &messages, &mut rng);
        let result = SpsEqSignature::verify(&key_pair.vk, &signature, &messages);
        println!("Sig: {:?}", signature);
        println!("verify: {:?}", result);

        let (rnd_messages, rnd_signature) = SpsEqSignature::change_representation(&signature, &messages, &mut rng);
        let rnd_result = SpsEqSignature::verify(&key_pair.vk, &rnd_signature, &rnd_messages);
        println!("RND_Sig: {:?}", rnd_signature);
        println!("RND_verify: {:?}", rnd_result);

        let sig_bytes = rnd_signature.to_bytes();
        let sig_from_bytes = SpsEqSignature::from_bytes(&sig_bytes);
        assert_eq!(sig_from_bytes, rnd_signature)
    }


    #[test]
    fn kgen_test() {
        let l = 2;
        let key_pair = SpsEqSignature::generate_key(l);
        let sk = key_pair.sk;
        let vk = key_pair.vk;

        // check sk
        let sk_bytes = SpsEqSignature::to_bytes_sk(sk.clone());
        let sk_hex = SpsEqSignature::to_hex_sk(&sk_bytes);
        let sk_bytes_decoded = SpsEqSignature::from_hex_sk(&sk_hex);
        let sk_decoded = SpsEqSignature::from_bytes_sk(&sk_bytes_decoded);
        println!("SPS-EQ-SIG SK: {:?}", sk_hex);
        assert_eq!(sk, sk_decoded);

        let vk_bytes = SpsEqSignature::to_bytes_vk(vk.clone());
        let vk_hex = SpsEqSignature::to_hex_vk(&vk_bytes);
        let vk_bytes_decoded = SpsEqSignature::from_hex_vk(&vk_hex);
        let vk_decoded = SpsEqSignature::from_bytes_vk(&vk_bytes_decoded);
        println!("SPS-EQ-SIG VK: {:?}", vk_hex);
        assert_eq!(vk, vk_decoded);
    }


    #[test]
    fn bench_test() {
        let l = 2^7;

        let key_pair = SpsEqSignature::generate_key(l);
        let mut rng = ark_std::test_rng();
        let messages  = vec![G1::generator().mul(ScalarField::rand(&mut rng)); l];

        let times = 100;

        let mut total_time = Duration::new(0, 0);
        for _ in 0..times {
            let loop_start = Instant::now();

            SpsEqSignature::sign_test(&key_pair.sk, &messages);

            let loop_time = loop_start.elapsed();
            total_time += loop_time;
        }

        let average_time = total_time / times;
        let millis = average_time.as_secs_f64() * 1000.0;
        println!("Average execution time: {:.2} milliseconds", millis);
    }

}

