use std::ops::{Add, Mul};
use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, Fr};
use ark_std::UniformRand;
use ark_ec::PrimeGroup;
use ark_std::Zero;
use ark_ff::fields::Field;
use ark_ec::pairing::{Pairing};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, Rng};


#[derive(Debug,PartialEq, Clone)]
pub struct SpMacEq {
    /// R point
    pub R: G1,
    /// T point
    pub T: G2,
}

impl SpMacEq {
    pub fn generate_key(l: usize) -> Vec<ScalarField> {
        let mut rng = ark_std::rand::thread_rng(); // todo

         vec![ScalarField::rand(&mut rng); l]
    }

    pub fn to_bytes_sk(sk: Vec<Fr>) -> Vec<Vec<u8>> {
        let mut bytes = Vec::new();
        for s in sk {
            let mut compressed_bytes = Vec::new();
            s.serialize_compressed(&mut compressed_bytes).unwrap();
            bytes.push(compressed_bytes)
        }
        bytes
    }

    pub fn to_hex(sk_bytes: &[Vec<u8>]) -> Vec<String> {
        let mut sk_hex = vec![];
        // let sk_bytes_clone = sk_bytes.to_vec().clone();
        for s_bytes in sk_bytes {
            let s = hex::encode(s_bytes);
            sk_hex.push(s)
        }
        sk_hex
    }

    pub fn from_hex(sk_hex: &[String]) -> Vec<Vec<u8>> {
        let mut sk_bytes = vec![];
        // let sk_bytes_clone = sk_bytes.to_vec().clone();
        for s_bytes in sk_hex {
            let s = hex::decode(s_bytes).unwrap();
            sk_bytes.push(s)
        }
        sk_bytes
    }

    pub fn to_bytes(&self) -> Vec<Vec<u8>> {
        let r_bytes = crate::protocols::hex_utils::g1_to_bytes(&self.R);
        let t_bytes = crate::protocols::hex_utils::g2_to_bytes(&self.T);
        vec![r_bytes,t_bytes]
    }

    pub fn from_bytes(bytes: &[Vec<u8>]) -> Self {
        let r = crate::protocols::hex_utils::bytes_to_g1(bytes.get(0).unwrap());
        let t = crate::protocols::hex_utils::bytes_to_g2(bytes.get(1).unwrap());

        SpMacEq{
            R: r,
            T: t,
        }
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

    pub fn mac_test(sk: &[ScalarField], messages: &[G1]) -> SpMacEq {
        // let mut rng = ark_std::rand::thread_rng(); // todo
        let mut rng = ark_std::test_rng();

        let a = ScalarField::rand(&mut rng);
        // zero checking

        let mut R:G1 = G1::zero();
        for (m, key) in messages.into_iter().zip(sk) {
            R += m.mul(key);
        }
        R *= a;

        let mut T:G2 = G2::generator();
        T *= a.inverse().expect("It will never be zero");

        SpMacEq {
            R,
            T,
        }
    }

    pub fn mac<R: Rng + CryptoRng>(sk: &[ScalarField], messages: &[G1], rng: &mut R) -> SpMacEq {
        // let mut rng = ark_std::rand::thread_rng(); // todo

        let a = ScalarField::rand(rng);
        // zero checking

        SpMacEq::mac_with_a(sk, messages, &a)
    }

    pub fn mac_with_a(sk: &[ScalarField], messages: &[G1], a: &ScalarField) -> SpMacEq {
        // let mut rng = ark_std::rand::thread_rng(); // todo

        // zero checking

        let mut R:G1 = G1::zero();
        for (m, key) in messages.into_iter().zip(sk) {
            R += m.mul(key);
        }
        R *= a;

        let mut T:G2 = G2::generator();
        T *= a.inverse().expect("It will never be zero");

        SpMacEq {
            R,
            T,
        }
    }

    pub fn verify(sk: &[ScalarField], signature: &SpMacEq, messages: &[G1]) -> bool {
        let mut sum: G1Projective = messages[0].mul(&sk[0]);
        for (m, x) in messages.into_iter().zip(sk).skip(1) {
            sum = sum.add(m.mul(x));
        }
        let lhs1 = Bls12_381::pairing(sum, G2::generator()).0;
        let rhs1 = Bls12_381::pairing(&signature.R, &signature.T).0;

        lhs1 == rhs1
    }

    pub fn change_representation<R: Rng + CryptoRng>(mac: &SpMacEq, rng: &mut R) -> SpMacEq {
        // let mut rng = ark_std::rand::thread_rng(); // todo
        let r1 = ScalarField::rand(rng);
        SpMacEq::change_representation_with_rand(mac, &r1, rng)
    }

    pub fn change_representation_with_rand<R: Rng + CryptoRng>(mac: &SpMacEq, r1: &ScalarField, rng: &mut R) -> SpMacEq {
        // let mut rng = ark_std::rand::thread_rng(); // todo
        let r2 = ScalarField::rand(rng);

        // randomize message
        // let rnd_messages: Vec<G1> = messages
        //     .to_owned()
        //     .into_iter()
        //     .map(|mut g| {
        //         g *= r1;
        //         g
        //     })
        //     .collect();

        // randomize mac
        let mut rnd_R:&G1 = &mac.R.mul(r1);
        //rnd_R = &rnd_R.mul(&r2);
        let binding = rnd_R.mul(&r2);
        rnd_R = &binding;

        let inverse_r2 = r2.inverse().expect("Inversion error");
        let rnd_T:&G2 = &mac.T.mul(&inverse_r2);

        let rnd_mac = SpMacEq {
            R: rnd_R.clone(),
            T: rnd_T.clone(),
        };

        rnd_mac
    }

    pub fn change_representation_with_message<R: Rng + CryptoRng>(mac: &SpMacEq, messages: &[G1], rng: &mut R) -> (Vec<G1>, SpMacEq) {
        // let mut rng = ark_std::rand::thread_rng(); // todo
        let r1 = ScalarField::rand(rng);
        SpMacEq::change_representation_with_rand_with_message(mac, messages, &r1, rng)
    }

    pub fn change_representation_with_rand_with_message<R: Rng + CryptoRng>(mac: &SpMacEq, messages: &[G1], r1: &ScalarField, rng: &mut R) -> (Vec<G1>, SpMacEq) {
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

        // randomize mac
        let mut rnd_R:&G1 = &mac.R.mul(r1);
        //rnd_R = &rnd_R.mul(&r2);
        let binding = rnd_R.mul(&r2);
        rnd_R = &binding;

        let inverse_r2 = r2.inverse().expect("Inversion error");
        let rnd_T:&G2 = &mac.T.mul(&inverse_r2);

        let rnd_mac = SpMacEq {
            R: rnd_R.clone(),
            T: rnd_T.clone(),
        };

        (rnd_messages, rnd_mac)
    }
}



#[cfg(test)]
mod spmaceq_mac_tests {
    use rand::rngs::OsRng;
    use super::*;

    #[test]
    fn full_test() {
        let l = 2;
        let sk = SpMacEq::generate_key(l);
        // println!("sk: {:?}", key_pair.sk);
        // println!("vk: {:?}", );
        // assert_eq!(result, 4);

        let messages = vec![G1::generator(), G1::zero()];
        let mut rng = OsRng;

        let mac = SpMacEq::mac(&sk, &messages, &mut rng);
        let result = SpMacEq::verify(&sk, &mac, &messages);
        println!("Mac: {:?}", mac);
        println!("verify: {:?}", result);

        let rnd_mac = SpMacEq::change_representation(&mac, &mut rng);
        let rnd_result = SpMacEq::verify(&sk, &rnd_mac, &messages);
        println!("RND_Mac: {:?}", rnd_mac);
        println!("RND_verify: {:?}", rnd_result);

        let rnd_mac_bytes = rnd_mac.to_bytes();
        let rnd_mac_from_bytes = SpMacEq::from_bytes(&rnd_mac_bytes);

        assert_eq!(rnd_mac, rnd_mac_from_bytes);
    }

    #[test]
    fn kgen_test() {
        let l = 2;
        let sk = SpMacEq::generate_key(l);

        let sk_bytes = SpMacEq::to_bytes_sk(sk.clone());

        let sk_hex = SpMacEq::to_hex(&sk_bytes);
        let sk_bytes_decoded = SpMacEq::from_hex(&sk_hex);
        let sk_decoded = SpMacEq::from_bytes_sk(&sk_bytes_decoded);
        println!("Sp-Mac SK: {:?}", sk_hex);

        assert_eq!(sk, sk_decoded);
    }

    #[test]
    fn gen_rand_scalar_field() {
        let mut rng = ark_std::rand::thread_rng(); // todo
        let rand = ScalarField::rand(&mut rng);

        // ScalarField to bytes
        let mut compressed_bytes = Vec::new();
        rand.serialize_compressed(&mut compressed_bytes).unwrap();

        // bytes to hex
        let rand_hex = hex::encode(compressed_bytes);

        println!("Rand hex: {:?}", rand_hex);
    }
}

