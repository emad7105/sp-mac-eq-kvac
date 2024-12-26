use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};


pub fn g1_to_bytes(g1: &G1) -> Vec<u8> {
    let mut compressed_bytes = Vec::new();
    g1.serialize_compressed(&mut compressed_bytes).unwrap();

    compressed_bytes
}

pub fn g2_to_bytes(g2: &G2) -> Vec<u8> {
    let mut compressed_bytes = Vec::new();
    g2.serialize_compressed(&mut compressed_bytes).unwrap();

    compressed_bytes
}

pub fn multi_g1_to_bytes(multi_g1: &[G1]) -> Vec<Vec<u8>> {
    let mut output = vec![];
    for g1 in multi_g1 {
        let mut compressed_bytes = Vec::new();
        g1.serialize_compressed(&mut compressed_bytes).unwrap();
        output.push(compressed_bytes)
    }

    output
}

pub fn bytes_to_g1(g1_bytes: &[u8]) -> G1 {
    G1::deserialize_compressed(&*g1_bytes).unwrap()
}

pub fn bytes_to_g2(g2_bytes: &[u8]) -> G2 {
    G2::deserialize_compressed(&*g2_bytes).unwrap()
}

pub fn bytes_to_mutli_g1(g1_bytes_multi: &[Vec<u8>]) -> Vec<G1> {
    let mut output = vec![];
    for g1_bytes in g1_bytes_multi {
        let g1_bytes = G1::deserialize_compressed(&**g1_bytes).unwrap();
        output.push(g1_bytes);
    }

    output
}


pub fn scalar_field_to_bytes(scalar_field: ScalarField) -> Vec<u8> {
    let mut compressed_bytes = Vec::new();
    scalar_field.serialize_compressed(&mut compressed_bytes).unwrap();

    compressed_bytes
}

pub fn multi_scalar_field_to_bytes(multi_scalar_field: &[ScalarField]) -> Vec<Vec<u8>> {
    let mut output = vec![];
    for scalar_field in multi_scalar_field {
        let mut compressed_bytes = Vec::new();
        scalar_field.serialize_compressed(&mut compressed_bytes).unwrap();
        output.push(compressed_bytes)
    }
    output
}

pub fn bytes_to_scalar_field(scalar_field_bytes: &[u8]) -> ScalarField {
    ScalarField::deserialize_compressed(&*scalar_field_bytes).unwrap()
}

pub fn bytes_to_multi_scalar_field(scalar_field_bytes_multi: &[Vec<u8>]) -> Vec<ScalarField> {
    let mut output = vec![];
    for scalar_field_bytes in scalar_field_bytes_multi {
        let scalar_field_bytes = ScalarField::deserialize_compressed(&**scalar_field_bytes).unwrap();
        output.push(scalar_field_bytes);
    }
    output
}


pub fn multi_g1_to_hex(g1s: &[G1]) -> String {
    let mut output = "".to_string();
    let g1s_bytes =  multi_g1_to_bytes(g1s);
    for b in g1s_bytes {
        output.push_str(&hex::encode(b));
    }
    output
}