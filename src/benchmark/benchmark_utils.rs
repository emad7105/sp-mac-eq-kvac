use ark_bls12_381::{Fr as ScalarField, G1Projective as G1, G2Projective as G2, Bls12_381, G1Projective, Fr, FrConfig};
use ark_std::UniformRand;


// this prepares a random set S of attributes for testing purposes
pub fn prepare_set_S(size: usize) -> Vec<ScalarField> {
    let mut rng = ark_std::rand::thread_rng();
    let mut S = vec![];
    for i in 0..size {
        let r = ScalarField::rand(&mut rng);
        S.push(r);
    }
    S
}

pub fn prepare_set_D(size: usize, S: &[ScalarField]) -> Vec<ScalarField> {
    S.iter().take(size).cloned().collect()
}

// for calculating f_{S\D}
pub fn pick_subset_excluding_first(S: Vec<ScalarField>, D: usize) -> Vec<ScalarField> {
    // Take the subset excluding the first D elements
    let subset = &S[D..];
    subset.into()
}