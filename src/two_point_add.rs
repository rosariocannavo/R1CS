// proving i know X and Y such that Z = X+Y
// Z = public input

use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{
    marker::PhantomData,
    rand::Rng,
    UniformRand,
};
use std::ops::Mul;
use ark_r1cs_std::fields::fp::FpVar;

#[derive(Copy)]
struct PairingScalar<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{   
    x: I::G1,
    y: I::G1,
    z: I::G1,
    _iv: Option<PhantomData<IV>>,
}

impl<I, IV> PairingScalar<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    #[allow(dead_code)]
    pub fn new<R: Rng>(mut rng: R) -> Self {

        let x = I::G1::rand(&mut rng);
        let y = I::G1::rand(&mut rng);

        let z = x + y;

        Self {
            x: x,
            y: y,
            z: z,
            _iv: Some(PhantomData),
        }
    }
}

impl<I, IV> Clone for PairingScalar<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    fn clone(&self) -> Self {
        Self {
            z: self.z,
            x: self.x,
            y: self.y,
            _iv: self._iv,
        }
    }
}

impl<I, IV> ConstraintSynthesizer<<I as Pairing>::BaseField> for PairingScalar<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
    IV::G1Var: CurveVar<I::G1, I::BaseField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<I as Pairing>::BaseField>,
    ) -> Result<(), SynthesisError> {
        //Z = X + Y
        let x_var = IV::G1Var::new_witness(cs.clone(), || Ok(self.x))?;
        let y_var = IV::G1Var::new_witness(cs.clone(), || Ok(self.y))?;
        let z_var =  IV::G1Var::new_input(cs.clone(), || Ok(self.z))?;

        let x_y_var = x_var + y_var;
        
        x_y_var.enforce_equal(&z_var)?;

        Ok(())
    }
}

mod tests {

    use ark_bls12_377::{constraints::PairingVar as IV, Bls12_377 as I};

    use super::*;
    use ark_ec::bls12::Bls12;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn preimage_constraints_correctness() {
        let cs =
            ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();
        let mut rng = ark_std::test_rng();
        PairingScalar::<I, IV>::new(&mut rng)
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
mod test_groth {

    use ark_bls12_377::Bls12_377;
    use ark_bls12_377::g1::G1Projective;
    use ark_bls12_381::Bls12_381;
    use ark_ec::{pairing::Pairing, CurveGroup};
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
    use ark_std::rand::RngCore;
    use ark_std::test_rng;
    use ark_std::vec::Vec;
    type E = Bls12_377;
    use ark_relations::r1cs::ConstraintSystem;
    type Fr = <E as Pairing>::ScalarField;
    type Fp = <E as Pairing>::BaseField;    //base field here
    use super::*;
    use ark_ec::bls12::Bls12;
    type IV = ark_bls12_377::constraints::PairingVar;
    use ark_groth16::Groth16;
    use ark_bw6_761::BW6_761 as P;
    use ark_crypto_primitives::snark::SNARK;
    use rand_core::OsRng;
    use ark_ff::{ToConstraintField, Field};
    use ark_groth16::prepare_verifying_key;
    use rand_core::SeedableRng;



    #[test]
    fn test_prove_and_verify2() {
        let mut rng = ark_std::test_rng();
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let circuit = PairingScalar::<E, IV>::new(&mut rng);
        let params = Groth16::<P>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng2).unwrap();
        let pvk = prepare_verifying_key(&params.vk);
        let proof = Groth16::<P>::create_random_proof_with_reduction(circuit.clone(), &params, &mut rng).unwrap();
        
        let input_z = circuit.z.into_affine();

        let mut public_input = Vec::new();

        let one = Fp::ONE;
        
        public_input.push(input_z.x);
        public_input.push(input_z.y);
        public_input.push(one);

      


        
       assert!(Groth16::<P>::verify_proof(&pvk, &proof, public_input.as_slice() ).unwrap());
    }

}