#![allow(unused, unreachable_code)]
use ark_ed_on_bls12_381::Fr;
use ark_ff::Field;
use ark_std::UniformRand;
use prompt::{puzzle, welcome};
use rand::Rng;
use strong_adaptivity::utils::b2s_hash_to_field;
use strong_adaptivity::verify;
use strong_adaptivity::PUZZLE_DESCRIPTION;
use strong_adaptivity::{data::puzzle_data, Instance, Proof, ProofCommitment, ProofResponse};

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);
    let ck = puzzle_data();

    let (instance, witness, proof): (Instance, (Fr, Fr, Fr, Fr), Proof) = {
        let rng = &mut rand::thread_rng();

        // ******************** "OFFLINE PHASE" ********************
        // generate random values: a_1, r_1
        let a_1 = Fr::rand(rng);
        // compute comm_1
        let (comm_1, r_1) = ck.commit_with_rng(a_1, rng);
        // sanity check
        assert_eq!(ck.commit_with_explicit_randomness(a_1, r_1), comm_1);
        // CHEAT: defer comm_2 so we can cheat and compute this with an adaptively selected a_2 value later!
        // generate random number: r_2
        let r_2 = Fr::rand(rng);

        // ******************** "ONLINE PHASE" ********************
        // Step 1. generate random values: rho, tau (do this below using commit_with_rng)
        // CHEAT: generate 2 random r values
        // we use different values of randomness for r_rho and r_tau instead of following sigma protocol
        // which uses the same randomness r for both commitments
        // this lets us calculate a_2 adaptively from these randomness values
        let r_rho = Fr::rand(rng);
        let r_tau = Fr::rand(rng);

        // Step 2.
        // compute comm_rho = comm(rho, r_rho), comm_tau = comm(tau, r_tau),
        // where r_rho and r_tau are 2 different random r values
        let (comm_rho, rho) = ck.commit_with_rng(r_rho, rng);
        let (comm_tau, tau) = ck.commit_with_rng(r_tau, rng);
        // create the proof commitment
        let commitment = ProofCommitment { comm_rho, comm_tau };

        // compute verifier's challenge e = H(G, H, comm_rho, comm_tau)
        let challenge = b2s_hash_to_field(&(ck, commitment));

        // Step 3.
        // CHEAT: compute adaptively: a_2, s
        // a_2 = a_1 - (r_tau - r_rho) / challenge
        let r_diff = r_tau - r_rho;
        let a_2 = a_1 - r_diff / challenge;
        // s = r_rho + challenge * a_1
        let s = r_rho + challenge * a_1;

        // compute u, t honestly
        let u = rho + challenge * r_1;
        let t = tau + challenge * r_2;
        // create the proof response
        let response = ProofResponse { s, u, t };

        // CHEAT: compute deferred comm_2 using the adaptively selected a_2 != a_1
        let comm_2 = ck.commit_with_explicit_randomness(a_2, r_2);

        // construct the instance, witness, proof out of the parts we've generated in our cheating order
        let instance = Instance { comm_1, comm_2 };
        let witness = (a_1, r_1, a_2, r_2);
        let proof = Proof {
            commitment,
            response,
        };

        // return
        (instance, witness, proof)
    };
    
    let (a_1, r_1, a_2, r_2) = witness;

    assert!(verify(&ck, &instance, &proof));
    // Check that commitments are correct
    assert_eq!(ck.commit_with_explicit_randomness(a_1, r_1), instance.comm_1);
    assert_eq!(ck.commit_with_explicit_randomness(a_2, r_2), instance.comm_2);
    // Check that messages are unequal
    assert_ne!(a_1, a_2);

    println!(
        "Proof verified with unequal messages! Include comm_1, comm_2 in the challenge hash to fix the security issue."
    );
}
