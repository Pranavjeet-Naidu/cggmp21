use generic_ec::{Curve, Point};
use rand::{seq::SliceRandom, Rng, RngCore};
use rand_dev::DevRng;
use sha2::Sha256;

use cggmp24::{
    key_share::{AnyKeyShare, IncompleteKeyShare, KeyShare},
    ExecutionId,
};
use cggmp24_tests::OptionalHd;

cggmp24_tests::test_suite! {
    test: full_pipeline_works,
    generics: all_curves_and_hd,
    suites: {
        t2n3: (2, 3),
        t3n5: (3, 5),
    }
}
fn full_pipeline_works<E, Hd>(t: u16, n: u16)
where
    E: Curve + cggmp24_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
    Hd: OptionalHd<E>,
{
    let mut rng = DevRng::new();
    let incomplete_shares = run_keygen::<E, Hd>(t, n, &mut rng);
    let shares = run_aux_gen(incomplete_shares, &mut rng);
    run_signing::<E, Hd>(&shares, &mut rng);
}

fn run_keygen<E, Hd>(t: u16, n: u16, rng: &mut DevRng) -> Vec<IncompleteKeyShare<E>>
where
    E: Curve + cggmp24_tests::CurveParams,
    Hd: OptionalHd<E>,
{
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        async move {
            let keygen = cggmp24::keygen(eid, i, n)
                .set_threshold(t)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>();

            #[cfg(feature = "hd-wallet")]
            let keygen = keygen.hd_wallet(Hd::ENABLED);

            keygen.start(&mut party_rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

fn run_aux_gen<E>(
    shares: Vec<IncompleteKeyShare<E>>,
    rng: &mut DevRng,
) -> Vec<KeyShare<E, E::SecurityLevel>>
where
    E: Curve + cggmp24_tests::CurveParams,
{
    let mut primes = cggmp24_tests::CACHED_PRIMES.iter();
    let n = shares.len().try_into().unwrap();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let aux_infos = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let pregenerated_data = primes.next().expect("Can't fetch primes");
        async move {
            cggmp24::aux_info_gen::<E::SecurityLevel>(eid, i, n, pregenerated_data)
                .set_digest::<E::Digest>()
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    shares
        .into_iter()
        .zip(aux_infos)
        .map(|(core, aux)| {
            KeyShare::from_parts((core, aux)).expect("Couldn't make share from parts")
        })
        .collect()
}

fn run_signing<E, Hd>(shares: &[KeyShare<E, E::SecurityLevel>], rng: &mut DevRng)
where
    E: Curve + cggmp24_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
    Hd: OptionalHd<E>,
{
    let t = shares[0].min_signers();
    let n = shares.len().try_into().unwrap();

    let optional_hd = Hd::generate_derivation_path(rng);

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut original_message_to_sign = [0u8; 100];
    rng.fill_bytes(&mut original_message_to_sign);
    let message_to_sign = cggmp24::signing::DataToSign::digest::<Sha256>(&original_message_to_sign);

    // Choose `t` signers to perform signing
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(rng);
    let participants = &participants[..usize::from(t)];
    println!("Signers: {participants:?}");
    let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

    let sig = round_based::sim::run_with_setup(participants_shares, |i, party, share| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        let optional_hd = optional_hd.clone();

        async move {
            let signing = cggmp24::signing(eid, i, participants, share).set_digest::<E::Digest>();
            let signing = optional_hd.apply(signing);

            signing.sign(&mut party_rng, party, &message_to_sign).await
        }
    })
    .unwrap()
    .expect_ok()
    .expect_eq();

    let public_key = optional_hd.derive_child_pk(&shares[0].core);

    sig.verify(&public_key, &message_to_sign)
        .expect("signature is not valid");
}
