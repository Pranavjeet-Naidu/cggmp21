use generic_ec::Point;
use rand::Rng;

use cggmp24::{key_share::KeyShare, ExecutionId};

cggmp24_tests::test_suite! {
    test: key_refresh_works,
    generics: all_curves,
    suites: {
        n3: (3, false),
        n5: (5, false),
        n5_reliable: (5, true),
    }
}
fn key_refresh_works<E>(n: u16, reliable_broadcast: bool)
where
    E: generic_ec::Curve + cggmp24_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
{
    let mut rng = rand_dev::DevRng::new();

    // Keygen (non-threshold n-of-n)
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let incomplete_shares = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        async move {
            cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let original_pk = incomplete_shares[0].shared_public_key;

    // Aux info generation
    let mut primes = cggmp24_tests::cached::PRIMES.iter::<E::SecurityLevel>();
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let aux_infos = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let pregenerated = primes.next().expect("Can't fetch primes");
        async move {
            cggmp24::aux_info_gen::<E::SecurityLevel>(eid, i, n, pregenerated)
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // Key refresh
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let refreshed = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let share = &incomplete_shares[usize::from(i)];
        async move {
            cggmp24::key_refresh::<E, E::SecurityLevel>(eid, share)
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    for output in &refreshed {
        assert_eq!(output.share.shared_public_key, original_pk);
    }

    let refreshed_key_shares: Vec<KeyShare<E, E::SecurityLevel>> = refreshed
        .into_iter()
        .zip(aux_infos)
        .map(|(output, aux)| {
            KeyShare::from_parts((output.share, aux)).expect("valid refreshed key share")
        })
        .collect();

    // Sign with all n parties using refreshed shares
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);
    let message_to_sign = cggmp24::signing::DataToSign::digest::<E::Digest>(&[42; 100]);
    let participants: Vec<u16> = (0..n).collect();

    let sig = round_based::sim::run_with_setup(refreshed_key_shares.iter(), |i, party, share| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let participants = participants.clone();
        async move {
            cggmp24::signing(eid, i, &participants, share)
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast)
                .sign(&mut party_rng, party, &message_to_sign)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .expect_eq();

    sig.verify(&original_pk, &message_to_sign)
        .expect("signature is not valid");
}
