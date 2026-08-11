use generic_ec::Point;
use rand::Rng;

use cggmp24::ExecutionId;

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
}