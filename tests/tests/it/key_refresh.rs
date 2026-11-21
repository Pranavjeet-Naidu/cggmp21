use generic_ec::Point;
use rand::Rng;

use crate::keygen::validate_keygen_output;
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
            let keygen = cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast);

            // Keygen turns HD on unless told otherwise. These suites are the
            // non-HD case, same as `keygen_works` with `HdDisabled`.
            #[cfg(feature = "hd-wallet")]
            let keygen = keygen.hd_wallet(false);

            keygen.start(&mut party_rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let original_pk = incomplete_shares[0].shared_public_key;
    let original_public_shares: Vec<_> = incomplete_shares
        .iter()
        .map(|s| s.public_shares.clone())
        .collect();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let refreshed = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let share = &incomplete_shares[usize::from(i)];
        async move {
            cggmp24_key_refresh::non_threshold::run_key_refresh::<
                E,
                _,
                _,
                E::SecurityLevel,
                E::Digest,
            >(&mut party_rng, party, eid, share, None, reliable_broadcast)
            .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let shares: Vec<_> = refreshed.into_iter().map(|o| o.share).collect();
    validate_keygen_output::<E, cggmp24_tests::HdDisabled>(&mut rng, &shares);

    for (i, share) in shares.iter().enumerate() {
        assert_eq!(share.shared_public_key, original_pk);
        assert!(share.vss_setup.is_none());
        assert_ne!(share.public_shares, original_public_shares[i]);
    }
}

cggmp24_tests::test_suite! {
    test: threshold_key_refresh_works,
    generics: all_curves,
    suites: {
        t2n3: (2, 3, false),
        t3n5: (3, 5, false),
        t3n5_reliable: (3, 5, true),
    }
}
fn threshold_key_refresh_works<E>(t: u16, n: u16, reliable_broadcast: bool)
where
    E: generic_ec::Curve + cggmp24_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
{
    let mut rng = rand_dev::DevRng::new();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let incomplete_shares = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        async move {
            let keygen = cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast)
                .set_threshold(t);

            // Keygen turns HD on unless told otherwise. These suites are the non-HD case.
            #[cfg(feature = "hd-wallet")]
            let keygen = keygen.hd_wallet(false);

            keygen.start(&mut party_rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let original_pk = incomplete_shares[0].shared_public_key;
    let original_public_shares: Vec<_> = incomplete_shares
        .iter()
        .map(|s| s.public_shares.clone())
        .collect();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let refreshed = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let share = &incomplete_shares[usize::from(i)];
        async move {
            cggmp24_key_refresh::threshold::run_threshold_key_refresh::<
                E,
                _,
                _,
                E::SecurityLevel,
                E::Digest,
            >(&mut party_rng, party, eid, share, None, reliable_broadcast)
            .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let shares: Vec<_> = refreshed.into_iter().map(|o| o.share).collect();
    validate_keygen_output::<E, cggmp24_tests::HdDisabled>(&mut rng, &shares);

    for (i, share) in shares.iter().enumerate() {
        assert_eq!(share.shared_public_key, original_pk);
        assert!(share.vss_setup.is_some());
        assert_eq!(share.min_signers(), t);
        assert_ne!(share.public_shares, original_public_shares[i]);
    }
}

cggmp24_tests::test_suite! {
    test: key_refresh_returns_pending_share_if_ack_round_fails,
    generics: all_curves,
    suites: {
        n3: (3),
    }
}
/// Party 0's incoming stream ends as soon as it sees the first ACK. Party 0 has already
/// broadcast its own ACK at that point, so the other parties adopt the refreshed shares.
/// Party 0 must get its refreshed share back in the error instead of losing it.
fn key_refresh_returns_pending_share_if_ack_round_fails<E>(n: u16)
where
    E: generic_ec::Curve + cggmp24_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
{
    use cggmp24_key_refresh::msg::non_threshold::Msg;
    use futures::StreamExt;

    let mut rng = rand_dev::DevRng::new();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let incomplete_shares = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        async move {
            let keygen = cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>();
            keygen.start(&mut party_rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut results = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let party = party.map_delivery(|delivery| {
            let (incomings, outgoings) = round_based::Delivery::split(delivery);
            let incomings = incomings.take_while(move |msg| {
                let is_ack = matches!(msg, Ok(m) if matches!(m.msg, Msg::Ack(_)));
                futures::future::ready(i != 0 || !is_ack)
            });
            (incomings, outgoings)
        });
        let mut party_rng = rng.fork();
        let share = &incomplete_shares[usize::from(i)];
        async move {
            cggmp24_key_refresh::non_threshold::run_key_refresh::<
                E,
                _,
                _,
                E::SecurityLevel,
                E::Digest,
            >(&mut party_rng, party, eid, share, None, false)
            .await
        }
    })
    .unwrap()
    .into_vec()
    .into_iter();

    let err = match results.next().unwrap() {
        Ok(_) => panic!("party 0 was expected to fail in the ack round"),
        Err(err) => err,
    };
    assert!(format!("{err:?}").contains("has_pending_share: true"));
    let pending = err
        .into_pending_share()
        .expect("error must carry the refreshed share");

    let adopted: Vec<_> = results
        .map(|r| r.unwrap_or_else(|err| panic!("other parties must finish: {err:?}")))
        .map(|o| o.share)
        .collect();

    // The pending share belongs to the same generation the other parties adopted
    assert_eq!(pending.share.i, 0);
    assert_eq!(pending.share.public_shares, adopted[0].public_shares);
    assert_eq!(
        pending.share.shared_public_key,
        adopted[0].shared_public_key
    );
    assert_eq!(
        Point::generator() * &pending.share.x,
        pending.share.public_shares[0]
    );
    assert_ne!(
        pending.share.public_shares,
        incomplete_shares[0].public_shares
    );
}
