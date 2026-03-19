use anyhow::{bail, Context, Result};
use cggmp24::{
    backend::Integer,
    key_share::{KeyShare, Validate},
    IncompleteKeyShare,
};
use generic_ec::Curve;
use rand::RngCore;
use serde_json::Value;

/// Wraps a sink to buffer the messages. Used in [`buffer_outgoing`]
#[pin_project::pin_project]
pub struct BufferedSink<M, Inner> {
    #[pin]
    messages: std::collections::VecDeque<M>,
    #[pin]
    inner: Inner,
}
type BufferedDelivery<M, D> = (
    <D as round_based::Delivery<M>>::Receive,
    BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
);

impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
    type Error = Inner::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // Always ready to buffer
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // Feed all buffered messages one by one
        while !self.messages.is_empty() {
            let mut projection = self.as_mut().project();
            let mut inner = projection.inner;
            // In case the inner sink wasn't ready, this method will be retried.
            // We rely on this and don't modify any internal state before this
            // point
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = projection.messages.pop_front() {
                inner.as_mut().start_send(item)?;
            }
        }
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

/// Modified 'Delivery' of the party to buffer outgoing messages. The messages
/// fed to the 'Delivery' sink will be buffered indefinitely until `flush` is
/// called
///
/// This is useful since the delivery used in round-based simulation doesn't do
/// buffering at all, however we want to verify that we don't forget to flush
/// the messages in our protocols. When this function is used, forgetting to
/// flush will cause the test to get stuck.
pub fn buffer_outgoing<M, D, R>(
    party: round_based::MpcParty<M, D, R>,
) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where
    M: Unpin,
    D: round_based::Delivery<M>,
    R: round_based::runtime::AsyncRuntime,
{
    party.map_delivery(|delivery| {
        let (incoming, outgoing) = delivery.split();
        let buffered_outgoing = BufferedSink::<round_based::Outgoing<M>, D::Send> {
            messages: std::collections::VecDeque::new(),
            inner: outgoing,
        };
        (incoming, buffered_outgoing)
    })
}

pub mod external_verifier;

lazy_static::lazy_static! {
    pub static ref CACHED_SHARES: PrecomputedKeyShares = {
        // note: serialized pregenerated shares take so much space, my (virtualized) compiler gets killed
        // on RAM overuse when trying to `include_str!` the file into the binary.
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../test-data/precomputed_shares.json");

        let file = std::fs::File::open(path).unwrap();
        let reader = std::io::BufReader::new(file);
        serde_json::from_reader(reader).unwrap()
    };
    pub static ref CACHED_PRIMES: PregeneratedPrimes =
        PregeneratedPrimes::from_serialized(
            include_str!("../../test-data/pregenerated_primes.json")
        ).unwrap();
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct PrecomputedKeyShares {
    /// contains only core key shares, that needs to be completed with `aux`
    shares: std::collections::BTreeMap<String, Vec<Value>>,
    /// re-usable aux data, maps `security_bits -> Vec<AuxInfo<SecurityLevel{bits}>>`
    aux: std::collections::BTreeMap<String, Vec<Value>>,
}

impl PrecomputedKeyShares {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn to_serialized(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize shares")
    }

    pub fn get_shares<E: Curve + CurveParams>(
        &self,
        t: Option<u16>,
        n: u16,
        hd_enabled: bool,
    ) -> Result<Vec<KeyShare<E, E::SecurityLevel>>> {
        let key_shares = self
            .shares
            .get(&Self::key::<E>(t, n, hd_enabled))
            .context("shares not found")?;
        let aux = self.get_aux(n).context("get aux")?;
        key_shares
            .iter()
            .cloned()
            .zip(aux)
            .map(|(share, aux)| {
                let share = serde_json::from_value(share).context("parse key share")?;
                cggmp24::KeyShare::from_parts((share, aux)).context("invalid key share")
            })
            .collect()
    }

    /// Retrieves aux data for a set of `n` signers
    fn get_aux<L>(&self, n: u16) -> Result<Vec<cggmp24::key_share::AuxInfo<L>>>
    where
        L: cggmp24::security_level::SecurityLevel,
    {
        let security_bits = L::KAPPA_BITS / 2;
        let aux = self
            .aux
            .get(&security_bits.to_string())
            .context("unsupported security level")?;
        // deserialize into DirtyAuxInfo to avoid double validation
        let aux: Vec<cggmp24::key_share::DirtyAuxInfo<L>> = aux
            .iter()
            .cloned()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .context("deserialize aux data")?;

        let n: usize = n.into();
        if n > aux.len() {
            anyhow::bail!("too many parties")
        }
        aux.iter()
            .cloned()
            .map(|mut aux| {
                aux.N.truncate(n);
                aux.pedersen_params.truncate(n);
                aux.validate()
            })
            .collect::<Result<_, _>>()
            .context("invalid resulting aux")
    }

    pub fn add_shares<E: Curve>(
        &mut self,
        t: Option<u16>,
        n: u16,
        hd_enabled: bool,
        shares: &[IncompleteKeyShare<E>],
    ) -> Result<()> {
        if usize::from(n) != shares.len() {
            bail!("expected {n} key shares, only {} provided", shares.len());
        }
        let key_shares = shares
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<_, _>>()
            .context("serialize key shares")?;
        self.shares
            .insert(Self::key::<E>(t, n, hd_enabled), key_shares);
        Ok(())
    }

    pub fn add_aux<L>(&mut self, aux: Vec<cggmp24::key_share::AuxInfo<L>>)
    where
        L: cggmp24::security_level::SecurityLevel,
    {
        let security_bits = L::KAPPA_BITS / 2;
        let aux = aux
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .expect("serialzie aux");
        self.aux.insert(security_bits.to_string(), aux);
    }

    fn key<E: Curve>(t: Option<u16>, n: u16, hd_enabled: bool) -> String {
        format!(
            "t={t:?},n={n},curve={},hd_wallet={hd_enabled}",
            E::CURVE_NAME
        )
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PregeneratedPrimes {
    /// Primes of appropriate size that can be used as Paillier private key meeting 128 bits of security
    primes_1536bits: Vec<Integer>,
    /// Primes of appropriate size that can be used as Paillier private key meeting 192 bits of security
    primes_3840bits: Vec<Integer>,
}

impl PregeneratedPrimes {
    pub fn from_serialized(repr: &str) -> Result<Self> {
        serde_json::from_str(repr).context("parse primes")
    }

    pub fn to_serialized(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize primes")
    }

    /// Iterate over numbers, producing pregenerated pairs for key refresh
    pub fn iter<L>(&self) -> impl Iterator<Item = cggmp24::key_refresh::PregeneratedPrimes<L>> + '_
    where
        L: cggmp24::security_level::SecurityLevel,
    {
        match L::RSA_PRIME_BITLEN {
            1536 => Self::iter_inner::<L>(&self.primes_1536bits),
            3840 => Self::iter_inner::<L>(&self.primes_3840bits),
            x => {
                panic!("we did not pregenerate {x} bits primes")
            }
        }
    }

    fn iter_inner<L>(
        primes: &[Integer],
    ) -> impl Iterator<Item = cggmp24::key_refresh::PregeneratedPrimes<L>> + '_
    where
        L: cggmp24::security_level::SecurityLevel,
    {
        primes.chunks(4).map(|primes| {
            let primes = [
                primes[0].clone(),
                primes[1].clone(),
                primes[2].clone(),
                primes[3].clone(),
            ];
            cggmp24::key_refresh::PregeneratedPrimes::try_from(primes)
                .expect("primes have wrong bit size")
        })
    }

    /// Generate enough primes so that you can do `amount` of key refreshes
    pub fn generate<R>(amount: usize, rng: &mut R) -> Self
    where
        R: RngCore,
    {
        Self {
            primes_1536bits: (0..amount * 4)
                .map(|_| generate_blum_prime(rng, 1536))
                .collect(),
            primes_3840bits: (0..amount * 4)
                .map(|_| generate_blum_prime(rng, 3840))
                .collect(),
        }
    }
}

/// Generates a blum prime
///
/// CGGMP24 requires using safe primes, however blum primes do not break correctness of the protocol
/// and they can be generated faster.
///
/// Only to be used in the tests.
pub fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> Integer {
    loop {
        let n: Integer = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

pub fn convert_stark_scalar(
    x: &generic_ec::Scalar<cggmp24::supported_curves::Stark>,
) -> anyhow::Result<starknet_crypto::FieldElement> {
    let bytes = x.to_be_bytes();
    debug_assert_eq!(bytes.len(), 32);
    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(bytes.as_bytes());
    starknet_crypto::FieldElement::from_bytes_be(&buffer)
        .map_err(|e| anyhow::Error::msg(format!("Can't convert scalar: {e}")))
}

pub fn convert_from_stark_scalar(
    x: &starknet_crypto::FieldElement,
) -> anyhow::Result<generic_ec::Scalar<generic_ec::curves::Stark>> {
    let bytes = x.to_bytes_be();
    generic_ec::Scalar::from_be_bytes(bytes).context("Can't read bytes")
}

#[cfg(feature = "hd-wallet")]
pub fn random_derivation_path(rng: &mut impl rand::RngCore) -> Vec<u32> {
    use rand::Rng;
    let len = rng.gen_range(1..=3);
    std::iter::repeat_with(|| rng.gen_range(0..cggmp24::hd_wallet::H))
        .take(len)
        .collect::<Vec<_>>()
}

/// Parameters per each curve that are needed in tests
pub trait CurveParams: Curve {
    /// Which HD derivation algorithm to use with that curve
    #[cfg(feature = "hd-wallet")]
    type HdAlgo: cggmp24::hd_wallet::HdWallet<Self>;
    /// External verifier for signatures on this curve
    type ExVerifier: external_verifier::ExternalVerifier<Self>;
    type SecurityLevel: cggmp24::security_level::SecurityLevel;

    /// Hash function that should be used with this curve
    ///
    /// Note that we need digest output to be Unpin for protocol messages to be Unpin. It's not easy
    /// to express that requirement in traits, we do that by introducing two dummy associated types:
    /// [`CurveParams::DigestOutSize`] and [`CurveParams::DigestOutArray`]
    type Digest: digest::Digest<OutputSize = Self::DigestOutSize> + Clone + 'static;
    /// Dummy associated type to express that digest output must be `Unpin`
    ///
    /// Implementation should always write:
    /// ```rust
    /// type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    /// ```
    type DigestOutSize: digest::generic_array::ArrayLength<u8, ArrayType = Self::DigestOutArray>;
    /// Dummy associated type to express that digest output must be `Unpin`
    ///
    /// Implementation should always write:
    /// ```rust
    /// type DigestOutArray =
    ///     <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
    /// ```
    type DigestOutArray: Unpin;
}

impl CurveParams for cggmp24::supported_curves::Secp256k1 {
    #[cfg(feature = "hd-wallet")]
    type HdAlgo = cggmp24::hd_wallet::Slip10;
    type ExVerifier = external_verifier::blockchains::Bitcoin;
    type SecurityLevel = cggmp24::security_level::SecurityLevel128;
    type Digest = sha2::Sha256;
    type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    type DigestOutArray =
        <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
}

impl CurveParams for cggmp24::supported_curves::Secp256r1 {
    #[cfg(feature = "hd-wallet")]
    type HdAlgo = cggmp24::hd_wallet::Slip10;
    type ExVerifier = external_verifier::Noop;
    type SecurityLevel = cggmp24::security_level::SecurityLevel128;
    type Digest = sha2::Sha256;
    type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    type DigestOutArray =
        <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
}

impl CurveParams for cggmp24::supported_curves::Secp384r1 {
    #[cfg(feature = "hd-wallet")]
    type HdAlgo = NoHd;
    type ExVerifier = external_verifier::Noop;
    type SecurityLevel = cggmp24::security_level::SecurityLevel192;
    type Digest = sha2::Sha384;
    type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    type DigestOutArray =
        <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
}

impl CurveParams for cggmp24::supported_curves::Stark {
    #[cfg(feature = "hd-wallet")]
    type HdAlgo = cggmp24::hd_wallet::Stark;
    type ExVerifier = external_verifier::blockchains::StarkNet;
    type SecurityLevel = cggmp24::security_level::SecurityLevel128;
    type Digest = sha2::Sha256;
    type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    type DigestOutArray =
        <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
}

// TODO: `NoHd` is to be removed before merging the PR. It's quick hack to make lib compile
// before I do architectural changes
#[cfg(feature = "hd-wallet")]
pub struct NoHd;
#[cfg(feature = "hd-wallet")]
impl hd_wallet::DeriveShift<cggmp24::supported_curves::Secp384r1> for NoHd {
    fn derive_public_shift(
        _parent_public_key: &hd_wallet::ExtendedPublicKey<cggmp24::supported_curves::Secp384r1>,
        _child_index: hd_wallet::NonHardenedIndex,
    ) -> hd_wallet::DerivedShift<cggmp24::supported_curves::Secp384r1> {
        panic!("no HD for this curve, sorry")
    }

    fn derive_hardened_shift(
        _parent_key: &hd_wallet::ExtendedKeyPair<cggmp24::supported_curves::Secp384r1>,
        _child_index: hd_wallet::HardenedIndex,
    ) -> hd_wallet::DerivedShift<cggmp24::supported_curves::Secp384r1> {
        panic!("no HD for this curve, sorry")
    }
}

/// Trait used by the tests to enable/disable HD wallets
///
/// Motivation for this trait is to have one test function that tests the code (keygen or signing)
/// with and without HD derivation, with and without `feature = "hd-wallet"`, taking into account
/// that some curves do not have support of HD derivation at all
///
/// Two structs implement this trait:
/// - [`HdDisabled`] that does no HD. All trait methods are no-op.
/// - [`HdEnabled<Algo>`](HdEnabled) that does HD derivation with `Algo`.
pub trait OptionalHd<E: Curve>: Clone {
    /// Indicates whether HD derivation is enabled
    const ENABLED: bool;

    /// Generates derivation path if HD is enabled
    fn generate_derivation_path(rng: &mut impl RngCore) -> Self;

    /// Applies derivation path (if enabled) to the signing builder
    fn apply<'r, L, D>(
        &self,
        builder: cggmp24::signing::SigningBuilder<'r, E, L, D>,
    ) -> cggmp24::signing::SigningBuilder<'r, E, L, D>
    where
        generic_ec::NonZero<generic_ec::Point<E>>: generic_ec::coords::AlwaysHasAffineX<E>,
        L: cggmp24::security_level::SecurityLevel,
        D: digest::Digest + Clone + 'static;

    /// Uses derivation path to derive a child public key
    ///
    /// If HD is disabled, this function returns the public key as is.
    fn derive_child_pk(
        &self,
        share: &cggmp24::key_share::DirtyIncompleteKeyShare<E>,
    ) -> generic_ec::NonZero<generic_ec::Point<E>>;
}

#[derive(Clone)]
pub struct HdDisabled;
impl<E: Curve> OptionalHd<E> for HdDisabled {
    const ENABLED: bool = false;
    fn generate_derivation_path(_rng: &mut impl RngCore) -> Self {
        Self
    }

    fn apply<'r, L, D>(
        &self,
        builder: cggmp24::signing::SigningBuilder<'r, E, L, D>,
    ) -> cggmp24::signing::SigningBuilder<'r, E, L, D>
    where
        generic_ec::NonZero<generic_ec::Point<E>>: generic_ec::coords::AlwaysHasAffineX<E>,
        L: cggmp24::security_level::SecurityLevel,
        D: digest::Digest + Clone + 'static,
    {
        builder
    }

    fn derive_child_pk(
        &self,
        share: &cggmp24::key_share::DirtyIncompleteKeyShare<E>,
    ) -> generic_ec::NonZero<generic_ec::Point<E>> {
        share.shared_public_key
    }
}

#[cfg(feature = "hd-wallet")]
pub struct HdEnabled<Algo> {
    path: Vec<hd_wallet::NonHardenedIndex>,
    _algo: core::marker::PhantomData<Algo>,
}
#[cfg(feature = "hd-wallet")]
impl<E, Algo> OptionalHd<E> for HdEnabled<Algo>
where
    E: Curve,
    Algo: hd_wallet::DeriveShift<E>,
{
    const ENABLED: bool = true;

    fn generate_derivation_path(rng: &mut impl RngCore) -> Self {
        use rand::Rng;
        let len = rng.gen_range(1..=3);
        let path = std::iter::repeat_with(|| rng.gen_range(0..cggmp24::hd_wallet::H))
            .take(len)
            .map(|index| index.try_into())
            .collect::<Result<Vec<_>, _>>()
            .expect("generated hardened index");
        eprintln!("derivation path: {path:?}");
        Self {
            path,
            _algo: core::marker::PhantomData,
        }
    }

    fn apply<'r, L, D>(
        &self,
        builder: cggmp24::signing::SigningBuilder<'r, E, L, D>,
    ) -> cggmp24::signing::SigningBuilder<'r, E, L, D>
    where
        generic_ec::NonZero<generic_ec::Point<E>>: generic_ec::coords::AlwaysHasAffineX<E>,
        L: cggmp24::security_level::SecurityLevel,
        D: digest::Digest + Clone + 'static,
    {
        builder
            .set_derivation_path_with_algo::<Algo, _>(self.path.iter().copied())
            .expect("hd is disabled for this key")
    }

    fn derive_child_pk(
        &self,
        share: &cggmp24::key_share::DirtyIncompleteKeyShare<E>,
    ) -> generic_ec::NonZero<generic_ec::Point<E>> {
        generic_ec::NonZero::from_point(
            share
                .derive_child_public_key::<Algo, _>(self.path.iter().copied())
                .expect("hd is disabled for this key")
                .public_key,
        )
        .unwrap()
    }
}
#[cfg(feature = "hd-wallet")]
impl<Algo> Clone for HdEnabled<Algo> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            _algo: core::marker::PhantomData,
        }
    }
}

#[macro_export]
macro_rules! test_suite {
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: all_curves,
        suites: {$($suites:tt)*}
        $(,)?
    ) => {
        $crate::test_suite! {
            $(async_test: $async_test,)?
            $(test: $test,)?
            generics: {
                secp256k1: <cggmp24::supported_curves::Secp256k1>,
                secp256r1: <cggmp24::supported_curves::Secp256r1>,
                secp384r1: <cggmp24::supported_curves::Secp384r1>,
                stark: <cggmp24::supported_curves::Stark>,
            },
            suites: {$($suites)*}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: all_curves_and_hd,
        suites: {$($suites:tt)*}
        $(,)?
    ) => {
        $crate::test_suite! {
            $(async_test: $async_test,)?
            $(test: $test,)?
            generics: {
                secp256k1: <cggmp24::supported_curves::Secp256k1, cggmp24_tests::HdDisabled>,
                secp256r1: <cggmp24::supported_curves::Secp256r1, cggmp24_tests::HdDisabled>,
                secp384r1: <cggmp24::supported_curves::Secp384r1, cggmp24_tests::HdDisabled>,
                stark: <cggmp24::supported_curves::Stark, cggmp24_tests::HdDisabled>,

                #[cfg(feature = "hd-wallet")]
                secp256k1_hd: <cggmp24::supported_curves::Secp256k1, cggmp24_tests::HdEnabled<hd_wallet::Slip10>>,
                #[cfg(feature = "hd-wallet")]
                secp256r1_hd: <cggmp24::supported_curves::Secp256r1, cggmp24_tests::HdEnabled<hd_wallet::Slip10>>,
                #[cfg(feature = "hd-wallet")]
                stark_hd: <cggmp24::supported_curves::Stark, cggmp24_tests::HdEnabled<hd_wallet::Stark>>,
            },
            suites: {$($suites)*}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: {$(
            $(#[$attr:meta])*
            $gmod:ident: <$($generic:path),*>
        ),+$(,)?},
        suites: {$($suites:tt)*}
        $(,)?
    ) => {
        mod $($test)? $($async_test)? {
            use super::$($test)? $($async_test)?;
            $crate::test_suite_traverse! {
                $(async_test: $async_test,)?
                $(test: $test,)?
                generics: {$($(#[$attr])* $gmod: <$($generic),+>),+},
                suites: {$($suites)*}
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! test_suite_traverse {
    (
        // Either `$async_test` or `$test` must be present, but not at the same time
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        // we traverse over `generics`
        generics: {
            $(#[$attr:meta])*
            $gmod:ident: <$($generic:path),*>
            $(, $($generics_rest:tt)*)?
        },
        suites: {$($suites:tt)*}
    ) => {
        $(#[$attr])*
        mod $gmod {
            use super::$($test)? $($async_test)?;
            $crate::test_suite_traverse! {
                $(async_test: $async_test,)?
                $(test: $test,)?
                generics: <$($generic),+>,
                suites: {$($suites)*}
            }
        }
        $crate::test_suite_traverse! {
            $(async_test: $async_test,)?
            $(test: $test,)?
            generics: {
                $($($generics_rest)*)?
            },
            suites: {$($suites)*}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        // generics list is empty - nothing to traverse
        generics: {},
        suites: {$($suites:tt)*}
    ) => {};

    (
        async_test: $test:ident,
        generics: <$($generic:path),*>,
        // we traverse async suites
        suites: {
            $(#[$attr:meta])*
            $suite_name:ident: ($($args:tt)*)
            $(, $($rest:tt)*)?
        }
    ) => {
        $(#[$attr])*
        #[tokio::test]
        async fn $suite_name() {
            $test::<$($generic),+>($($args)*).await
        }

        $crate::test_suite_traverse! {
            async_test: $test,
            generics: <$($generic),*>,
            suites: {$($($rest)*)?}
        }
    };
    (
        test: $test:ident,
        generics: <$($generic:path),*>,
        // we traverse sync suites
        suites: {
            $(#[$attr:meta])*
            $suite_name:ident: ($($args:tt)*)
            $(, $($rest:tt)*)?
        }
    ) => {
        $(#[$attr])*
        #[test]
        fn $suite_name() {
            $test::<$($generic),+>($($args)*)
        }

        $crate::test_suite_traverse! {
            test: $test,
            generics: <$($generic),*>,
            suites: {$($($rest)*)?}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: <$($generic:path),*>,
        // suites list is empty - nothing to traverse
        suites: {}
    ) => {};
}
