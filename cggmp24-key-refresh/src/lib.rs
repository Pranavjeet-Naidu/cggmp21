//! CGGMP24 key share refresh
//!
//! This crate implements share refresh from [CGGMP24] Figure 7 without Paillier/Pedersen
//! regeneration. Non-threshold (`n`-out-of-`n`) refresh is supported
//!
//! [CGGMP24]: https://ia.cr/2021/060

#![allow(non_snake_case, clippy::too_many_arguments)]
#![forbid(missing_docs)]
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod errors;
mod non_threshold;
mod utils;

/// Protocol progress tracing
pub mod progress {
    #[doc(inline)]
    pub use cggmp24_keygen::progress::{Event, Tracer};
    #[cfg(feature = "std")]
    pub use cggmp24_keygen::progress::{PerfProfiler, PerfReport, Stderr};
}

/// Security level parameters
pub mod security_level {
    #[doc(inline)]
    pub use cggmp24_keygen::security_level::{
        define_security_level, SecurityLevel, SecurityLevel128, SecurityLevel192,
    };
}

use alloc::vec::Vec;

use digest::Digest;
use generic_ec::Curve;
use rand_core::{CryptoRng, RngCore};
use round_based::Mpc;

#[doc(inline)]
pub use key_share::{
    CoreKeyShare as IncompleteKeyShare, DirtyCoreKeyShare as DirtyIncompleteKeyShare,
    DirtyKeyInfo, InvalidCoreShare, Validate,
};

use crate::errors::IoError;
use crate::progress::Tracer;
use crate::security_level::SecurityLevel;

pub use cggmp24_keygen::ExecutionId;
pub use self::non_threshold::KeyRefreshOutput;
#[doc(no_inline)]
pub use self::non_threshold::Msg as NonThresholdMsg;

/// Default digest and security level used by [`key_refresh`]
mod default_choice {
    pub type Digest = sha2::Sha256;
    pub type SecurityLevel = crate::security_level::SecurityLevel128;
}

/// Message types for the non-threshold key refresh protocol
pub mod msg {
    /// Messages for non-threshold (`n`-out-of-`n`) key refresh
    pub mod non_threshold {
        pub use crate::non_threshold::{
            Msg, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3Broadcast, MsgRound3Unicast,
        };
    }
}

/// Key refresh protocol error
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("key refresh protocol failed to complete")]
pub struct KeyRefreshError(#[cfg_attr(feature = "std", source)] Reason);

crate::errors::impl_from! {
    impl From for KeyRefreshError {
        err: ProtocolAborted => KeyRefreshError(Reason::Aborted(err)),
        err: IoError => KeyRefreshError(Reason::IoError(err)),
        err: Bug => KeyRefreshError(Reason::Bug(err)),
        err: Reason => KeyRefreshError(err),
    }
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum Reason {
    /// Protocol was maliciously aborted by another party
    #[displaydoc("protocol was aborted by malicious party")]
    Aborted(#[cfg_attr(feature = "std", source)] ProtocolAborted),
    #[displaydoc("i/o error")]
    IoError(#[cfg_attr(feature = "std", source)] IoError),
    /// Bug occurred
    #[displaydoc("bug occurred")]
    Bug(#[cfg_attr(feature = "std", source)] Bug),
}

impl From<ProtocolAborted> for Reason {
    fn from(err: ProtocolAborted) -> Self {
        Reason::Aborted(err)
    }
}

/// Error indicating that protocol was aborted by malicious party
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum ProtocolAborted {
    #[displaydoc("party decommitment doesn't match commitment: {0:?}")]
    InvalidDecommitment(Vec<utils::AbortBlame>),
    #[displaydoc("party provided invalid masked share: {0:?}")]
    InvalidMaskedShare(Vec<utils::AbortBlame>),
    #[displaydoc("party provided invalid schnorr proof: {0:?}")]
    InvalidSchnorrProof(Vec<utils::AbortBlame>),
    #[displaydoc("round1 wasn't reliable")]
    Round1NotReliable(Vec<utils::AbortBlame>),
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum Bug {
    #[displaydoc("resulting key share is not valid")]
    Invalid(#[cfg_attr(feature = "std", source)] InvalidCoreShare),
    #[displaydoc("unexpected zero value")]
    ZeroSecret,
    #[displaydoc("unexpected zero public share")]
    ZeroPublic,
}

macro_rules! make_factory {
    ($function:ident, $variant:ident) => {
        fn $function(parties: Vec<utils::AbortBlame>) -> Self {
            Self::$variant(parties)
        }
    };
}

impl ProtocolAborted {
    make_factory!(invalid_decommitment, InvalidDecommitment);
    make_factory!(invalid_masked_share, InvalidMaskedShare);
    make_factory!(invalid_schnorr_proof, InvalidSchnorrProof);
    make_factory!(round1_not_reliable, Round1NotReliable);
}

/// Builder for non-threshold key share refresh
pub struct KeyRefreshBuilder<
    'a,
    E: Curve,
    L: SecurityLevel = crate::default_choice::SecurityLevel,
    D: Digest = crate::default_choice::Digest,
> {
    execution_id: ExecutionId<'a>,
    share: &'a IncompleteKeyShare<E>,
    reliable_broadcast_enforced: bool,
    tracer: Option<&'a mut dyn Tracer>,
    _params: core::marker::PhantomData<(E, L, D)>,
}

impl<'a, E: Curve, L: SecurityLevel, D: Digest + Clone + 'static> KeyRefreshBuilder<'a, E, L, D> {
    /// Specifies another hash function to use
    pub fn set_digest<D2>(self) -> KeyRefreshBuilder<'a, E, L, D2>
    where
        D2: Digest + Clone + 'static,
    {
        KeyRefreshBuilder {
            execution_id: self.execution_id,
            share: self.share,
            reliable_broadcast_enforced: self.reliable_broadcast_enforced,
            tracer: self.tracer,
            _params: core::marker::PhantomData,
        }
    }

    /// Specifies [security level](crate::security_level)
    pub fn set_security_level<L2>(self) -> KeyRefreshBuilder<'a, E, L2, D>
    where
        L2: SecurityLevel,
    {
        KeyRefreshBuilder {
            execution_id: self.execution_id,
            share: self.share,
            reliable_broadcast_enforced: self.reliable_broadcast_enforced,
            tracer: self.tracer,
            _params: core::marker::PhantomData,
        }
    }

    /// Sets a tracer that tracks progress of protocol execution
    pub fn set_progress_tracer(mut self, tracer: &'a mut dyn Tracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    /// Specifies whether reliable broadcast check is enforced
    pub fn enforce_reliable_broadcast(self, enforce: bool) -> Self {
        Self {
            reliable_broadcast_enforced: enforce,
            ..self
        }
    }

    /// Starts key share refresh
    pub async fn start<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<KeyRefreshOutput<E, L>, KeyRefreshError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = non_threshold::Msg<E, L, D>>,
    {
        non_threshold::run_key_refresh(
            rng,
            party,
            self.execution_id,
            self.share,
            self.tracer,
            self.reliable_broadcast_enforced,
        )
        .await
    }

    /// Returns a state machine that can be used to carry out the key refresh protocol
    #[cfg(feature = "state-machine")]
    pub fn into_state_machine<R>(
        self,
        rng: &'a mut R,
    ) -> impl round_based::state_machine::StateMachine<
        Output = Result<KeyRefreshOutput<E, L>, KeyRefreshError>,
        Msg = non_threshold::Msg<E, L, D>,
    > + 'a
    where
        R: RngCore + CryptoRng,
    {
        round_based::state_machine::wrap_protocol(|party| self.start(rng, party))
    }
}

/// Key share refresh entry point
///
/// Refreshes additive (`n`-out-of-`n`) secret shares without changing the joint public key.
/// Threshold (Shamir) shares are not supported yet.
pub fn key_refresh<'a, E>(
    eid: ExecutionId<'a>,
    share: &'a IncompleteKeyShare<E>,
) -> KeyRefreshBuilder<'a, E>
where
    E: Curve,
{
    KeyRefreshBuilder {
        execution_id: eid,
        share,
        reliable_broadcast_enforced: true,
        tracer: None,
        _params: core::marker::PhantomData,
    }
}
