//! CGGMP24 key share refresh
//!
//! This crate implements share refresh from [CGGMP24] Figure 7 without Paillier/Pedersen
//! regeneration. Both non-threshold (`n`-out-of-`n`) and threshold (`t`-out-of-`n`) refresh
//! are supported
//!
//! [CGGMP24]: https://ia.cr/2021/060

#![allow(non_snake_case, clippy::too_many_arguments)]
#![forbid(missing_docs)]
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod ack;
mod errors;
/// Non-threshold (`n`-out-of-`n`) key share refresh
pub mod non_threshold;
/// Threshold (`t`-out-of-`n`) key share refresh
pub mod threshold;
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

use alloc::boxed::Box;
use alloc::vec::Vec;

#[doc(inline)]
pub use key_share::{
    CoreKeyShare as IncompleteKeyShare, DirtyCoreKeyShare as DirtyIncompleteKeyShare, DirtyKeyInfo,
    InvalidCoreShare, Validate, VssSetup,
};

use crate::errors::IoError;
use crate::security_level::SecurityLevel;

#[doc(no_inline)]
pub use self::non_threshold::Msg as NonThresholdMsg;
#[doc(no_inline)]
pub use self::threshold::Msg as ThresholdMsg;
pub use cggmp24_keygen::ExecutionId;

/// Message types for the key refresh protocols
pub mod msg {
    /// Messages for non-threshold (`n`-out-of-`n`) key refresh
    pub mod non_threshold {
        pub use crate::non_threshold::{
            Msg, MsgAck, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3Broadcast,
            MsgRound3ReliabilityCheck, MsgRound3Unicast,
        };
    }

    /// Messages for threshold (`t`-out-of-`n`) key refresh
    pub mod threshold {
        pub use crate::threshold::{
            Msg, MsgAck, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3Broadcast,
            MsgRound3ReliabilityCheck, MsgRound3Unicast,
        };
    }
}

/// Output of a key refresh protocol
pub struct KeyRefreshOutput<E: generic_ec::Curve, L: SecurityLevel> {
    /// Refreshed key share
    pub share: IncompleteKeyShare<E>,
    /// Ephemeral session identifier XOR'd from all parties' contributions
    pub rid: L::KappaBytes,
}

/// Key refresh protocol error
///
/// If the error happened during the final ACK round, after this party had already proven
/// knowledge of its refreshed share to the other parties, the error carries that refreshed
/// share. See [`KeyRefreshError::pending_share`].
pub struct KeyRefreshError<E: generic_ec::Curve, L: SecurityLevel> {
    reason: Reason,
    // Boxed to keep `Result<_, KeyRefreshError>` small on the happy path
    pending: Option<Box<KeyRefreshOutput<E, L>>>,
}

impl<E: generic_ec::Curve, L: SecurityLevel> KeyRefreshError<E, L> {
    /// Refreshed share that this party had already acknowledged when the protocol failed
    ///
    /// Returns `Some(_)` only when the protocol failed during the ACK round, after this
    /// party had computed and validated its refreshed share and started broadcasting its ACK.
    /// At that point other parties may have collected every ACK and switched to the new share,
    /// even though this party did not see every ACK. It is also possible that no party has
    /// switched.
    ///
    /// **Do not drop this share.** Persist it next to the old share, mark it as pending,
    /// and do not delete the old share until you have resolved which generation the other
    /// parties use (for example, by checking which public shares they use in the next signing
    /// session). If the share is dropped and the other parties switched, this party can no
    /// longer take part in signing.
    pub fn pending_share(&self) -> Option<&KeyRefreshOutput<E, L>> {
        self.pending.as_deref()
    }

    /// Takes the pending refreshed share out of the error
    ///
    /// See [`KeyRefreshError::pending_share`].
    pub fn into_pending_share(self) -> Option<KeyRefreshOutput<E, L>> {
        self.pending.map(|pending| *pending)
    }

    /// Error raised while the ACK round was collecting ACKs, carrying the refreshed share
    fn ack_incomplete(err: IoError, pending: KeyRefreshOutput<E, L>) -> Self {
        Self {
            reason: Reason::AckIncomplete(err),
            pending: Some(Box::new(pending)),
        }
    }
}

impl<E: generic_ec::Curve, L: SecurityLevel> core::fmt::Debug for KeyRefreshError<E, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The pending share contains secret material, so only its presence is printed
        f.debug_struct("KeyRefreshError")
            .field("reason", &self.reason)
            .field("has_pending_share", &self.pending.is_some())
            .finish()
    }
}

impl<E: generic_ec::Curve, L: SecurityLevel> core::fmt::Display for KeyRefreshError<E, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("key refresh protocol failed to complete")
    }
}

#[cfg(feature = "std")]
impl<E: generic_ec::Curve, L: SecurityLevel> std::error::Error for KeyRefreshError<E, L> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}

macro_rules! impl_from_reason {
    ($($ty:ty),+ $(,)?) => {$(
        impl<E: generic_ec::Curve, L: SecurityLevel> From<$ty> for KeyRefreshError<E, L> {
            fn from(err: $ty) -> Self {
                Self {
                    reason: err.into(),
                    pending: None,
                }
            }
        }
    )+}
}
impl_from_reason!(ProtocolAborted, IoError, Bug, InvalidArgs, Reason);

crate::errors::impl_from! {
    impl From for Reason {
        err: IoError => Reason::IoError(err),
        err: Bug => Reason::Bug(err),
        err: InvalidArgs => Reason::InvalidArgs(err),
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
    /// Invalid arguments were provided
    #[displaydoc("invalid arguments")]
    InvalidArgs(#[cfg_attr(feature = "std", source)] InvalidArgs),
    /// Threshold key share passed to non-threshold refresh
    #[displaydoc("threshold key share is not supported by non-threshold key refresh")]
    NotThreshold,
    /// Additive key share passed to threshold refresh
    #[displaydoc("additive key share is not supported by threshold key refresh")]
    ExpectedThresholdShare,
    /// ACK round failed after this party had already sent its ACK
    #[displaydoc("i/o error in ack round, refreshed share may have been adopted by other parties")]
    AckIncomplete(#[cfg_attr(feature = "std", source)] IoError),
}

/// Error indicating that caller supplied invalid arguments
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum InvalidArgs {
    #[displaydoc("party index `i` is out of bounds (must be < n)")]
    PartyIndexOutOfBounds,
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
    #[displaydoc("round3 wasn't reliable")]
    Round3NotReliable(Vec<utils::AbortBlame>),
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
    #[displaydoc("min_signers underflowed")]
    MinSignersUnderflow,
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
    make_factory!(round3_not_reliable, Round3NotReliable);
}
