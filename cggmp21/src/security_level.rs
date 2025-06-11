//! Security level of CGGMP protocol
//!
//! Security level is defined as set of parameters in the CGGMP paper. Higher security level gives more
//! security but makes protocol execution slower.
//!
//! We provide a predefined default [SecurityLevel128].
//!
//! You can define your own security level using macro [define_security_level]. Be sure that you properly
//! analyzed the CGGMP paper and you understand implications. Inconsistent security level may cause unexpected
//! unverbose runtime error or reduced security of the protocol.

use crate::rug::Integer;

/// Security level of CGGMP21 DKG protocol
pub use cggmp21_keygen::security_level::SecurityLevel as KeygenSecurityLevel;

/// Hardcoded value for parameter $m$ of security level
///
/// Currently, [security parameter $m$](SecurityLevel::M) is hardcoded to this constant. We're going to fix that
/// once `feature(generic_const_exprs)` is stable.
pub const M: usize = 128;

/// Security level of the CGGMP21 protocol
///
/// You should not implement this trait manually. Use [define_security_level] macro instead.
pub trait SecurityLevel: KeygenSecurityLevel {
    /// Length of RSA prime that matches [Self::SECURITY_BITS]
    const RSA_PRIME_BITLEN: u32;
    /// Minimal length of RSA public key (bi-prime $N = pq$) that matches [Self::SECURITY_BITS]
    const RSA_PUBKEY_BITLEN: u32;

    /// $\varepsilon$ bits
    const EPSILON: usize;

    /// $\ell$ parameter
    const ELL: usize;
    /// $\ell'$ parameter
    const ELL_PRIME: usize;

    /// $q$ parameter
    ///
    /// Note that it's not curve order, and it doesn't need to be a prime, it's another security parameter
    /// that determines security level.
    fn q() -> Integer;
}

/// Determines max size of exponents
///
/// During the CGGMP21 protocol, we often calculate $s^x t^y \mod N$. Given the security level
/// we can determine max size of $x$ and $y$ in bits.
///
/// Size of exponents can be used to build a [multiexp table](paillier_zk::multiexp).
///
/// Returns `(x_bits, y_bits)`
pub fn max_exponents_size<L: SecurityLevel>() -> (u32, u32) {
    use std::cmp;

    let x_bits = cmp::max(
        L::ELL as u32 + L::EPSILON as u32 + 4 * L::SECURITY_BITS,
        (L::ELL_PRIME + L::EPSILON) as _,
    );
    let y_bits = (L::ELL + L::EPSILON) as u32 + 8 * L::SECURITY_BITS;

    (x_bits, y_bits)
}

/// Internal module that's powers `define_security_level` macro
#[doc(hidden)]
pub mod _internal {

    pub use crate::rug::Integer;
    pub use cggmp21_keygen::security_level::{
        define_security_level as define_keygen_security_level, SecurityLevel as KeygenSecurityLevel,
    };
}

/// Defines security level
///
/// ## Example
///
/// This code defines security level corresponding to $\kappa=1024$, $\varepsilon=128$, $\ell = \ell' = 1024$,
/// $m = 128$, and $q = 2^{48}-1$ (note: choice of parameters is random, it does not correspond to meaningful
/// security level):
/// ```rust
/// use cggmp21::security_level::define_security_level;
/// use cggmp21::rug::Integer;
///
/// #[derive(Clone)]
/// pub struct MyLevel;
/// define_security_level!(MyLevel{
///     security_bits = 1024,
///     epsilon = 128,
///     ell = 1024,
///     ell_prime = 1024,
///     m = 128,
///     q = (Integer::ONE.clone() << 48_u32) - 1,
/// });
/// ```
///
/// **Note:** currently, security parameter $m$ is hardcoded to the [`M = 128`](M) due to compiler limitations.
/// Setting any other value of $m$ results into compilation error. We're going to fix that once `generic_const_exprs`
/// feature is stable.
#[macro_export]
macro_rules! define_security_level {
    ($struct_name:ident {
        security_bits: $k:expr,
        rsa_prime_bitlen: $rsa_prime_bitlen:expr,
        rsa_pubkey_bitlen: $rsa_pubkey_bitlen:expr,
        epsilon: $e:expr,
        ell: $ell:expr,
        ell_prime: $ell_prime:expr,
        m: $m:tt,
        q: $q:expr,
    }) => {
        $crate::define_security_level! {
            $struct_name {
                rsa_prime_bitlen: $rsa_prime_bitlen,
                rsa_pubkey_bitlen: $rsa_pubkey_bitlen,
                epsilon: $e,
                ell: $ell,
                ell_prime: $ell_prime,
                m: $m,
                q: $q,
            }
        }
        $crate::security_level::_internal::define_keygen_security_level! {
            $struct_name {
                security_bits: $k,
            }
        }
    };
    ($struct_name:ident {
        rsa_prime_bitlen: $rsa_prime_bitlen:expr,
        rsa_pubkey_bitlen: $rsa_pubkey_bitlen:expr,
        epsilon: $e:expr,
        ell: $ell:expr,
        ell_prime: $ell_prime:expr,
        m: 128,
        q: $q:expr,
    }) => {
        impl $crate::security_level::SecurityLevel for $struct_name {
            const RSA_PRIME_BITLEN: u32 = $rsa_prime_bitlen;
            const RSA_PUBKEY_BITLEN: u32 = $rsa_pubkey_bitlen;
            const EPSILON: usize = $e;
            const ELL: usize = $ell;
            const ELL_PRIME: usize = $ell_prime;

            fn q() -> $crate::security_level::_internal::Integer {
                $q
            }
        }
    };
    ($struct_name:ident {
        rsa_prime_bitlen: $rsa_prime_bitlen:expr,
        rsa_pubkey_bitlen: $rsa_pubkey_bitlen:expr,
        epsilon: $e:expr,
        ell: $ell:expr,
        ell_prime: $ell_prime:expr,
        m: $m:tt,
        q: $q:expr,
    }) => {
        compile_error!(concat!("Currently, we can not set security parameter M to anything but 128 (you set m=", stringify!($m), ")"));
    };
}

#[doc(inline)]
pub use define_security_level;

#[doc(inline)]
pub use cggmp21_keygen::security_level::SecurityLevel128;
define_security_level!(SecurityLevel128 {
    rsa_prime_bitlen: 1536,
    rsa_pubkey_bitlen: 3071,
    epsilon: 256,
    ell: 128,
    ell_prime: 640,
    m: 128,
    q: (Integer::ONE << 128_u32).into(),
});

/// Checks that public paillier key meets security level constraints
pub(crate) fn validate_public_paillier_key_size<L: SecurityLevel>(N: &Integer) -> bool {
    N.significant_bits() >= L::RSA_PUBKEY_BITLEN
}

/// Checks that a prime, that is a part of secret paillier key, meets security level constraints
pub(crate) fn validate_secret_paillier_prime_size<L: SecurityLevel>(prime: &Integer) -> bool {
    prime.significant_bits() >= L::RSA_PRIME_BITLEN
}
