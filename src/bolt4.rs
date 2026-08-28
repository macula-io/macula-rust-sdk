//! BOLT#4-style error taxonomy for CALL failures, ported from
//! `src/peering/macula_bolt4.erl` (`macula-io/macula`) — see
//! `plans/PLAN_WIRE_PROTOCOL.md` §9. Adapted from Lightning Network's
//! BOLT#4 onion-failure codes: a small, specific taxonomy that prevents
//! retry loops and enables post-mortem, rather than an open-ended error
//! string. Codes are stable across V2 minor versions; new codes append
//! at the next free integer.
//!
//! The retry policy is advisory — a caller's own CALL state machine is
//! the actual decision point (not implemented by this module).

/// The 17 codes macula's own `table/0` defines, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Ok = 0x00,
    UnknownNextPeer = 0x01,
    TemporaryRelayFailure = 0x02,
    RelayDisabled = 0x03,
    NodeNotFoundAtTargetRelay = 0x04,
    TargetRealmRefused = 0x05,
    LoopDetected = 0x06,
    ExpiryTooSoon = 0x07,
    UpstreamCongestion = 0x08,
    InvalidPathHeader = 0x09,
    CryptoPuzzleInvalid = 0x0A,
    RealmNotAuthoritativeHere = 0x0B,
    Tombstoned = 0x0C,
    PayloadTooLarge = 0x0D,
    SignatureInvalid = 0x0E,
    UnknownError = 0x0F,
    /// Direct-dial dual-trust: the caller lacked a valid UCAN capability
    /// for a gated procedure.
    Unauthorized = 0x10,
}

/// Whether the retry policy for a code permits retrying at all. `none`
/// (success), `application` (handler-level remedy), and `crypto_drop`
/// (security-critical) are all non-retryable — everything else means
/// "retry, differently."
impl Code {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            Code::Ok => "ok",
            Code::UnknownNextPeer => "unknown_next_peer",
            Code::TemporaryRelayFailure => "temporary_relay_failure",
            Code::RelayDisabled => "relay_disabled",
            Code::NodeNotFoundAtTargetRelay => "node_not_found_at_target_relay",
            Code::TargetRealmRefused => "target_realm_refused",
            Code::LoopDetected => "loop_detected",
            Code::ExpiryTooSoon => "expiry_too_soon",
            Code::UpstreamCongestion => "upstream_congestion",
            Code::InvalidPathHeader => "invalid_path_header",
            Code::CryptoPuzzleInvalid => "crypto_puzzle_invalid",
            Code::RealmNotAuthoritativeHere => "realm_not_authoritative_here",
            Code::Tombstoned => "tombstoned",
            Code::PayloadTooLarge => "payload_too_large",
            Code::SignatureInvalid => "signature_invalid",
            Code::UnknownError => "unknown_error",
            Code::Unauthorized => "unauthorized",
        }
    }

    pub fn is_retryable(self) -> bool {
        !matches!(
            self,
            Code::Ok
                | Code::TargetRealmRefused
                | Code::Tombstoned
                | Code::PayloadTooLarge
                | Code::Unauthorized
                | Code::CryptoPuzzleInvalid
                | Code::SignatureInvalid
        )
    }

    pub fn from_u8(code: u8) -> Option<Code> {
        Some(match code {
            0x00 => Code::Ok,
            0x01 => Code::UnknownNextPeer,
            0x02 => Code::TemporaryRelayFailure,
            0x03 => Code::RelayDisabled,
            0x04 => Code::NodeNotFoundAtTargetRelay,
            0x05 => Code::TargetRealmRefused,
            0x06 => Code::LoopDetected,
            0x07 => Code::ExpiryTooSoon,
            0x08 => Code::UpstreamCongestion,
            0x09 => Code::InvalidPathHeader,
            0x0A => Code::CryptoPuzzleInvalid,
            0x0B => Code::RealmNotAuthoritativeHere,
            0x0C => Code::Tombstoned,
            0x0D => Code::PayloadTooLarge,
            0x0E => Code::SignatureInvalid,
            0x0F => Code::UnknownError,
            0x10 => Code::Unauthorized,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_defined_code() {
        for code in 0x00u8..=0x10 {
            let parsed =
                Code::from_u8(code).unwrap_or_else(|| panic!("code {code:#x} should be defined"));
            assert_eq!(parsed.as_u8(), code);
        }
    }

    #[test]
    fn unknown_code_is_none() {
        assert_eq!(Code::from_u8(0x11), None);
        assert_eq!(Code::from_u8(0xFF), None);
    }

    #[test]
    fn non_retryable_codes_match_the_reference_table() {
        // none | application | crypto_drop, per macula_bolt4.erl's table/0.
        assert!(!Code::Ok.is_retryable());
        assert!(!Code::TargetRealmRefused.is_retryable());
        assert!(!Code::Tombstoned.is_retryable());
        assert!(!Code::PayloadTooLarge.is_retryable());
        assert!(!Code::Unauthorized.is_retryable());
        assert!(!Code::CryptoPuzzleInvalid.is_retryable());
        assert!(!Code::SignatureInvalid.is_retryable());
    }

    #[test]
    fn retryable_codes_match_the_reference_table() {
        assert!(Code::UnknownNextPeer.is_retryable());
        assert!(Code::TemporaryRelayFailure.is_retryable());
        assert!(Code::RelayDisabled.is_retryable());
        assert!(Code::NodeNotFoundAtTargetRelay.is_retryable());
        assert!(Code::LoopDetected.is_retryable());
        assert!(Code::ExpiryTooSoon.is_retryable());
        assert!(Code::UpstreamCongestion.is_retryable());
        assert!(Code::InvalidPathHeader.is_retryable());
        assert!(Code::RealmNotAuthoritativeHere.is_retryable());
        assert!(Code::UnknownError.is_retryable());
    }

    #[test]
    fn names_match_the_reference_spelling() {
        assert_eq!(Code::UnknownNextPeer.name(), "unknown_next_peer");
        assert_eq!(Code::Unauthorized.name(), "unauthorized");
    }
}
