//! Macula's UCAN (User Controlled Authorization Networks) tokens:
//! creation, verification, and introspection, plus the policy layer a
//! provider gates an inbound CALL through.
//!
//! Ported from `macula-io/macula`'s `src/auth/macula_ucan_nif.erl` and its
//! native Rust NIF (`native/macula_ucan_nif/src/lib.rs`) — both hand-roll a
//! JWT-shaped token (`header.payload.signature`, base64url-no-pad), EdDSA
//! over Ed25519, UCAN spec version `"0.10.0"` (the older JWT-based draft;
//! **not** the current non-JWT/IPLD UCAN 1.0 spec). Confirmed directly by
//! reading the NIF's own `Cargo.toml`: no UCAN-spec crate is depended on at
//! all, only generic `ed25519-dalek`/`serde_json`/`base64`/`sha2` — because
//! no library implements 0.10.0 (the only actively maintained Rust/Go UCAN
//! libraries target the incompatible 1.0.0-rc.1 CBOR/IPLD format, per
//! `macula-go-sdk`'s own `ucan` package doc, which made the identical
//! choice porting this same reference). This module does the same: hand-
//! rolled on the crypto/serialization primitives already in this crate
//! (`ed25519-dalek` via [`crate::identity`], plus `serde`/`serde_json`/
//! `base64` added for this module), matching the reference exactly rather
//! than adopting an incompatible library.
//!
//! A token minted here verifies against `macula-go-sdk`'s `ucan` package,
//! the Erlang macula SDK, or vice versa — same header shape, same payload
//! field names (`iss`/`aud`/`exp`/`nbf`/`nnc`/`cap`/`fct`/`prf`), same
//! signing input (`header_b64 + "." + payload_b64`), same algorithm. Field
//! ORDER in the JSON is not part of the compatibility contract (a verifier
//! decodes into a struct, never re-encodes and compares bytes) — only the
//! field NAMES and the exact bytes signed matter.
//!
//! Cross-referenced against `macula-go-sdk/ucan/{ucan,policy}.go`, itself
//! independently verified against this same Erlang/Rust reference earlier
//! this session — the two ports should stay behaviorally identical.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

use crate::identity::{verify as identity_verify, KeyPair};

const ALG: &str = "EdDSA";
const TYP: &str = "JWT";
const UCV: &str = "0.10.0";

/// Errors from token creation, decoding, or verification.
#[derive(Debug)]
pub enum UcanError {
    /// Not a well-formed `header.payload.signature` triple, or a part
    /// isn't valid base64url/JSON — mirrors `macula_ucan_nif`'s
    /// `{error, invalid_token}`.
    InvalidToken,
    /// The token parsed fine but its signature does not verify against
    /// the given public key — mirrors `{error, invalid_signature}`.
    InvalidSignature,
    /// The supplied public key isn't a 32-byte Ed25519 key — mirrors
    /// `{error, invalid_public_key}`.
    InvalidPublicKey,
    /// The token's `exp` claim is in the past — mirrors `{error, expired}`.
    Expired,
    /// The token's `nbf` claim is in the future — mirrors
    /// `{error, not_yet_valid}`.
    NotYetValid,
    /// A UCAN-gated procedure was called with no token at all — mirrors
    /// `macula_station_link.erl`'s `check_ucan(<<>>, _) -> unauthorized`
    /// clause (an empty/absent token is refused before ever attempting to
    /// verify anything).
    NoToken,
}

impl std::fmt::Display for UcanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UcanError::InvalidToken => write!(f, "ucan: invalid token"),
            UcanError::InvalidSignature => write!(f, "ucan: invalid signature"),
            UcanError::InvalidPublicKey => write!(f, "ucan: invalid public key"),
            UcanError::Expired => write!(f, "ucan: token expired"),
            UcanError::NotYetValid => write!(f, "ucan: token not yet valid"),
            UcanError::NoToken => write!(f, "ucan: no token presented for a gated procedure"),
        }
    }
}

impl std::error::Error for UcanError {}

/// One entry in a UCAN token's capability list — mirrors
/// `macula_ucan_nif`'s `capability() :: #{with := binary(), can := binary()}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub with: String,
    pub can: String,
}

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    ucv: String,
}

/// The JSON shape actually signed/transmitted. Field names match the
/// reference exactly.
#[derive(Serialize, Deserialize)]
struct WirePayload {
    iss: String,
    aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nnc: Option<String>,
    cap: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fct: Option<HashMap<String, serde_json::Value>>,
    prf: Vec<String>,
}

/// A UCAN token's decoded claims — the Rust-idiomatic counterpart to
/// `WirePayload`, returned from [`decode`]/[`verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct Payload {
    pub issuer: String,
    pub audience: String,
    pub capabilities: Vec<Capability>,
    pub expires_at: Option<i64>,
    pub not_before: Option<i64>,
    pub nonce: String,
    pub facts: Option<HashMap<String, serde_json::Value>>,
    pub proofs: Vec<String>,
}

/// Optional claims for [`create`] — mirrors `macula_ucan_nif`'s
/// `ucan_opts()` map.
#[derive(Debug, Clone, Default)]
pub struct CreateOpts {
    pub expires_at: Option<i64>,
    pub not_before: Option<i64>,
    pub nonce: Option<String>,
    pub facts: Option<HashMap<String, serde_json::Value>>,
    pub proofs: Option<Vec<String>>,
}

/// Mints a new UCAN token, self-issued and signed by `id`. `issuer` and
/// `audience` are opaque DID strings (e.g. `"did:macula:io.macula.acme"`)
/// — this module does not validate or resolve DID structure, matching
/// `macula_ucan_nif:create/4,5`'s own scope exactly (that's
/// `macula_did_nif`'s job on the Erlang side, out of scope here). `id`
/// signs with its own Ed25519 private key; the resulting token verifies
/// against `id`'s public key ([`KeyPair::node_id`]), the same convention
/// every advertised capability in this SDK already uses.
pub fn create(
    issuer: &str,
    audience: &str,
    capabilities: Vec<Capability>,
    id: &KeyPair,
    opts: CreateOpts,
) -> Result<Vec<u8>, UcanError> {
    let payload = WirePayload {
        iss: issuer.to_string(),
        aud: audience.to_string(),
        exp: opts.expires_at,
        nbf: opts.not_before,
        nnc: opts.nonce,
        cap: capabilities,
        fct: opts.facts,
        prf: opts.proofs.unwrap_or_default(),
    };

    let header_json = serde_json::to_vec(&Header {
        alg: ALG.into(),
        typ: TYP.into(),
        ucv: UCV.into(),
    })
    .map_err(|_| UcanError::InvalidToken)?;
    let payload_json = serde_json::to_vec(&payload).map_err(|_| UcanError::InvalidToken)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = id.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    Ok(format!("{signing_input}.{sig_b64}").into_bytes())
}

fn split_token(token: &[u8]) -> Result<(&str, &str, &str), UcanError> {
    let text = std::str::from_utf8(token).map_err(|_| UcanError::InvalidToken)?;
    let mut parts = text.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(UcanError::InvalidToken);
    };
    Ok((h, p, s))
}

fn decode_payload(payload_b64: &str) -> Result<Payload, UcanError> {
    let raw = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| UcanError::InvalidToken)?;
    let wp: WirePayload = serde_json::from_slice(&raw).map_err(|_| UcanError::InvalidToken)?;
    Ok(Payload {
        issuer: wp.iss,
        audience: wp.aud,
        capabilities: wp.cap,
        expires_at: wp.exp,
        not_before: wp.nbf,
        nonce: wp.nnc.unwrap_or_default(),
        facts: wp.fct,
        proofs: wp.prf,
    })
}

/// Parses a UCAN token's payload WITHOUT verifying its signature or
/// checking expiration. Mirrors `macula_ucan_nif:decode/1` — same warning
/// applies: never use this for an authorization decision, only [`verify`]
/// does that.
pub fn decode(token: &[u8]) -> Result<Payload, UcanError> {
    let (_, payload_b64, _) = split_token(token)?;
    decode_payload(payload_b64)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Checks a UCAN token's signature against `public_key` (the claimed
/// issuer's 32-byte Ed25519 public key) and its `exp`/`nbf` claims against
/// the current time, returning the decoded payload only on full success.
/// Mirrors `macula_ucan_nif:verify/2` exactly, including its check ORDER —
/// public key shape, then token shape, then `exp`, then `nbf`, then
/// signature — matching both the Erlang fallback and the Rust NIF, which
/// check claims before the signature; this module preserves that order for
/// parity even though it means an invalid-but-well-formed token's expiry
/// is observable before its signature is checked.
pub fn verify(token: &[u8], public_key: &[u8; 32]) -> Result<Payload, UcanError> {
    let (header_b64, payload_b64, sig_b64) = split_token(token)?;
    let payload = decode_payload(payload_b64)?;
    let now = now_unix();
    if let Some(exp) = payload.expires_at {
        if now > exp {
            return Err(UcanError::Expired);
        }
    }
    if let Some(nbf) = payload.not_before {
        if now < nbf {
            return Err(UcanError::NotYetValid);
        }
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| UcanError::InvalidToken)?;
    let sig: [u8; 64] = sig_bytes.try_into().map_err(|_| UcanError::InvalidToken)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    if !identity_verify(signing_input.as_bytes(), &sig, public_key) {
        return Err(UcanError::InvalidSignature);
    }
    Ok(payload)
}

/// Returns a UCAN token's content identifier: SHA-256 of the raw token
/// bytes, base64url-no-pad encoded. NOT a real multihash/CIDv1 — matches
/// `macula_ucan_nif:compute_cid/1`'s own (loosely-named) scheme exactly.
/// Used only for proof-chain references between UCANs (a child token's
/// `prf` entries name parent tokens by this value).
pub fn compute_cid(token: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Decodes `token` (without verifying it) and returns its `iss` claim.
/// Mirrors `macula_ucan_nif:get_issuer/1`.
pub fn get_issuer(token: &[u8]) -> Result<String, UcanError> {
    decode(token).map(|p| p.issuer)
}

/// Decodes `token` (without verifying it) and returns its `aud` claim.
/// Mirrors `macula_ucan_nif:get_audience/1`.
pub fn get_audience(token: &[u8]) -> Result<String, UcanError> {
    decode(token).map(|p| p.audience)
}

/// Decodes `token` (without verifying it) and returns its `cap` claim.
/// Mirrors `macula_ucan_nif:get_capabilities/1`.
pub fn get_capabilities(token: &[u8]) -> Result<Vec<Capability>, UcanError> {
    decode(token).map(|p| p.capabilities)
}

/// Decodes `token` (without verifying it) and returns its `exp` claim, or
/// `None` if absent. Mirrors `macula_ucan_nif:get_expiration/1`.
pub fn get_expiration(token: &[u8]) -> Result<Option<i64>, UcanError> {
    decode(token).map(|p| p.expires_at)
}

/// Decodes `token` (without verifying it) and returns its `prf` claim.
/// Mirrors `macula_ucan_nif:get_proofs/1`.
pub fn get_proofs(token: &[u8]) -> Result<Vec<String>, UcanError> {
    decode(token).map(|p| p.proofs)
}

/// Decodes `token` (without verifying it) and reports whether its `exp`
/// claim is in the past. A token with no `exp` claim is never expired.
/// Mirrors `macula_ucan_nif:is_expired/1`.
pub fn is_expired(token: &[u8]) -> Result<bool, UcanError> {
    let payload = decode(token)?;
    Ok(match payload.expires_at {
        Some(exp) => now_unix() > exp,
        None => false,
    })
}

/// What a provider requires to answer one `(realm, procedure)`: open (any
/// identified caller, the default) or UCAN-gated (the caller's token must
/// verify against `required_issuer`). Mirrors `macula_station_link.erl`'s
/// own policy shape exactly — `open | {ucan_required, Issuer}` — where
/// `Issuer` there is the 32-byte Ed25519 public key the gate checks the
/// token's signature against, not a DID string (the reference code passes
/// it straight to `macula_ucan_nif:verify/2`, whose second argument is a
/// raw public key).
///
/// Gating happens BEFORE a handler runs — see
/// [`crate::connection::Session::serve_one_call_gated`] — so a rejected
/// caller never reaches business logic, and an accepted caller's handler
/// never sees the raw token either; the policy layer already did the only
/// thing that mattered with it.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub gated: bool,
    pub required_issuer: [u8; 32],
}

impl Policy {
    /// The default, ungated policy: any identified caller may invoke the
    /// procedure, no UCAN token needed. Equivalent to Erlang's `open`.
    pub fn open() -> Self {
        Self::default()
    }

    /// Builds a UCAN-gated policy: a caller must present a token that
    /// verifies (signature, `exp`, `nbf`) against `issuer_public_key`.
    /// Equivalent to Erlang's `{ucan_required, issuer_public_key}`.
    pub fn required(issuer_public_key: [u8; 32]) -> Self {
        Self {
            gated: true,
            required_issuer: issuer_public_key,
        }
    }

    /// Applies this policy to an inbound CALL's `ucan_token`, returning
    /// `Ok(())` if the call is authorized to proceed to lookup/dispatch.
    /// An open policy always passes; a gated policy requires `ucan_token`
    /// to [`verify`] against `required_issuer`.
    pub fn check(&self, ucan_token: &[u8]) -> Result<(), UcanError> {
        if !self.gated {
            return Ok(());
        }
        if ucan_token.is_empty() {
            return Err(UcanError::NoToken);
        }
        verify(ucan_token, &self.required_issuer).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> KeyPair {
        KeyPair::generate()
    }

    #[test]
    fn create_and_verify_round_trip() {
        let id = keypair();
        let token = create(
            "did:macula:issuer",
            "did:macula:audience",
            vec![Capability {
                with: "mri:x".into(),
                can: "read".into(),
            }],
            &id,
            CreateOpts::default(),
        )
        .unwrap();
        let payload = verify(&token, &id.node_id()).unwrap();
        assert_eq!(payload.issuer, "did:macula:issuer");
        assert_eq!(payload.audience, "did:macula:audience");
        assert_eq!(
            payload.capabilities,
            vec![Capability {
                with: "mri:x".into(),
                can: "read".into()
            }]
        );
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let id = keypair();
        let token = create("iss", "aud", vec![], &id, CreateOpts::default()).unwrap();
        let mut text = String::from_utf8(token).unwrap();
        // Flip a byte in the payload segment without corrupting base64
        // framing -- this is the same tamper strategy this crate's other
        // signed-record tests already use (see dht.rs's tests).
        let parts: Vec<&str> = text.split('.').collect();
        let mut payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        payload_bytes[0] ^= 0xFF;
        let tampered_payload = URL_SAFE_NO_PAD.encode(payload_bytes);
        text = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);
        let err = verify(text.as_bytes(), &id.node_id()).unwrap_err();
        assert!(matches!(
            err,
            UcanError::InvalidToken | UcanError::InvalidSignature
        ));
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let id = keypair();
        let other = keypair();
        let token = create("iss", "aud", vec![], &id, CreateOpts::default()).unwrap();
        let err = verify(&token, &other.node_id()).unwrap_err();
        assert!(matches!(err, UcanError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_expired() {
        let id = keypair();
        let opts = CreateOpts {
            expires_at: Some(now_unix() - 60),
            ..Default::default()
        };
        let token = create("iss", "aud", vec![], &id, opts).unwrap();
        let err = verify(&token, &id.node_id()).unwrap_err();
        assert!(matches!(err, UcanError::Expired));
    }

    #[test]
    fn verify_rejects_not_yet_valid() {
        let id = keypair();
        let opts = CreateOpts {
            not_before: Some(now_unix() + 3600),
            ..Default::default()
        };
        let token = create("iss", "aud", vec![], &id, opts).unwrap();
        let err = verify(&token, &id.node_id()).unwrap_err();
        assert!(matches!(err, UcanError::NotYetValid));
    }

    #[test]
    fn decode_does_not_check_signature() {
        let id = keypair();
        let other = keypair();
        let token = create("iss", "aud", vec![], &id, CreateOpts::default()).unwrap();
        // decode() against ANY key (or none at all) still returns the
        // payload -- it never checks the signature, matching
        // macula_ucan_nif:decode/1's own documented warning.
        let payload = decode(&token).unwrap();
        assert_eq!(payload.issuer, "iss");
        let _ = other; // not used for verification here, on purpose
    }

    #[test]
    fn getters_match_created_claims() {
        let id = keypair();
        let caps = vec![Capability {
            with: "mri:x".into(),
            can: "write".into(),
        }];
        let opts = CreateOpts {
            expires_at: Some(now_unix() + 3600),
            proofs: Some(vec!["parent-cid".into()]),
            ..Default::default()
        };
        let token = create("did:iss", "did:aud", caps.clone(), &id, opts).unwrap();
        assert_eq!(get_issuer(&token).unwrap(), "did:iss");
        assert_eq!(get_audience(&token).unwrap(), "did:aud");
        assert_eq!(get_capabilities(&token).unwrap(), caps);
        assert!(get_expiration(&token).unwrap().is_some());
        assert_eq!(get_proofs(&token).unwrap(), vec!["parent-cid".to_string()]);
        assert!(!is_expired(&token).unwrap());
    }

    #[test]
    fn is_expired_true_for_past_exp() {
        let id = keypair();
        let opts = CreateOpts {
            expires_at: Some(now_unix() - 1),
            ..Default::default()
        };
        let token = create("iss", "aud", vec![], &id, opts).unwrap();
        // is_expired() never checks the signature either -- consistent
        // with every other getter in this module.
        assert!(is_expired(&token).unwrap());
    }

    #[test]
    fn is_expired_false_with_no_exp_claim() {
        let id = keypair();
        let token = create("iss", "aud", vec![], &id, CreateOpts::default()).unwrap();
        assert!(!is_expired(&token).unwrap());
    }

    #[test]
    fn cid_is_deterministic_and_content_addressed() {
        let id = keypair();
        let token_a = create("iss", "aud", vec![], &id, CreateOpts::default()).unwrap();
        assert_eq!(compute_cid(&token_a), compute_cid(&token_a));
        let token_b = create("iss2", "aud", vec![], &id, CreateOpts::default()).unwrap();
        assert_ne!(compute_cid(&token_a), compute_cid(&token_b));
    }

    #[test]
    fn policy_open_never_requires_a_token() {
        let policy = Policy::open();
        assert!(policy.check(&[]).is_ok());
    }

    #[test]
    fn policy_required_rejects_empty_token() {
        let id = keypair();
        let policy = Policy::required(id.node_id());
        assert!(matches!(policy.check(&[]).unwrap_err(), UcanError::NoToken));
    }

    #[test]
    fn policy_required_accepts_valid_token_from_the_right_issuer() {
        let id = keypair();
        let token = create("did:iss", "did:aud", vec![], &id, CreateOpts::default()).unwrap();
        let policy = Policy::required(id.node_id());
        assert!(policy.check(&token).is_ok());
    }

    #[test]
    fn policy_required_rejects_token_from_the_wrong_issuer() {
        let id = keypair();
        let impostor = keypair();
        let token = create(
            "did:iss",
            "did:aud",
            vec![],
            &impostor,
            CreateOpts::default(),
        )
        .unwrap();
        let policy = Policy::required(id.node_id());
        assert!(matches!(
            policy.check(&token).unwrap_err(),
            UcanError::InvalidSignature
        ));
    }
}
