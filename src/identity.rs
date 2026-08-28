//! Ed25519 identity and the S/Kademlia crypto puzzle, matching macula's
//! own `macula_identity.erl` (`macula-io/macula`).
//!
//! Uses `ed25519-dalek` 2.1 with the `rand_core` feature — the exact same
//! crate and version macula's own `macula_crypto_nif` Rust NIF already
//! wraps in production, not a separate crypto implementation. Every
//! keypair/sign/verify test in this module is checked against fixtures
//! captured directly from the real `crypto:generate_key/2` and
//! `crypto:sign/4` in `macula-io/macula`'s own `rebar3 shell`, not just
//! hand-derived expectations — Ed25519 signing is deterministic per
//! RFC 8032, so the same seed and message must produce byte-identical
//! signatures across implementations if both are correct.
//!
//! A macula NodeId **is** an Ed25519 public key (32 bytes) — there is no
//! separate account/identity layer underneath it. Identities are
//! optionally "puzzle-hardened": ground until `SHA-256(pubkey)` has at
//! least `N` leading zero bits (S/Kademlia Sybil defense — this raises
//! the cost of *minting* identities in bulk, not of connecting with one
//! that already exists). Grinding is a one-time cost paid once per
//! identity, not per connection: `puzzle_evidence` is a cheap,
//! deterministic hash computed fresh on every `CONNECT` frame, and
//! `puzzle_valid` is a cheap check, not a proof-of-work re-verification.
//!
//! **Every station checks this on every CONNECT/HELLO, for every kind of
//! dialer — this is not a station-to-station-only concern.** Skipping it
//! produces a real, previously-observed failure mode: the QUIC/TLS
//! connection reports healthy, but the station silently rejects the
//! application-layer HELLO, so the link looks connected while delivering
//! nothing. Always use [`KeyPair::generate_with_puzzle`], never
//! [`KeyPair::generate`], for any identity that will actually dial a
//! station.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Matches `?DEFAULT_PUZZLE_DIFFICULTY` in `macula_identity.erl`. Grinding
/// at this difficulty is sub-millisecond — see the module doc.
pub const DEFAULT_PUZZLE_DIFFICULTY: u32 = 8;

const KEY_FILE_MAGIC: &[u8] = b"macula-v2-key\0";

/// An Ed25519 keypair. The public half **is** the macula NodeId.
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a fresh keypair. Does **not** grind a puzzle — the
    /// resulting identity will be silently rejected by any station that
    /// enforces puzzle admission (which is every station in practice).
    /// Prefer [`generate_with_puzzle`](Self::generate_with_puzzle) unless
    /// you specifically need an unhardened identity (e.g. a unit test
    /// that never dials a real station).
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Generate a keypair, grinding fresh candidates until
    /// `puzzle_valid(pubkey, difficulty)` holds. This is the one-time
    /// cost described in the module doc — not something to redo per
    /// connection.
    pub fn generate_with_puzzle(difficulty: u32) -> Self {
        loop {
            let candidate = Self::generate();
            if puzzle_valid(&candidate.public_bytes(), difficulty) {
                return candidate;
            }
        }
    }

    /// As [`generate_with_puzzle`](Self::generate_with_puzzle), at
    /// [`DEFAULT_PUZZLE_DIFFICULTY`].
    pub fn generate_with_default_puzzle() -> Self {
        Self::generate_with_puzzle(DEFAULT_PUZZLE_DIFFICULTY)
    }

    /// Reconstruct a keypair from its 32-byte seed. Deterministic — the
    /// same seed always yields the same public key and, for a given
    /// message, the same signature (Ed25519 per RFC 8032 has no signing
    /// randomness).
    pub fn from_seed_bytes(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// The public key — also this identity's macula NodeId.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The 32-byte seed. Matches `macula_identity:private/1`.
    pub fn private_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Alias for [`public_bytes`](Self::public_bytes) — NodeId == public
    /// key, matching `macula_identity:node_id/1`'s own doc ("Phase 1:
    /// NodeId == public key").
    pub fn node_id(&self) -> [u8; 32] {
        self.public_bytes()
    }

    /// Sign `msg` with this identity. Callers add their own domain
    /// separation by prefixing `msg` (see the frame-signing domains in
    /// `plans/PLAN_WIRE_PROTOCOL.md` §4) — this function itself is raw
    /// Ed25519, matching `macula_identity:sign/2` exactly.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    /// This identity's puzzle evidence — see [`puzzle_evidence`].
    pub fn puzzle_evidence(&self) -> [u8; 32] {
        puzzle_evidence(&self.public_bytes())
    }

    /// Save this keypair to `path`, atomically (write to a `.tmp`
    /// sibling, then rename) with `0600` permissions on Unix — matching
    /// `macula_identity:save/2`'s own file format and discipline exactly:
    /// a 14-byte magic header (`"macula-v2-key\0"`), then the 32-byte
    /// public key, then the 32-byte private seed.
    ///
    /// This raw-file format is a testing/parity convenience, matching the
    /// Erlang reference. A real mobile binding should use platform
    /// secure storage (Keychain on iOS, Keystore on Android) instead of
    /// this file format directly — see
    /// `plans/PLAN_WIRE_PROTOCOL.md`'s puzzle_evidence lifecycle note.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        let mut blob = Vec::with_capacity(KEY_FILE_MAGIC.len() + 64);
        blob.extend_from_slice(KEY_FILE_MAGIC);
        blob.extend_from_slice(&self.public_bytes());
        blob.extend_from_slice(&self.private_bytes());

        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, &blob)?;
        set_owner_only_permissions(&tmp_path)?;
        fs::rename(&tmp_path, path)
    }

    /// Load a keypair previously written by [`save`](Self::save).
    /// Returns [`LoadKeyError::PubkeyMismatch`] if the file's stored
    /// public key doesn't match the one derived from its stored private
    /// key — a corrupted or hand-edited key file would otherwise
    /// silently produce a keypair that can never complete a real
    /// handshake, which is a much harder failure to diagnose than a
    /// load-time error.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadKeyError> {
        let blob = fs::read(path.as_ref())?;
        let expected_len = KEY_FILE_MAGIC.len() + 64;
        if blob.len() != expected_len || !blob.starts_with(KEY_FILE_MAGIC) {
            return Err(LoadKeyError::BadKeyFile);
        }
        let rest = &blob[KEY_FILE_MAGIC.len()..];
        let stored_pub: [u8; 32] = rest[..32].try_into().expect("checked length");
        let stored_priv: [u8; 32] = rest[32..64].try_into().expect("checked length");

        let keypair = Self::from_seed_bytes(stored_priv);
        if keypair.public_bytes() != stored_pub {
            return Err(LoadKeyError::PubkeyMismatch);
        }
        Ok(keypair)
    }
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> io::Result<()> {
    // No POSIX permission bits off Unix; the platform's own file ACLs
    // apply. Real mobile builds should not be using this raw-file format
    // at all — see `KeyPair::save`'s doc.
    Ok(())
}

#[derive(Debug)]
pub enum LoadKeyError {
    Io(io::Error),
    BadKeyFile,
    PubkeyMismatch,
}

impl fmt::Display for LoadKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadKeyError::Io(e) => write!(f, "I/O error reading key file: {e}"),
            LoadKeyError::BadKeyFile => write!(f, "key file has the wrong magic header or length"),
            LoadKeyError::PubkeyMismatch => {
                write!(
                    f,
                    "stored public key does not match the one derived from the stored private key"
                )
            }
        }
    }
}

impl std::error::Error for LoadKeyError {}

impl From<io::Error> for LoadKeyError {
    fn from(e: io::Error) -> Self {
        LoadKeyError::Io(e)
    }
}

/// Verify `sig` over `msg` against `pubkey`. Matches
/// `macula_identity:verify/3`'s contract exactly: a structurally invalid
/// public key (not a valid Ed25519 point) is treated as "verification
/// failed" (`false`), not a separate error — it could not have produced
/// a valid signature either way.
pub fn verify(msg: &[u8], sig: &[u8; 64], pubkey: &[u8; 32]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    verifying_key.verify(msg, &signature).is_ok()
}

/// `SHA-256(pubkey)` — the proof-of-work output measured by the puzzle.
/// Cheap; not itself the expensive step (see the module doc).
pub fn puzzle_evidence(pubkey: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(pubkey).into()
}

/// Whether `pubkey` satisfies the puzzle at `difficulty` (leading zero
/// bits of its [`puzzle_evidence`]).
pub fn puzzle_valid(pubkey: &[u8; 32], difficulty: u32) -> bool {
    count_leading_zero_bits(&puzzle_evidence(pubkey)) >= difficulty
}

fn count_leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured directly from a real, random `crypto:generate_key(eddsa,
    /// ed25519)` / `crypto:sign/4` / `crypto:hash(sha256, Pub)` in
    /// `macula-io/macula`'s own `rebar3 shell` — see this module's doc
    /// comment. Not a synthetic fixture.
    const VECTOR_PUB: &str = "B966A9812649C3D5542FF54954FE090C43FDA6574FE48A0DD326626CFAD29A83";
    const VECTOR_PRIV: &str = "457F45FF5A09E172ED15CB20D6CB26B51AD15ED7308C12D478E8631F9CA03D4F";
    const VECTOR_MSG: &str = "6D6163756C612D76322D6672616D650068656C6C6F20776F726C64";
    const VECTOR_SIG: &str = "E8605CF0387CDFCDD88308A0E40A1DCB83402864C335A64D44431DC8ABC5E7E4FF16CA0C56231B32EEB312C4F89F20B6BA76280AFD622983E9D8BC5F4456AC0B";
    const VECTOR_PUZZLE_EVIDENCE: &str =
        "09D48C91CB46513ED2580BDCEA87C40DA508D4E50EC3DF2F701AFC55D1C5C0B2";
    const VECTOR_LEADING_ZERO_BITS: u32 = 4;

    fn fixed_array(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str)
            .expect("valid hex fixture")
            .try_into()
            .expect("32-byte fixture")
    }

    fn fixed_array64(hex_str: &str) -> [u8; 64] {
        hex::decode(hex_str)
            .expect("valid hex fixture")
            .try_into()
            .expect("64-byte fixture")
    }

    #[test]
    fn seed_derives_the_reference_pubkey() {
        let kp = KeyPair::from_seed_bytes(fixed_array(VECTOR_PRIV));
        assert_eq!(
            kp.public_bytes(),
            fixed_array(VECTOR_PUB),
            "ed25519-dalek's public-key derivation diverged from Erlang's crypto module"
        );
    }

    #[test]
    fn signature_matches_the_reference_byte_for_byte() {
        let kp = KeyPair::from_seed_bytes(fixed_array(VECTOR_PRIV));
        let msg = hex::decode(VECTOR_MSG).unwrap();
        let sig = kp.sign(&msg);
        assert_eq!(
            sig,
            fixed_array64(VECTOR_SIG),
            "Ed25519 is deterministic (RFC 8032) — a mismatch here means \
             the two implementations disagree on the signing algorithm \
             itself, not just on random input"
        );
    }

    #[test]
    fn verify_accepts_the_reference_signature() {
        let pubkey = fixed_array(VECTOR_PUB);
        let msg = hex::decode(VECTOR_MSG).unwrap();
        let sig = fixed_array64(VECTOR_SIG);
        assert!(verify(&msg, &sig, &pubkey));
    }

    #[test]
    fn verify_rejects_a_tampered_message() {
        let pubkey = fixed_array(VECTOR_PUB);
        let sig = fixed_array64(VECTOR_SIG);
        assert!(!verify(b"not the original message", &sig, &pubkey));
    }

    #[test]
    fn verify_rejects_a_structurally_invalid_pubkey_without_panicking() {
        // All-0xFF is not a valid Ed25519 point.
        let bogus_pubkey = [0xFFu8; 32];
        let msg = hex::decode(VECTOR_MSG).unwrap();
        let sig = fixed_array64(VECTOR_SIG);
        assert!(!verify(&msg, &sig, &bogus_pubkey));
    }

    #[test]
    fn puzzle_evidence_matches_the_reference() {
        let pubkey = fixed_array(VECTOR_PUB);
        assert_eq!(
            puzzle_evidence(&pubkey),
            fixed_array(VECTOR_PUZZLE_EVIDENCE)
        );
    }

    #[test]
    fn puzzle_valid_matches_the_reference_leading_zero_count() {
        let pubkey = fixed_array(VECTOR_PUB);
        assert!(puzzle_valid(&pubkey, VECTOR_LEADING_ZERO_BITS));
        assert!(!puzzle_valid(&pubkey, VECTOR_LEADING_ZERO_BITS + 1));
        assert!(puzzle_valid(&pubkey, 0)); // 0 is always satisfied
    }

    #[test]
    fn generate_with_default_puzzle_produces_a_valid_identity() {
        // A real grind, not a fixture — proves the loop terminates and
        // its result actually satisfies the check it's grinding for.
        // Sub-millisecond at the default difficulty per the Erlang
        // reference's own comment; this test should be fast.
        let kp = KeyPair::generate_with_default_puzzle();
        assert!(puzzle_valid(&kp.public_bytes(), DEFAULT_PUZZLE_DIFFICULTY));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.key");

        let original = KeyPair::from_seed_bytes(fixed_array(VECTOR_PRIV));
        original.save(&path).expect("save");

        let loaded = KeyPair::load(&path).expect("load");
        assert_eq!(loaded.public_bytes(), original.public_bytes());
        assert_eq!(loaded.private_bytes(), original.private_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn saved_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.key");
        KeyPair::generate().save(&path).expect("save");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn load_rejects_a_corrupted_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.key");
        fs::write(&path, b"not a key file").expect("write");

        assert!(matches!(
            KeyPair::load(&path),
            Err(LoadKeyError::BadKeyFile)
        ));
    }

    #[test]
    fn load_rejects_a_tampered_pubkey() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.key");
        KeyPair::generate().save(&path).expect("save");

        // Flip a byte inside the stored public key.
        let mut blob = fs::read(&path).expect("read");
        let pub_offset = KEY_FILE_MAGIC.len();
        blob[pub_offset] ^= 0xFF;
        fs::write(&path, &blob).expect("write tampered");

        assert!(matches!(
            KeyPair::load(&path),
            Err(LoadKeyError::PubkeyMismatch)
        ));
    }
}
