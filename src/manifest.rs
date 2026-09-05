//! Fixed-size chunking, Merkle-root computation, and manifest
//! construction for content larger than one storage block. Ported from
//! macula's own `macula_manifest` (SDK) — see
//! `plans/PLAN_WIRE_PROTOCOL.md` §12.2.
//!
//! Mirrors the reference byte-for-byte: same MCID format, same default
//! chunk size (256 KiB), same Merkle fold (including the odd-leaf-count
//! rule — pair the last hash with itself), same canonical-CBOR MCID
//! derivation. Verified against real `macula_manifest:create/2` /
//! `chunk_mcid/3` / `verify/2` output (even *and* odd chunk counts, to
//! exercise both branches of the Merkle fold) — see this module's tests.
//!
//! **Two different wire representations of `name`, both verified
//! separately, not confused with each other:** `compute_mcid`'s
//! canonical hash input wraps `name` as CBOR *text* (a deliberate,
//! narrow special case in the reference, just for that hash
//! computation), while [`to_wire`] — the actual manifest map as sent in
//! a `_content.put_manifest` CALL payload — encodes `name` as a raw
//! *byte string*, matching its `binary()` type. Confirmed directly by
//! encoding a real manifest through the general deterministic-CBOR
//! codec and inspecting the bytes, not inferred from the type spec
//! alone — see the CALL/PUBLISH `procedure`/`topic` lesson in
//! `src/frame.rs` for why that inference alone wasn't trusted here.

use crate::cbor::Value;

/// 256 KiB — matches `macula_manifest:default_chunk_size/0`.
pub const DEFAULT_CHUNK_SIZE: usize = 262_144;

const VERSION: u8 = 1;
const CODEC_RAW: u8 = 0x55;
const CODEC_MANIFEST: u8 = 0x56;

/// `<<Version:8, Codec:8, Hash:32/binary>>` — 34 bytes.
pub type Mcid = [u8; 34];

fn make_mcid(codec: u8, hash: [u8; 32]) -> Mcid {
    let mut out = [0u8; 34];
    out[0] = VERSION;
    out[1] = codec;
    out[2..].copy_from_slice(&hash);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Blake3,
    Sha256,
}

impl Algorithm {
    fn hash(self, data: &[u8]) -> [u8; 32] {
        match self {
            Algorithm::Blake3 => *blake3::hash(data).as_bytes(),
            Algorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                Sha256::digest(data).into()
            }
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Blake3 => "blake3",
            Algorithm::Sha256 => "sha256",
        }
    }

    /// Matches `to_algorithm/1`'s own fallback: anything unrecognized
    /// defaults to `blake3`, it doesn't error.
    pub fn from_name(name: &str) -> Algorithm {
        match name {
            "sha256" => Algorithm::Sha256,
            _ => Algorithm::Blake3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkInfo {
    pub index: usize,
    pub offset: usize,
    pub size: usize,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub mcid: Mcid,
    pub version: u32,
    pub name: String,
    pub size: u64,
    pub created: u64,
    pub chunk_size: usize,
    pub chunk_count: usize,
    pub hash_algorithm: Algorithm,
    pub root_hash: [u8; 32],
    pub chunks: Vec<ChunkInfo>,
}

#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub name: String,
    pub chunk_size: usize,
    pub hash_algorithm: Algorithm,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            name: "unnamed".to_string(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            hash_algorithm: Algorithm::Blake3,
        }
    }
}

/// Split `data` into fixed-size chunks and build its manifest. Returns
/// the manifest and the chunk bytes in order (index 0 first) — a caller
/// uploads each chunk (`_content.put_block`) then the manifest itself
/// (`_content.put_manifest`), per §12.2.
///
/// `opts.chunk_size` must be non-zero (matches the reference: it never
/// guards against zero either, and a zero chunk size is a caller bug,
/// not a case worth silently tolerating).
pub fn create(data: &[u8], opts: &CreateOptions) -> (Manifest, Vec<Vec<u8>>) {
    create_with_created(data, opts, current_unix_secs())
}

fn create_with_created(
    data: &[u8],
    opts: &CreateOptions,
    created: u64,
) -> (Manifest, Vec<Vec<u8>>) {
    let chunks = do_chunk(data, opts.chunk_size);
    let chunk_infos = chunk_infos(&chunks, opts.hash_algorithm);
    let root_hash = root_hash_for(&chunk_infos, opts.hash_algorithm);
    let chunk_count = chunk_infos.len();
    let mcid = compute_mcid(
        &opts.name,
        data.len() as u64,
        opts.chunk_size,
        chunk_count,
        opts.hash_algorithm,
        &root_hash,
    );
    let manifest = Manifest {
        mcid,
        version: 1,
        name: opts.name.clone(),
        size: data.len() as u64,
        created,
        chunk_size: opts.chunk_size,
        chunk_count,
        hash_algorithm: opts.hash_algorithm,
        root_hash,
        chunks: chunk_infos,
    };
    (manifest, chunks)
}

/// The MCID a chunk at `index` is stored/fetched under — the station
/// derives this same value independently when serving the chunk, so
/// both sides agree on its address without exchanging it.
pub fn chunk_mcid(manifest: &Manifest, index: usize) -> Option<Mcid> {
    manifest
        .chunks
        .get(index)
        .map(|c| make_mcid(CODEC_RAW, c.hash))
}

/// The MCID a whole blob is stored/fetched under when it's small enough
/// to be a single block (no manifest at all). Matches
/// `macula_content_transfer:put_single_block/3` exactly: **always**
/// BLAKE3, regardless of any algorithm preference — single-block content
/// has no algorithm choice, only chunked/manifest content does.
pub fn block_mcid(data: &[u8]) -> Mcid {
    make_mcid(CODEC_RAW, Algorithm::Blake3.hash(data))
}

/// Whether `mcid` addresses a manifest (chunked content) rather than a
/// single raw block — determined from its own codec byte, no network
/// round trip needed. Matches `macula_content_transfer:is_chunked/2`'s
/// get-side check.
pub fn mcid_is_chunked(mcid: &Mcid) -> bool {
    mcid[1] == CODEC_MANIFEST
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    SizeMismatch,
    RootHashMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::SizeMismatch => write!(f, "data size does not match the manifest"),
            VerifyError::RootHashMismatch => {
                write!(f, "re-chunked root hash does not match the manifest")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify reassembled `data` against `manifest`: size, then a fresh
/// Merkle root over `data` re-chunked the same way.
pub fn verify(manifest: &Manifest, data: &[u8]) -> Result<(), VerifyError> {
    if data.len() as u64 != manifest.size {
        return Err(VerifyError::SizeMismatch);
    }
    let chunks = do_chunk(data, manifest.chunk_size);
    let infos = chunk_infos(&chunks, manifest.hash_algorithm);
    let actual_root = root_hash_for(&infos, manifest.hash_algorithm);
    if actual_root == manifest.root_hash {
        Ok(())
    } else {
        Err(VerifyError::RootHashMismatch)
    }
}

fn do_chunk(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    // `[T]::chunks(n)` is exactly equivalent to the reference's
    // recursive `do_chunk/3` for every case checked, including exact
    // multiples of chunk_size (no trailing empty chunk) and empty input
    // (zero chunks, not one empty chunk).
    data.chunks(chunk_size).map(<[u8]>::to_vec).collect()
}

fn chunk_infos(chunks: &[Vec<u8>], algorithm: Algorithm) -> Vec<ChunkInfo> {
    let mut offset = 0usize;
    chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let info = ChunkInfo {
                index,
                offset,
                size: chunk.len(),
                hash: algorithm.hash(chunk),
            };
            offset += chunk.len();
            info
        })
        .collect()
}

fn root_hash_for(infos: &[ChunkInfo], algorithm: Algorithm) -> [u8; 32] {
    if infos.is_empty() {
        return algorithm.hash(&[]);
    }
    let mut hashes: Vec<[u8; 32]> = infos.iter().map(|i| i.hash).collect();
    while hashes.len() > 1 {
        hashes = combine(&hashes, algorithm);
    }
    hashes[0]
}

/// One Merkle-fold pass: pairs from the front, `hash(L || R)`. An odd
/// leftover at the end is paired with itself, `hash(Last || Last)` — the
/// rule most likely to be implemented wrong; verified against an
/// odd-chunk-count reference vector specifically (see this module's
/// tests), not just even counts.
fn combine(hashes: &[[u8; 32]], algorithm: Algorithm) -> Vec<[u8; 32]> {
    hashes
        .chunks(2)
        .map(|pair| {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&pair[0]);
            buf.extend_from_slice(pair.get(1).unwrap_or(&pair[0]));
            algorithm.hash(&buf)
        })
        .collect()
}

/// The canonical hash input for a manifest's own MCID — deliberately
/// excludes `created` (timestamp) and `chunks` (already rolled up into
/// `root_hash`). `name` and `hash_algorithm` are wrapped as CBOR text
/// here specifically, matching the reference's own special-cased
/// `compute_mcid/2` — see this module's doc comment for why that's
/// *not* the same encoding [`to_wire`] uses for `name`.
fn compute_mcid(
    name: &str,
    size: u64,
    chunk_size: usize,
    chunk_count: usize,
    algorithm: Algorithm,
    root_hash: &[u8; 32],
) -> Mcid {
    let canonical = Value::Map(vec![
        (Value::text("name"), Value::text(name)),
        (Value::text("size"), Value::Int(size as i128)),
        (Value::text("chunk_size"), Value::Int(chunk_size as i128)),
        (Value::text("chunk_count"), Value::Int(chunk_count as i128)),
        (Value::text("hash_algorithm"), Value::text(algorithm.name())),
        (Value::text("root_hash"), Value::Bytes(root_hash.to_vec())),
    ]);
    let bytes = crate::cbor::encode(&canonical).expect("manifest MCID fields are always encodable");
    let hash = algorithm.hash(&bytes);
    make_mcid(CODEC_MANIFEST, hash)
}

/// Encode `manifest` as it's actually sent in a `_content.put_manifest`
/// CALL payload — `name` as bytes (its real `binary()` type), NOT the
/// text-wrapped form `compute_mcid` uses internally. See this module's
/// doc comment.
pub fn to_wire(manifest: &Manifest) -> Value {
    Value::Map(vec![
        (Value::text("mcid"), Value::Bytes(manifest.mcid.to_vec())),
        (Value::text("version"), Value::Int(manifest.version as i128)),
        (
            Value::text("name"),
            Value::Bytes(manifest.name.as_bytes().to_vec()),
        ),
        (Value::text("size"), Value::Int(manifest.size as i128)),
        (Value::text("created"), Value::Int(manifest.created as i128)),
        (
            Value::text("chunk_size"),
            Value::Int(manifest.chunk_size as i128),
        ),
        (
            Value::text("chunk_count"),
            Value::Int(manifest.chunk_count as i128),
        ),
        (
            Value::text("hash_algorithm"),
            Value::text(manifest.hash_algorithm.name()),
        ),
        (
            Value::text("root_hash"),
            Value::Bytes(manifest.root_hash.to_vec()),
        ),
        (
            Value::text("chunks"),
            Value::List(manifest.chunks.iter().map(chunk_info_to_wire).collect()),
        ),
    ])
}

fn chunk_info_to_wire(info: &ChunkInfo) -> Value {
    Value::Map(vec![
        (Value::text("index"), Value::Int(info.index as i128)),
        (Value::text("offset"), Value::Int(info.offset as i128)),
        (Value::text("size"), Value::Int(info.size as i128)),
        (Value::text("hash"), Value::Bytes(info.hash.to_vec())),
    ])
}

#[derive(Debug, PartialEq, Eq)]
pub enum FromWireError {
    MissingField(&'static str),
    WrongFieldType(&'static str),
    /// `chunk_size` is 0. Never produced by [`create`] (its own doc
    /// comment already requires a non-zero `chunk_size`), so this only
    /// ever rejects a malicious/malformed wire manifest — accepting it
    /// would panic downstream: `[T]::chunks(0)` (called from
    /// [`verify`]'s own `do_chunk`) panics unconditionally on a zero
    /// chunk size, even for empty content.
    ZeroChunkSize,
    /// `chunk_count` doesn't match the actual number of entries in the
    /// `chunks` list. Never produced by [`create`] (`chunk_count` is
    /// always `chunk_infos.len()`), so this only ever rejects a
    /// malicious/malformed wire manifest — accepting it would let a
    /// caller iterate `0..chunk_count` past the real end of `chunks`
    /// and panic on the resulting `None` from [`chunk_mcid`].
    InconsistentChunkCount,
}

impl std::fmt::Display for FromWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FromWireError::MissingField(name) => write!(f, "missing required field {name:?}"),
            FromWireError::WrongFieldType(name) => write!(f, "field {name:?} has the wrong type"),
            FromWireError::ZeroChunkSize => write!(f, "chunk_size is 0"),
            FromWireError::InconsistentChunkCount => {
                write!(
                    f,
                    "chunk_count does not match the number of entries in chunks"
                )
            }
        }
    }
}

impl std::error::Error for FromWireError {}

/// Parse a manifest as received from a `_content.get_manifest` RESULT.
pub fn from_wire(value: &Value) -> Result<Manifest, FromWireError> {
    let mcid: Mcid = get_bytes_exact(value, "mcid")?;
    let version = get_uint(value, "version")? as u32;
    let name = get_string_bytes(value, "name")?;
    let size = get_uint(value, "size")?;
    let created = get_uint(value, "created")?;
    let chunk_size = get_uint(value, "chunk_size")? as usize;
    let chunk_count = get_uint(value, "chunk_count")? as usize;
    let hash_algorithm = Algorithm::from_name(&get_text(value, "hash_algorithm")?);
    let root_hash: [u8; 32] = get_bytes_exact(value, "root_hash")?;
    let chunks = match value.get("chunks") {
        Some(Value::List(items)) => items
            .iter()
            .map(chunk_info_from_wire)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(FromWireError::WrongFieldType("chunks")),
        None => return Err(FromWireError::MissingField("chunks")),
    };
    if chunk_size == 0 {
        return Err(FromWireError::ZeroChunkSize);
    }
    if chunks.len() != chunk_count {
        return Err(FromWireError::InconsistentChunkCount);
    }
    Ok(Manifest {
        mcid,
        version,
        name,
        size,
        created,
        chunk_size,
        chunk_count,
        hash_algorithm,
        root_hash,
        chunks,
    })
}

fn chunk_info_from_wire(value: &Value) -> Result<ChunkInfo, FromWireError> {
    Ok(ChunkInfo {
        index: get_uint(value, "index")? as usize,
        offset: get_uint(value, "offset")? as usize,
        size: get_uint(value, "size")? as usize,
        hash: get_bytes_exact(value, "hash")?,
    })
}

fn get_uint(value: &Value, field: &'static str) -> Result<u64, FromWireError> {
    match value.get(field) {
        Some(Value::Int(n)) if *n >= 0 => Ok(*n as u64),
        Some(_) => Err(FromWireError::WrongFieldType(field)),
        None => Err(FromWireError::MissingField(field)),
    }
}

fn get_text(value: &Value, field: &'static str) -> Result<String, FromWireError> {
    match value.get(field) {
        Some(Value::Text(t)) => Ok(t.clone()),
        Some(_) => Err(FromWireError::WrongFieldType(field)),
        None => Err(FromWireError::MissingField(field)),
    }
}

fn get_string_bytes(value: &Value, field: &'static str) -> Result<String, FromWireError> {
    match value.get(field) {
        Some(Value::Bytes(b)) => {
            String::from_utf8(b.clone()).map_err(|_| FromWireError::WrongFieldType(field))
        }
        Some(_) => Err(FromWireError::WrongFieldType(field)),
        None => Err(FromWireError::MissingField(field)),
    }
}

fn get_bytes_exact<const N: usize>(
    value: &Value,
    field: &'static str,
) -> Result<[u8; N], FromWireError> {
    match value.get(field) {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| FromWireError::WrongFieldType(field)),
        Some(_) => Err(FromWireError::WrongFieldType(field)),
        None => Err(FromWireError::MissingField(field)),
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(s: &str) -> Vec<u8> {
        ::hex::decode(s).expect("valid hex fixture")
    }

    /// Even chunk count (4) — captured from a real `macula_manifest:create/2`
    /// via `rebar3 shell` against `macula-io/macula`.
    #[test]
    fn even_chunk_count_matches_the_reference() {
        let data = b"AAAABBBBCCCCD"; // 13 bytes
        let opts = CreateOptions {
            name: "test-file".to_string(),
            chunk_size: 4,
            hash_algorithm: Algorithm::Blake3,
        };
        let (manifest, chunks) = create_with_created(data, &opts, 0);

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0], b"AAAA");
        assert_eq!(chunks[3], b"D");

        assert_eq!(
            hex::encode_upper(manifest.root_hash),
            "784F87CDC9C180A21C878FC26703F9E4782F2FD2E6235048299811675E36EAC4"
        );
        assert_eq!(
            hex::encode_upper(manifest.mcid),
            "01564CC855EF538530393E36DBD4CCD216558B60F87498889890247EEB9B52B8FED7"
        );

        // Per-chunk hashes and offsets, spot-checked against the same run.
        assert_eq!(manifest.chunks[0].offset, 0);
        assert_eq!(
            hex::encode_upper(manifest.chunks[0].hash),
            "26C7BB3DAAAA0439EB3E5C5270E7C4DB05218D8892A0258FBD4911CEF5006D23"
        );
        assert_eq!(manifest.chunks[3].offset, 12);
        assert_eq!(manifest.chunks[3].size, 1);

        assert_eq!(
            chunk_mcid(&manifest, 0).map(hex::encode_upper),
            Some(
                "015526C7BB3DAAAA0439EB3E5C5270E7C4DB05218D8892A0258FBD4911CEF5006D23".to_string()
            )
        );

        assert_eq!(verify(&manifest, data), Ok(()));
    }

    /// Odd chunk count (3) — exercises the Merkle fold's "pair the last
    /// hash with itself" branch, which the even-count test above never
    /// touches.
    #[test]
    fn odd_chunk_count_matches_the_reference() {
        let data = b"AAAABBBBCCCC"; // 12 bytes, chunk_size 4 -> exactly 3 chunks
        let opts = CreateOptions {
            name: "odd-test".to_string(),
            chunk_size: 4,
            hash_algorithm: Algorithm::Blake3,
        };
        let (manifest, chunks) = create_with_created(data, &opts, 0);

        assert_eq!(chunks.len(), 3);
        assert_eq!(
            hex::encode_upper(manifest.root_hash),
            "50FE839CCDE80B13D7531A9C34FD856DBCBBB87D8FBD241DE6AFF2C86909CD54"
        );
        assert_eq!(
            hex::encode_upper(manifest.mcid),
            "0156589728C90DB0138CA87E4E500A61812C64D30C3BE325184A761F20CA04BC86FB"
        );

        assert_eq!(verify(&manifest, data), Ok(()));
        assert_eq!(
            verify(&manifest, b"AAAABBBBWRONG"),
            Err(VerifyError::SizeMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_content_of_the_same_size() {
        let data = b"AAAABBBBCCCC";
        let opts = CreateOptions {
            chunk_size: 4,
            ..Default::default()
        };
        let (manifest, _) = create_with_created(data, &opts, 0);
        assert_eq!(
            verify(&manifest, b"AAAABBBBCCCX"),
            Err(VerifyError::RootHashMismatch)
        );
    }

    /// The full manifest map as it's actually sent in a
    /// `_content.put_manifest` CALL payload — captured by encoding a
    /// real manifest through `macula_cbor_nif:pack_deterministic/1`
    /// directly (the same general codec CALL payloads go through), not
    /// through `compute_mcid`'s special canonical path. This is what
    /// proves `name` really is bytes on the wire, not text.
    #[test]
    fn to_wire_matches_the_reference_byte_for_byte() {
        let data = b"AAAABBBBCCCC";
        let opts = CreateOptions {
            name: "odd-test".to_string(),
            chunk_size: 4,
            hash_algorithm: Algorithm::Blake3,
        };
        let (manifest, _) = create_with_created(data, &opts, 1_787_892_082); // 0x6A911172

        let wire = to_wire(&manifest);
        let encoded = crate::cbor::encode(&wire).expect("encodable manifest");
        assert_eq!(
            encoded,
            hex_bytes(
                "AA646D63696458220156589728C90DB0138CA87E4E500A61812C64D30C3BE325184A761F20CA04BC86FB646E616D65486F64642D746573746473697A650C666368756E6B7383A46468617368582026C7BB3DAAAA0439EB3E5C5270E7C4DB05218D8892A0258FBD4911CEF5006D236473697A650465696E64657800666F666673657400A464686173685820255EC90F561EDA98B1E5E3EFA56B7B477086E273CD07CC4F780A646D052726446473697A650465696E64657801666F666673657404A464686173685820A83CE6EC6760EB7F66D3D7BBC84D1AAC3BEF0948074F8ED21423D825AE8821726473697A650465696E64657802666F66667365740867637265617465641A6A9111726776657273696F6E0169726F6F745F68617368582050FE839CCDE80B13D7531A9C34FD856DBCBBB87D8FBD241DE6AFF2C86909CD546A6368756E6B5F73697A65046B6368756E6B5F636F756E74036E686173685F616C676F726974686D66626C616B6533"
            )
        );

        // Round-trip through from_wire.
        let decoded = crate::cbor::decode(&encoded).expect("valid CBOR");
        let parsed = from_wire(&decoded).expect("well-formed manifest");
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn from_wire_rejects_a_missing_field() {
        let value = Value::Map(vec![(Value::text("mcid"), Value::Bytes(vec![0; 34]))]);
        assert_eq!(
            from_wire(&value),
            Err(FromWireError::MissingField("version"))
        );
    }

    /// A malicious/malformed manifest claiming `chunk_size: 0` must be
    /// rejected at parse time, not accepted and left to panic later:
    /// `verify`'s own `do_chunk` calls `[T]::chunks(manifest.chunk_size)`,
    /// which panics unconditionally when its argument is 0.
    #[test]
    fn from_wire_rejects_zero_chunk_size() {
        let (manifest, _) = create_with_created(b"AAAABBBBCCCC", &CreateOptions::default(), 0);
        let tampered = to_wire(&manifest).with_field("chunk_size", Value::Int(0));
        assert_eq!(from_wire(&tampered), Err(FromWireError::ZeroChunkSize));
    }

    /// A malicious/malformed manifest whose `chunk_count` doesn't match
    /// the actual number of entries in `chunks` must be rejected at
    /// parse time: a caller iterating `0..chunk_count` (see
    /// `content::get`) would otherwise index past the real end of
    /// `chunks` and panic on the resulting `None`.
    #[test]
    fn from_wire_rejects_inconsistent_chunk_count() {
        let opts = CreateOptions {
            chunk_size: 4,
            ..CreateOptions::default()
        };
        let (manifest, _) = create_with_created(b"AAAABBBBCCCC", &opts, 0);
        let tampered = to_wire(&manifest).with_field("chunk_count", Value::Int(1000));
        assert_eq!(
            from_wire(&tampered),
            Err(FromWireError::InconsistentChunkCount)
        );
    }

    #[test]
    fn algorithm_from_name_defaults_to_blake3() {
        assert_eq!(Algorithm::from_name("blake3"), Algorithm::Blake3);
        assert_eq!(Algorithm::from_name("sha256"), Algorithm::Sha256);
        assert_eq!(Algorithm::from_name("something-unknown"), Algorithm::Blake3);
    }

    #[test]
    fn empty_data_produces_zero_chunks() {
        let (manifest, chunks) = create_with_created(b"", &CreateOptions::default(), 0);
        assert_eq!(chunks.len(), 0);
        assert_eq!(manifest.chunk_count, 0);
    }
}
