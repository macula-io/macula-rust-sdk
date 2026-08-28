//! UniFFI (Kotlin/Swift) bindings for [`macula_rust_sdk`]. A thin wrapper,
//! not a reimplementation — everything here delegates straight to the
//! core crate; nothing wire-level lives in this crate at all.
//!
//! Structure mirrors `iroh-ffi`'s relationship to `iroh`: a separate
//! crate depending on the core one, so the core crate carries zero
//! UniFFI dependency and zero FFI-shaped types. That separation is what
//! keeps `macula-rust-sdk` itself just as usable from plain Rust, a CLI,
//! or WASM as it was before this crate existed.
//!
//! **First slice only — proves the pipeline, not full coverage.**
//! Identity generation, CONNECT/HELLO, and CALL/RESULT/ERROR. Not yet
//! exposed: PUBLISH/SUBSCRIBE/EVENT, content transfer, streaming RPC —
//! all already built and live-verified in the core crate
//! (`plans/PLAN_WIRE_PROTOCOL.md`), just not wrapped here yet.
//!
//! [`FfiValue`] covers `Null`/`Int`/`Bytes`/`Text`/`Float` — the
//! variants [`macula_rust_sdk::cbor::Value`] itself has, MINUS
//! `List`/`Map` (recursive UniFFI enums; deferred, not a wire
//! limitation) and with `Int` narrowed from `i128` to `i64` (UniFFI has
//! no 128-bit integer type; out-of-range values round-trip as an
//! [`FfiError::UnrepresentableValue`] rather than silently truncating).
//!
//! Generate the bindings with the `uniffi-bindgen` binary this crate
//! also builds, e.g.:
//! ```text
//! cargo build -p macula-rust-sdk-ffi --release
//! cargo run -p macula-rust-sdk-ffi --bin uniffi-bindgen -- generate \
//!     --library target/release/libmacula_rust_sdk_ffi.so \
//!     --language kotlin --out-dir bindings/kotlin
//! ```

uniffi::setup_scaffolding!();

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("connecting to the station: {reason}")]
    Connect { reason: String },
    #[error("the call failed: {reason}")]
    Call { reason: String },
    #[error("a value could not cross the FFI boundary: {reason}")]
    UnrepresentableValue { reason: String },
    #[error("expected exactly 32 bytes, got {len}")]
    WrongByteLength { len: u32 },
    #[error("this session is already closed")]
    Closed,
}

/// A restricted mirror of [`macula_rust_sdk::cbor::Value`] — see this
/// crate's module doc for exactly what's missing and why.
#[derive(uniffi::Enum, Debug, Clone)]
pub enum FfiValue {
    Null,
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Float(f64),
}

impl From<FfiValue> for macula_rust_sdk::cbor::Value {
    fn from(v: FfiValue) -> Self {
        use macula_rust_sdk::cbor::Value;
        match v {
            FfiValue::Null => Value::Null,
            FfiValue::Int(n) => Value::Int(n as i128),
            FfiValue::Bytes(b) => Value::Bytes(b),
            FfiValue::Text(t) => Value::Text(t),
            FfiValue::Float(f) => Value::Float(f),
        }
    }
}

impl TryFrom<macula_rust_sdk::cbor::Value> for FfiValue {
    type Error = FfiError;

    fn try_from(v: macula_rust_sdk::cbor::Value) -> Result<Self, FfiError> {
        use macula_rust_sdk::cbor::Value;
        match v {
            Value::Null => Ok(FfiValue::Null),
            Value::Int(n) => {
                i64::try_from(n)
                    .map(FfiValue::Int)
                    .map_err(|_| FfiError::UnrepresentableValue {
                        reason: format!("integer {n} is outside i64 range"),
                    })
            }
            Value::Bytes(b) => Ok(FfiValue::Bytes(b)),
            Value::Text(t) => Ok(FfiValue::Text(t)),
            Value::Float(f) => Ok(FfiValue::Float(f)),
            Value::List(_) => Err(FfiError::UnrepresentableValue {
                reason: "list values are not yet supported across the FFI boundary".to_string(),
            }),
            Value::Map(_) => Err(FfiError::UnrepresentableValue {
                reason: "map values are not yet supported across the FFI boundary".to_string(),
            }),
        }
    }
}

/// The result of a CALL: a mirror of
/// [`macula_rust_sdk::frame::CallResponse`].
#[derive(uniffi::Enum, Debug, Clone)]
pub enum FfiCallResponse {
    Result {
        payload: FfiValue,
        responded_by: Vec<u8>,
    },
    Error {
        code: u8,
        name: String,
        reported_by: Vec<u8>,
        detail: Option<String>,
    },
}

impl TryFrom<macula_rust_sdk::frame::CallResponse> for FfiCallResponse {
    type Error = FfiError;

    fn try_from(r: macula_rust_sdk::frame::CallResponse) -> Result<Self, FfiError> {
        use macula_rust_sdk::frame::CallResponse;
        match r {
            CallResponse::Result {
                payload,
                responded_by,
            } => Ok(FfiCallResponse::Result {
                payload: FfiValue::try_from(payload)?,
                responded_by: responded_by.to_vec(),
            }),
            CallResponse::Error {
                code,
                name,
                reported_by,
                detail,
            } => Ok(FfiCallResponse::Error {
                code,
                name,
                reported_by: reported_by.to_vec(),
                detail,
            }),
        }
    }
}

/// An Ed25519 identity, puzzle-hardened by construction — see
/// [`macula_rust_sdk::identity::KeyPair::generate_with_default_puzzle`]'s
/// own doc for why this is always the right default despite its (small,
/// one-time) CPU cost.
#[derive(uniffi::Object)]
pub struct FfiKeyPair(macula_rust_sdk::identity::KeyPair);

#[uniffi::export]
impl FfiKeyPair {
    #[uniffi::constructor]
    pub fn generate() -> Self {
        Self(macula_rust_sdk::identity::KeyPair::generate_with_default_puzzle())
    }

    /// This identity's node_id (its Ed25519 public key), 32 bytes.
    pub fn node_id(&self) -> Vec<u8> {
        self.0.node_id().to_vec()
    }
}

/// A handshaked connection to a macula-station. Wraps
/// [`macula_rust_sdk::connection::Session`] behind a mutex — UniFFI
/// object methods take `&self`, but the wrapped methods need `&mut
/// self`, so this crate's only job here is bridging that, not adding
/// behavior.
#[derive(uniffi::Object)]
pub struct FfiSession(tokio::sync::Mutex<Option<macula_rust_sdk::connection::Session>>);

#[uniffi::export(async_runtime = "tokio")]
impl FfiSession {
    /// Dial `host:port` and complete the CONNECT/HELLO handshake, using
    /// WebPki (CA-chain) trust — the mode the live macula.io fleet
    /// actually presents (`plans/PLAN_WIRE_PROTOCOL.md`'s §2 empirical
    /// note). Pubkey pinning isn't exposed at the FFI boundary yet.
    #[uniffi::constructor]
    pub async fn connect(host: String, port: u16, identity: &FfiKeyPair) -> Result<Self, FfiError> {
        let session = macula_rust_sdk::connection::connect(
            &host,
            port,
            macula_rust_sdk::transport::Trust::WebPki,
            &identity.0,
        )
        .await
        .map_err(|e| FfiError::Connect {
            reason: e.to_string(),
        })?;
        Ok(Self(tokio::sync::Mutex::new(Some(session))))
    }

    /// Send a signed CALL and wait for the matching RESULT or ERROR.
    /// `realm` must be exactly 32 bytes. `timeout_ms` bounds both the
    /// wait for a response and the frame's own `deadline_ms` field
    /// (`now + timeout_ms`).
    pub async fn call(
        &self,
        procedure: String,
        realm: Vec<u8>,
        payload: FfiValue,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<FfiCallResponse, FfiError> {
        let realm_len = realm.len() as u32;
        let realm: [u8; 32] = realm
            .try_into()
            .map_err(|_| FfiError::WrongByteLength { len: realm_len })?;
        let deadline_ms = (now_ms() + timeout_ms) as i128;

        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let response = session
            .call(
                &procedure,
                realm,
                payload.into(),
                deadline_ms,
                &identity.0,
                std::time::Duration::from_millis(timeout_ms),
            )
            .await
            .map_err(|e| FfiError::Call {
                reason: e.to_string(),
            })?;
        FfiCallResponse::try_from(response)
    }

    /// Close the session with a GOODBYE frame. A no-op if already closed.
    pub async fn close(&self, identity: &FfiKeyPair) {
        let mut guard = self.0.lock().await;
        if let Some(session) = guard.take() {
            session.close("normal", None, &identity.0).await;
        }
    }
}
