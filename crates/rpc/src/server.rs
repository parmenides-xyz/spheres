//! Redacted sphere RPC server.
//!
//! An axum HTTP server backed by the sphere node's EthApi, with
//! authentication and privacy redactions applied per-method.
//!
//! Supports both HTTP POST and WebSocket transports.

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use std::{io, sync::Arc, time::Instant};
use tracing::info;

use crate::{
    auth::{self, AuthContext},
    config::RedactedRpcConfig,
    error::{AuthError, AuthenticateError},
    handlers::{self, SphereRpcApi},
    metrics::{RedactedRpcAuthMetrics, RedactedRpcCallMetrics},
    types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse},
    ws::handle_ws_upgrade,
};

/// Maximum number of requests in a single JSON-RPC batch.
pub(crate) const MAX_BATCH_SIZE: usize = 100;

/// Shared state for the redacted RPC server.
#[derive(Clone)]
pub struct RpcState {
    /// Server configuration.
    pub config: RedactedRpcConfig,
    /// Type-erased EthApi for handling RPC methods.
    pub api: Arc<dyn SphereRpcApi>,
    /// Authentication failure metric for the redacted RPC.
    auth_metrics: RedactedRpcAuthMetrics,
}

/// Start the redacted sphere RPC server.
///
/// The `api` argument provides the underlying EthApi methods (obtained from
/// the sphere node's launched handle).
pub async fn start_redacted_rpc(
    config: RedactedRpcConfig,
    api: Arc<dyn SphereRpcApi>,
) -> eyre::Result<std::net::SocketAddr> {
    let listen_addr = config.listen_addr;
    let state = Arc::new(RpcState {
        config,
        api,
        auth_metrics: RedactedRpcAuthMetrics::default(),
    });

    let app = Router::new()
        .route("/", post(handle_rpc))
        .route("/", get(handle_ws_upgrade))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;

    info!(target: "sphere::rpc", %local_addr, "Starting redacted sphere RPC server");

    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(target: "sphere::rpc", %err, "Redacted RPC server failed");
        }
    });

    Ok(local_addr)
}

/// Pre-serialized JSON-RPC response body.
pub(crate) struct RpcResult(String);

impl IntoResponse for RpcResult {
    fn into_response(self) -> axum::response::Response {
        ([(header::CONTENT_TYPE, "application/json")], self.0).into_response()
    }
}

impl RpcResult {
    fn single(response: JsonRpcResponse, max_response_size: usize) -> Self {
        Self(serialize_response_with_limit(response, max_response_size))
    }
}

fn serialize_response(response: JsonRpcResponse) -> String {
    serde_json::to_string(&response).expect("JsonRpcResponse serialization is infallible")
}

pub(crate) fn append_batch_response(
    batch: &mut String,
    response: JsonRpcResponse,
    max_response_size: usize,
) -> Result<(), String> {
    let response = serialize_response_with_limit(response, max_response_size);
    if batch.len().saturating_add(response.len()).saturating_add(1) > max_response_size {
        return Err(serialize_response(JsonRpcResponse::error(
            serde_json::Value::Null,
            JsonRpcError::batch_response_too_large(max_response_size),
        )));
    }
    batch.push_str(&response);
    batch.push(',');
    Ok(())
}

pub(crate) fn serialize_response_with_limit(
    response: JsonRpcResponse,
    max_response_size: usize,
) -> String {
    let id = response.id.clone();
    let mut writer = BoundedWriter::new(max_response_size);
    if serde_json::to_writer(&mut writer, &response).is_ok() {
        String::from_utf8(writer.into_bytes())
            .expect("serde_json only emits valid UTF-8 response bytes")
    } else {
        serialize_response(JsonRpcResponse::error(
            id,
            JsonRpcError::response_too_large(max_response_size),
        ))
    }
}

/// Writer that refuses to buffer more than the configured response size.
struct BoundedWriter {
    max_len: usize,
    bytes: Vec<u8>,
}

impl BoundedWriter {
    fn new(max_len: usize) -> Self {
        Self {
            max_len,
            bytes: Vec::with_capacity(128.min(max_len)),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl io::Write for &mut BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.max_len {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "response size limit exceeded",
            ));
        }

        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Parse and dispatch a JSON-RPC text payload, handling both single and batch
/// requests. Shared by HTTP and WebSocket transports.
pub(crate) async fn process_rpc_text(
    text: &str,
    auth: &AuthContext,
    api: &dyn SphereRpcApi,
    max_response_size: usize,
) -> RpcResult {
    let trimmed = text.trim_start();

    if trimmed.starts_with('[') {
        match serde_json::from_str::<Vec<JsonRpcRequest>>(trimmed) {
            Ok(requests) if requests.is_empty() => RpcResult::single(
                JsonRpcResponse::error(
                    serde_json::Value::Null,
                    JsonRpcError::parse_error("empty batch"),
                ),
                max_response_size,
            ),
            Ok(requests) if requests.len() > MAX_BATCH_SIZE => RpcResult::single(
                JsonRpcResponse::error(
                    serde_json::Value::Null,
                    JsonRpcError::invalid_params(format!(
                        "batch too large ({} > {MAX_BATCH_SIZE})",
                        requests.len()
                    )),
                ),
                max_response_size,
            ),
            Ok(requests) => {
                let mut responses = String::from("[");
                for req in &requests {
                    let response = dispatch_request(req, auth, api).await;
                    if let Err(error) =
                        append_batch_response(&mut responses, response, max_response_size)
                    {
                        return RpcResult(error);
                    }
                }
                responses.pop();
                responses.push(']');
                RpcResult(responses)
            }
            Err(e) => RpcResult::single(
                JsonRpcResponse::error(
                    serde_json::Value::Null,
                    JsonRpcError::parse_error(format!("parse error: {e}")),
                ),
                max_response_size,
            ),
        }
    } else {
        match serde_json::from_str::<JsonRpcRequest>(trimmed) {
            Ok(request) => RpcResult::single(
                dispatch_request(&request, auth, api).await,
                max_response_size,
            ),
            Err(e) => RpcResult::single(
                JsonRpcResponse::error(
                    serde_json::Value::Null,
                    JsonRpcError::parse_error(format!("parse error: {e}")),
                ),
                max_response_size,
            ),
        }
    }
}

pub(crate) async fn dispatch_request(
    req: &JsonRpcRequest,
    auth: &AuthContext,
    api: &dyn SphereRpcApi,
) -> JsonRpcResponse {
    let metrics = RedactedRpcCallMetrics::new_for(&req.method);
    let started_at = Instant::now();

    metrics.started_total.increment(1);
    let response = handlers::dispatch(req, auth, api).await;
    metrics
        .time_seconds
        .record(started_at.elapsed().as_secs_f64());

    if response.error.is_some() {
        metrics.failed_total.increment(1);
    } else {
        metrics.successful_total.increment(1);
    }

    response
}

/// Main HTTP RPC handler — authenticates, dispatches, returns response.
async fn handle_rpc(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let auth = match authenticate(&headers, &state.config).await {
        Ok(auth) => auth,
        Err(e) => {
            if e.is_invalid() {
                state.auth_metrics.auth_failures_total.increment(1);
            }
            e.log("http");
            return (e.status_code(), "").into_response();
        }
    };

    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid UTF-8").into_response();
        }
    };

    process_rpc_text(
        body_str,
        &auth,
        state.api.as_ref(),
        state.config.max_response_size,
    )
    .await
    .into_response()
}

/// Authenticate the request using the `X-Authorization-Token` header.
async fn authenticate(
    headers: &HeaderMap,
    config: &RedactedRpcConfig,
) -> Result<AuthContext, AuthenticateError> {
    let header_value = headers
        .get(auth::X_AUTHORIZATION_TOKEN)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Missing)?;

    authenticate_token(header_value, config).await
}

/// Authenticate using a raw token string (shared by HTTP and WebSocket paths).
pub(crate) async fn authenticate_token(
    token_value: &str,
    config: &RedactedRpcConfig,
) -> Result<AuthContext, AuthenticateError> {
    let token = auth::parse_auth_header(token_value)?;
    let max_auth_token_validity = config
        .max_auth_token_validity
        .min(auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY);

    // Validate token fields against server config
    token.validate_with_max_auth_token_validity(
        config.sphere_id,
        config.chain_id,
        max_auth_token_validity,
    )?;

    let signature = alloy_primitives::Signature::try_from(token.signature.as_ref())
        .map_err(|_| AuthError::InvalidSignature)?;
    let caller = alloy_consensus::crypto::secp256k1::recover_signer(&signature, token.digest)
        .map_err(|_| AuthError::InvalidSignature)?;

    Ok(AuthContext {
        caller,
        expires_at: token.expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::to_raw;

    #[test]
    fn oversized_response_matches_jsonrpsee_error() {
        let response = JsonRpcResponse::success(
            serde_json::json!(7),
            to_raw(&"x".repeat(128)).expect("test response serializes"),
        );

        let response = serialize_response_with_limit(response, 64);
        let response: serde_json::Value =
            serde_json::from_str(&response).expect("response is valid JSON");

        assert_eq!(response["id"], serde_json::json!(7));
        assert_eq!(response["error"]["code"], serde_json::json!(-32008));
        assert_eq!(response["error"]["message"], "Response is too big");
        assert_eq!(response["error"]["data"], "Exceeded max limit of 64");
    }

    #[test]
    fn batch_response_limit_is_aggregate() {
        let response = JsonRpcResponse::success(
            serde_json::json!(1),
            to_raw(&"result").expect("test response serializes"),
        );
        let serialized = serialize_response(response.clone());
        // Exactly enough bytes for `[response]`, but not for a second response.
        let max_response_size = serialized.len() + 2;
        let mut batch = String::from("[");

        append_batch_response(&mut batch, response.clone(), max_response_size)
            .expect("one response fits");
        let error = append_batch_response(&mut batch, response, max_response_size)
            .expect_err("aggregate batch response exceeds the limit");
        let error: serde_json::Value =
            serde_json::from_str(&error).expect("response is valid JSON");

        assert_eq!(error["id"], serde_json::Value::Null);
        assert_eq!(error["error"]["code"], serde_json::json!(-32011));
        assert_eq!(
            error["error"]["message"],
            "The batch response was too large"
        );
        assert_eq!(
            error["error"]["data"],
            format!("Exceeded max limit of {max_response_size}")
        );
    }
}
