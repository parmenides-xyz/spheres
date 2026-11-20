use std::{sync::Arc, time::Duration};

use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use futures::{SinkExt, StreamExt, stream};
use serde_json::{Value, json};
use sphere_rpc::{
    RedactedRpcConfig,
    auth::build_token_fields,
    handlers::SphereRpcApi,
    start_redacted_rpc,
    subscription::{BoxWsSubscriptionFut, WsSubscriptionStream},
    types::{BoxFut, JsonRpcError},
};
use tokio_tungstenite::{connect_async, tungstenite};

// ---------------------------------------------------------------------------
// Mock API
// ---------------------------------------------------------------------------

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

#[derive(Default)]
struct MockSphereRpcApi {
    ws_subscriptions_enabled: bool,
}

impl MockSphereRpcApi {
    fn with_ws_subscriptions() -> Self {
        Self {
            ws_subscriptions_enabled: true,
        }
    }
}

macro_rules! stub {
    ($method:ident $(, $arg:ident : $ty:ty)*) => {
        fn $method(&self $(, $arg: $ty)*) -> BoxFut<'_> {
            Box::pin(async { Err(JsonRpcError::internal("not implemented")) })
        }
    };
}

impl SphereRpcApi for MockSphereRpcApi {
    fn block_number(&self) -> BoxFut<'_> {
        Box::pin(async { sphere_rpc::types::to_raw(&"0x42") })
    }

    fn chain_id(&self) -> BoxFut<'_> {
        Box::pin(async { sphere_rpc::types::to_raw(&"0x1") })
    }

    stub!(net_version);
    stub!(client_version);
    stub!(syncing);
    stub!(coinbase);
    stub!(gas_price);
    stub!(max_priority_fee_per_gas);
    stub!(fee_history, _a: u64, _b: alloy_rpc_types_eth::BlockNumberOrTag, _c: Option<Vec<f64>>);
    stub!(get_balance, _a: Address, _b: Option<alloy_rpc_types_eth::BlockId>, _c: sphere_rpc::auth::AuthContext);
    stub!(get_transaction_count, _a: Address, _b: Option<alloy_rpc_types_eth::BlockId>, _c: sphere_rpc::auth::AuthContext);
    stub!(block_by_number, _a: alloy_rpc_types_eth::BlockNumberOrTag, _b: bool, _c: sphere_rpc::auth::AuthContext);
    stub!(block_by_hash, _a: alloy_primitives::B256, _b: bool, _c: sphere_rpc::auth::AuthContext);
    stub!(transaction_by_hash, _a: alloy_primitives::B256, _c: sphere_rpc::auth::AuthContext);
    stub!(transaction_receipt, _a: alloy_primitives::B256, _c: sphere_rpc::auth::AuthContext);
    stub!(call, _a: alloy_rpc_types_eth::TransactionRequest, _b: Option<alloy_rpc_types_eth::BlockId>, _c: Option<alloy_rpc_types_eth::state::StateOverride>, _d: sphere_rpc::auth::AuthContext);
    stub!(estimate_gas, _a: alloy_rpc_types_eth::TransactionRequest, _b: Option<alloy_rpc_types_eth::BlockId>, _c: Option<alloy_rpc_types_eth::state::StateOverride>, _d: sphere_rpc::auth::AuthContext);
    stub!(send_raw_transaction, _a: alloy_primitives::Bytes, _c: sphere_rpc::auth::AuthContext);
    fn send_raw_transaction_sync(
        &self,
        _data: alloy_primitives::Bytes,
        _auth: sphere_rpc::auth::AuthContext,
    ) -> BoxFut<'_> {
        Box::pin(async { Err(JsonRpcError::internal("not implemented")) })
    }
    stub!(fill_transaction, _a: alloy_rpc_types_eth::TransactionRequest, _c: sphere_rpc::auth::AuthContext);
    stub!(get_logs, _a: alloy_rpc_types_eth::Filter, _c: sphere_rpc::auth::AuthContext);
    stub!(new_filter, _a: alloy_rpc_types_eth::Filter, _c: sphere_rpc::auth::AuthContext);
    stub!(get_filter_logs, _a: alloy_rpc_types_eth::FilterId, _c: sphere_rpc::auth::AuthContext);
    stub!(get_filter_changes, _a: alloy_rpc_types_eth::FilterId, _c: sphere_rpc::auth::AuthContext);
    stub!(new_block_filter, _c: sphere_rpc::auth::AuthContext);
    stub!(uninstall_filter, _a: alloy_rpc_types_eth::FilterId, _c: sphere_rpc::auth::AuthContext);

    fn ws_subscribe_new_heads(
        &self,
        _auth: sphere_rpc::auth::AuthContext,
    ) -> BoxWsSubscriptionFut<'_> {
        let enabled = self.ws_subscriptions_enabled;
        Box::pin(async move {
            if !enabled {
                return Err(JsonRpcError::method_disabled());
            }

            let stream = stream::iter(vec![sphere_rpc::types::to_raw(&json!({
                "hash": B256::repeat_byte(0x44)
                    .to_string(),
                "number": "0x42",
                "parentHash": alloy_primitives::B256::ZERO.to_string(),
                "logsBloom": format!("{:#x}", alloy_primitives::Bloom::ZERO),
                "gasUsed": "0x0",
                "size": "0x0",
                "transactionsRoot": alloy_primitives::B256::ZERO.to_string(),
                "receiptsRoot": alloy_primitives::B256::ZERO.to_string(),
                "stateRoot": alloy_primitives::B256::ZERO.to_string(),
                "extraData": "0x",
            }))]);
            let stream: WsSubscriptionStream = Box::pin(stream);
            Ok(stream)
        })
    }

    fn ws_subscribe_logs(
        &self,
        _filter: alloy_rpc_types_eth::Filter,
        _auth: sphere_rpc::auth::AuthContext,
    ) -> BoxWsSubscriptionFut<'_> {
        let enabled = self.ws_subscriptions_enabled;
        Box::pin(async move {
            if !enabled {
                return Err(JsonRpcError::method_disabled());
            }

            let stream = stream::iter(vec![sphere_rpc::types::to_raw(&json!({
                "address": format!("{:#x}", Address::ZERO),
                "topics": [
                    B256::repeat_byte(0x11)
                        .to_string()
                ],
                "data": "0x",
                "blockHash": B256::repeat_byte(0x22)
                .to_string(),
                "blockNumber": "0x42",
                "transactionHash": B256::repeat_byte(0x33)
                .to_string(),
                "transactionIndex": "0x0",
                "logIndex": "0x0",
                "removed": false
            }))]);
            let stream: WsSubscriptionStream = Box::pin(stream);
            Ok(stream)
        })
    }

    fn sphere_get_authorization_token_info(
        &self,
        auth: sphere_rpc::auth::AuthContext,
    ) -> BoxFut<'_> {
        Box::pin(async move {
            sphere_rpc::types::to_raw(&serde_json::json!({
                "account": auth.caller,
                "expiresAt": alloy_primitives::U64::from(auth.expires_at),
            }))
        })
    }

    fn sphere_get_sphere_info(&self, _auth: sphere_rpc::auth::AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            sphere_rpc::types::to_raw(&serde_json::json!({
                "sphereId": "0x1",
                "sphereTokens": [format!("{:#x}", Address::repeat_byte(0x11))],
                "chainId": "0x2a",
            }))
        })
    }

    fn sphere_get_encryption_key(&self, _auth: sphere_rpc::auth::AuthContext) -> BoxFut<'_> {
        Box::pin(async { Err(sphere_rpc::types::JsonRpcError::internal("not implemented")) })
    }
}

// ---------------------------------------------------------------------------
// Test context
// ---------------------------------------------------------------------------

const SPHERE_ID: u32 = 1;
const CHAIN_ID: u64 = 42;

struct TestContext {
    addr: std::net::SocketAddr,
    signer: PrivateKeySigner,
}

impl TestContext {
    async fn start(api: MockSphereRpcApi) -> Self {
        Self::start_shared(Arc::new(api)).await
    }

    async fn start_shared(api: Arc<MockSphereRpcApi>) -> Self {
        Self::start_shared_with_max_response_size(api, 160 * 1024 * 1024).await
    }

    async fn start_with_max_response_size(api: MockSphereRpcApi, max_response_size: usize) -> Self {
        Self::start_shared_with_max_response_size(Arc::new(api), max_response_size).await
    }

    async fn start_shared_with_max_response_size(
        api: Arc<MockSphereRpcApi>,
        max_response_size: usize,
    ) -> Self {
        let signer = PrivateKeySigner::random();
        let config = RedactedRpcConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            sphere_id: SPHERE_ID,
            chain_id: CHAIN_ID,
            max_auth_token_validity: sphere_rpc::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY,
            max_response_size,
            sphere_portal: Address::ZERO,
        };
        let addr = start_redacted_rpc(config, api).await.unwrap();
        Self { addr, signer }
    }

    fn build_token(&self) -> String {
        let now = now_secs();
        self.build_token_expiring_at(now, now + 600)
    }

    fn build_token_expiring_at(&self, issued_at: u64, expires_at: u64) -> String {
        let (fields, digest) = build_token_fields(SPHERE_ID, CHAIN_ID, issued_at, expires_at);
        let sig = self.signer.sign_hash_sync(&digest).expect("signing failed");

        alloy_primitives::hex::encode([sig.as_rsy().as_slice(), &fields].concat())
    }

    fn ws_url(&self) -> String {
        format!("ws://{}", self.addr)
    }
}

/// Build a JSON-RPC request string.
fn jsonrpc(method: &str, id: u64) -> String {
    serde_json::json!({"jsonrpc":"2.0","method":method,"params":[],"id":id}).to_string()
}

fn jsonrpc_with_params(method: &str, params: Value, id: u64) -> String {
    serde_json::json!({"jsonrpc":"2.0","method":method,"params":params,"id":id}).to_string()
}

/// Connect to the WS endpoint using the X-Authorization-Token header.
async fn connect_with_header(
    ctx: &TestContext,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let token = ctx.build_token();
    connect_with_token(&ctx.ws_url(), ctx.addr, &token)
        .await
        .expect("ws connect failed")
}

async fn connect_with_token(
    ws_url: &str,
    addr: std::net::SocketAddr,
    token: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tungstenite::Error,
> {
    let req = tungstenite::http::Request::builder()
        .uri(ws_url)
        .header("x-authorization-token", token)
        .header(
            "sec-websocket-key",
            tungstenite::handshake::client::generate_key(),
        )
        .header("host", addr.to_string())
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header("sec-websocket-version", "13")
        .body(())
        .unwrap();

    connect_async(req).await.map(|(ws, _)| ws)
}

/// Parse a JSON-RPC response from a WS text message.
fn parse_response(msg: tungstenite::Message) -> Value {
    match msg {
        tungstenite::Message::Text(t) => serde_json::from_str(&t).expect("invalid json"),
        other => panic!("expected text message, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ws_roundtrip_with_header_auth() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text(
        jsonrpc("eth_blockNumber", 1).into(),
    ))
    .await
    .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"], "0x42");
}

#[tokio::test]
async fn ws_roundtrip_with_query_auth() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let token = ctx.build_token();
    let url = format!("{}/?token={token}", ctx.ws_url());

    let (mut ws, _) = connect_async(&url).await.expect("ws connect failed");

    ws.send(tungstenite::Message::Text(
        jsonrpc("eth_blockNumber", 1).into(),
    ))
    .await
    .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"], "0x42");
}

#[tokio::test]
async fn ws_reject_no_auth() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let result = connect_async(ctx.ws_url()).await;
    // Server should reject the upgrade — tungstenite surfaces this as an error
    // with the HTTP 401 status.
    let err = result.expect_err("should fail without auth");
    let tungstenite::Error::Http(response) = err else {
        panic!("expected HTTP error, got {err:?}");
    };
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn ws_reject_invalid_token() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let req = tungstenite::http::Request::builder()
        .uri(ctx.ws_url())
        .header("x-authorization-token", "deadbeef")
        .header(
            "sec-websocket-key",
            tungstenite::handshake::client::generate_key(),
        )
        .header("host", ctx.addr.to_string())
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header("sec-websocket-version", "13")
        .body(())
        .unwrap();

    let err = connect_async(req)
        .await
        .expect_err("should fail with bad token");
    let tungstenite::Error::Http(response) = err else {
        panic!("expected HTTP error, got {err:?}");
    };
    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn ws_multiple_requests() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let mut ws = connect_with_header(&ctx).await;

    for i in 1..=5 {
        ws.send(tungstenite::Message::Text(
            jsonrpc("eth_blockNumber", i).into(),
        ))
        .await
        .unwrap();
        let resp = parse_response(ws.next().await.unwrap().unwrap());
        assert_eq!(resp["id"], i);
        assert_eq!(resp["result"], "0x42");
    }
}

#[tokio::test]
async fn ws_batch_request() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let mut ws = connect_with_header(&ctx).await;

    let batch = serde_json::json!([
        {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},
        {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2},
    ]);
    ws.send(tungstenite::Message::Text(batch.to_string().into()))
        .await
        .unwrap();

    let resp = parse_response(ws.next().await.unwrap().unwrap());
    let arr = resp.as_array().expect("expected batch response array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], 1);
    assert_eq!(arr[0]["result"], "0x42");
    assert_eq!(arr[1]["id"], 2);
    assert_eq!(arr[1]["result"], "0x1");
}

#[tokio::test]
async fn ws_oversized_response_matches_jsonrpsee_error() {
    let ctx = TestContext::start_with_max_response_size(MockSphereRpcApi::default(), 64).await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text(
        jsonrpc("sphere_getSphereInfo", 7).into(),
    ))
    .await
    .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["id"], 7);
    assert_eq!(resp["error"]["code"], -32008);
    assert_eq!(resp["error"]["message"], "Response is too big");
    assert_eq!(resp["error"]["data"], "Exceeded max limit of 64");
}

#[tokio::test]
async fn ws_batch_response_limit_is_aggregate() {
    let one_response = json!({"jsonrpc":"2.0","result":"0x42","id":1}).to_string();
    let max_response_size = one_response.len() + 2;
    let ctx =
        TestContext::start_with_max_response_size(MockSphereRpcApi::default(), max_response_size)
            .await;
    let mut ws = connect_with_header(&ctx).await;
    let batch = json!([
        {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},
        {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2},
    ]);

    ws.send(tungstenite::Message::Text(batch.to_string().into()))
        .await
        .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["id"], Value::Null);
    assert_eq!(resp["error"]["code"], -32011);
    assert_eq!(resp["error"]["message"], "The batch response was too large");
    assert_eq!(
        resp["error"]["data"],
        format!("Exceeded max limit of {max_response_size}")
    );
}

#[tokio::test]
async fn ws_invalid_json() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text("{broken".into()))
        .await
        .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["error"]["code"], -32700);
}

#[tokio::test]
async fn ws_unknown_method() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text(jsonrpc("eth_foobar", 1).into()))
        .await
        .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["id"], 1);
    assert_eq!(resp["error"]["code"], -32601);
}

#[tokio::test]
async fn ws_disabled_subscription_method() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text(
        jsonrpc_with_params("eth_subscribe", json!(["newHeads"]), 1).into(),
    ))
    .await
    .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["id"], 1);
    assert_eq!(resp["error"]["code"], -32006);
}

#[tokio::test]
async fn ws_subscribe_new_heads_emits_redacted_headers() {
    let ctx = TestContext::start(MockSphereRpcApi::with_ws_subscriptions()).await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text(
        jsonrpc_with_params("eth_subscribe", json!(["newHeads"]), 1).into(),
    ))
    .await
    .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["id"], 1);
    let subscription_id = resp["result"].as_str().expect("subscription id");

    let notification = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timed out waiting for newHeads notification")
        .unwrap()
        .unwrap();
    let notification = parse_response(notification);

    assert_eq!(notification["method"], "eth_subscription");
    assert_eq!(notification["params"]["subscription"], subscription_id);
    assert_eq!(
        notification["params"]["result"]["hash"],
        B256::repeat_byte(0x44).to_string()
    );
    assert_eq!(
        notification["params"]["result"]["logsBloom"],
        alloy_primitives::Bloom::ZERO.to_string()
    );
    assert!(
        notification["params"]["result"]
            .get("transactions")
            .is_none()
    );
}

#[tokio::test]
async fn ws_subscription_notifications_match_unredacted_size_behavior() {
    let max_response_size = 64;
    let ctx = TestContext::start_with_max_response_size(
        MockSphereRpcApi::with_ws_subscriptions(),
        max_response_size,
    )
    .await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text(
        jsonrpc_with_params("eth_subscribe", json!(["newHeads"]), 1).into(),
    ))
    .await
    .unwrap();
    let response = parse_response(ws.next().await.unwrap().unwrap());
    assert!(response["result"].as_str().is_some());

    let notification = ws.next().await.unwrap().unwrap();
    let tungstenite::Message::Text(text) = &notification else {
        panic!("expected text notification");
    };
    assert!(text.len() > max_response_size);
    let notification = parse_response(notification);
    assert_eq!(notification["method"], "eth_subscription");
}

#[tokio::test]
async fn ws_subscribe_logs_emits_notifications() {
    let ctx = TestContext::start(MockSphereRpcApi::with_ws_subscriptions()).await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text(
        jsonrpc_with_params("eth_subscribe", json!(["logs", {}]), 1).into(),
    ))
    .await
    .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["id"], 1);
    let subscription_id = resp["result"].as_str().expect("subscription id");

    let notification = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timed out waiting for log notification")
        .unwrap()
        .unwrap();
    let notification = parse_response(notification);

    assert_eq!(notification["method"], "eth_subscription");
    assert_eq!(notification["params"]["subscription"], subscription_id);
    assert_eq!(notification["params"]["result"]["blockNumber"], "0x42");
}

#[tokio::test]
async fn ws_subscribe_pending_transactions_is_disabled() {
    let ctx = TestContext::start(MockSphereRpcApi::with_ws_subscriptions()).await;
    let mut ws = connect_with_header(&ctx).await;

    for (id, params) in [
        (1, json!(["newPendingTransactions"])),
        (2, json!(["newPendingTransactions", true])),
        (3, json!(["newPendingTransactions", {}])),
    ] {
        ws.send(tungstenite::Message::Text(
            jsonrpc_with_params("eth_subscribe", params, id).into(),
        ))
        .await
        .unwrap();
        let resp = parse_response(ws.next().await.unwrap().unwrap());

        assert_eq!(resp["id"], id);
        assert_eq!(resp["error"]["code"], -32006);
    }
}

#[tokio::test]
async fn ws_unsubscribe_removes_subscription() {
    let ctx = TestContext::start(MockSphereRpcApi::with_ws_subscriptions()).await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text(
        jsonrpc_with_params("eth_subscribe", json!(["logs", {}]), 1).into(),
    ))
    .await
    .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());
    let subscription_id = resp["result"].clone();

    ws.send(tungstenite::Message::Text(
        jsonrpc_with_params("eth_unsubscribe", json!([subscription_id]), 2).into(),
    ))
    .await
    .unwrap();
    let resp = loop {
        let message = parse_response(ws.next().await.unwrap().unwrap());
        if message["id"] == 2 {
            break message;
        }
    };

    assert_eq!(resp["id"], 2);
    assert_eq!(resp["result"], true);
}

#[tokio::test]
async fn ws_subscribe_rejects_invalid_param_shapes() {
    let ctx = TestContext::start(MockSphereRpcApi::with_ws_subscriptions()).await;
    let mut ws = connect_with_header(&ctx).await;

    for (id, params) in [(1, json!(["newHeads", false])), (2, json!(["logs", false]))] {
        ws.send(tungstenite::Message::Text(
            jsonrpc_with_params("eth_subscribe", params, id).into(),
        ))
        .await
        .unwrap();
        let resp = parse_response(ws.next().await.unwrap().unwrap());
        assert_eq!(resp["id"], id);
        assert_eq!(resp["error"]["code"], -32602);
    }
}

#[tokio::test]
async fn ws_subscribe_rejects_too_many_active_subscriptions() {
    let ctx = TestContext::start(MockSphereRpcApi::with_ws_subscriptions()).await;
    let mut ws = connect_with_header(&ctx).await;

    for id in 1..=32 {
        ws.send(tungstenite::Message::Text(
            jsonrpc_with_params("eth_subscribe", json!(["newHeads"]), id).into(),
        ))
        .await
        .unwrap();

        let resp = loop {
            let message = parse_response(ws.next().await.unwrap().unwrap());
            if message["id"] == id {
                break message;
            }
        };

        assert!(resp["result"].as_str().is_some());
    }

    ws.send(tungstenite::Message::Text(
        jsonrpc_with_params("eth_subscribe", json!(["newHeads"]), 33).into(),
    ))
    .await
    .unwrap();

    let resp = loop {
        let message = parse_response(ws.next().await.unwrap().unwrap());
        if message["id"] == 33 {
            break message;
        }
    };

    assert_eq!(resp["error"]["code"], -32602);
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("too many active subscriptions")
    );
}

#[tokio::test]
async fn ws_empty_batch() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let mut ws = connect_with_header(&ctx).await;

    ws.send(tungstenite::Message::Text("[]".into()))
        .await
        .unwrap();
    let resp = parse_response(ws.next().await.unwrap().unwrap());

    assert_eq!(resp["error"]["code"], -32700);
}

#[tokio::test]
async fn ws_closes_when_auth_token_expires() {
    let ctx = TestContext::start(MockSphereRpcApi::default()).await;
    let now = now_secs();
    let token = ctx.build_token_expiring_at(now, now + 1);
    let mut ws = connect_with_token(&ctx.ws_url(), ctx.addr, &token)
        .await
        .expect("ws connect failed");

    let _closed = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("timed out waiting for token-expiry close");
}
