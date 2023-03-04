//! A module for operating an RGB HTTP JSON-RPC proxy

use amplify::s;
use reqwest::blocking::Client as BlockingClient;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use tokio::task;

use core::time::Duration;

const JSON: &str = "application/json";
const PROXY_TIMEOUT: u8 = 90;

/// JSON-RPC Error
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JsonRpcError {
    pub(crate) code: i64,
    message: String,
}

/// JSON-RPC request
#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcRequest<P> {
    method: String,
    jsonrpc: String,
    id: Option<String>,
    params: Option<P>,
}

/// JSON-RPC response
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JsonRpcResponse<R> {
    id: Option<String>,
    pub(crate) result: Option<R>,
    pub(crate) error: Option<JsonRpcError>,
}

/// Blinded UTXO parameter
#[derive(Debug, Deserialize, Serialize)]
pub struct BlindedUtxoParam {
    blinded_utxo: String,
}

fn get_blocking_client() -> BlockingClient {
    BlockingClient::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT as u64))
        .build()
        .expect("valid proxy")
}

pub(crate) fn get_consignment(
    url: &str,
    consignment_id: String,
) -> Result<JsonRpcResponse<String>, reqwest::Error> {
    task::block_in_place(|| {
        let body = JsonRpcRequest {
            method: s!("consignment.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(BlindedUtxoParam { blinded_utxo: consignment_id }),
        };
        get_blocking_client()
            .post(url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()?
            .json::<JsonRpcResponse<String>>()
    })
}
