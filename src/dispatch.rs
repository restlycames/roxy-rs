use axum::{
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, head},
    Router,
};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;

use crate::rsa;

#[derive(Debug, Deserialize)]
struct DispatchQuery {
    version: String,
    language: String,
    channel_id: String,
    sub_channel_id: String,
    platform: String,
}

async fn query_dispatch(
    Query(query): Query<DispatchQuery>,
) -> impl IntoResponse {
    println!(
        "[DISPATCH] query_dispatch: version={} language={} channel={} sub_channel={} platform={}",
        query.version,
        query.language,
        query.channel_id,
        query.sub_channel_id,
        query.platform
    );

    let response = json!({
        "retcode": 0,
        "region_list": [
            {
                "name": "prod_gf_cn",
                "title": "Roxy",
                "dispatch_url": "http://127.0.0.1:12401/query_gateway/prod_gf_cn",
                "ping_url": "",
                "biz": "nap_global",
                "area": 2,
                "env": 2,
                "retcode": 0,
                "is_recommend": true
            }
        ]
    });

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        response.to_string(),
    )
}

async fn query_gateway() -> impl IntoResponse {
    println!("[DISPATCH] query_gateway: prod_gf_cn");

    /*
     * This is the plaintext structure expected by the
     * CNBetaWin3.3.2 client after RSA decryption.
     *
     * Keep the field names exactly as they are.
     */
    let gateway = json!({
        "retcode": 0,
        "title": "Roxy",
        "region_name": "prod_gf_cn",

        "client_secret_key": "roxy",

        "gateway": {
            "ip": "127.0.0.1",
            "port": 20501
        },

        "region_ext": {
            "func_switch": {
                "isKcp": 1
            }
        },

        "cdn_conf_ext": {
            "design_data": {
                "base_url": "https://autopatchcn.juequling.com/design_data/beta_live/output_18899788_c54f6f6d85/client/",
                "data_revision": "18899788",
                "md5_files": "[{\"fileName\":\"data_version\",\"fileSize\":6130,\"fileMD5\":\"17749673979304245076\"}]"
            },

            "game_res": {
                "audio_revision": "18870681",
                "base_url": "https://autopatchcn.juequling.com/game_res/beta_live/output_18899788_c54f6f6d85/client/",
                "branch": "beta_live",
                "md5_files": "[{\"fileName\":\"res_version\",\"fileSize\":3073028,\"fileMD5\":\"15342633487325113642\"},{\"fileName\":\"audio_version\",\"fileSize\":67676,\"fileMD5\":\"16254747493890496990\"},{\"fileName\":\"base_revision\",\"fileSize\":19,\"fileMD5\":\"11348633997289929401\"}]",
                "res_revision": "18899788"
            },

            "silence_data": {
                "base_url": "https://autopatchcn.juequling.com/design_data/beta_live/output_18899788_c54f6f6d85/client_silence/",
                "md5_files": "[{\"fileName\":\"silence_version\",\"fileSize\":600,\"fileMD5\":\"12857468659010489073\"}]",
                "silence_revision": "18899788"
            }
        }
    });

    let plaintext = gateway.to_string();

    println!(
        "[DISPATCH] Gateway plaintext: {} bytes",
        plaintext.len()
    );

    /*
     * RSA-1024 can encrypt at most 117 bytes with
     * PKCS#1 v1.5 padding.
     *
     * Roxy's RSA helper splits the plaintext into blocks,
     * encrypts every block and concatenates them.
     */
    match rsa::encrypt_gateway(&plaintext) {
        Ok((content, sign)) => {
            let response = json!({
                "content": content,
                "sign": sign
            });

            println!(
                "[DISPATCH] Gateway response generated: content={} bytes, sign={} bytes",
                content.len(),
                sign.len()
            );

            (
                StatusCode::OK,
                [("content-type", "application/json")],
                response.to_string(),
            )
        }

        Err(error) => {
            eprintln!(
                "[DISPATCH] Failed to encrypt gateway response: {error}"
            );

            let response = json!({
                "retcode": -1,
                "message": error.to_string()
            });

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "application/json")],
                response.to_string(),
            )
        }
    }
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route(
            "/query_dispatch",
            get(query_dispatch),
        )
        .route(
            "/query_dispatch",
            head(query_dispatch),
        )
        .route(
            "/query_gateway/prod_gf_cn",
            get(query_gateway),
        );

    let listener =
        TcpListener::bind("127.0.0.1:12401").await?;

    println!(
        "[DISPATCH] Listening on 127.0.0.1:12401"
    );

    axum::serve(listener, app).await?;

    Ok(())
}