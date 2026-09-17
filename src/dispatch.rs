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
        "[DISPATCH] query_dispatch: {query:?}"
    );

    let response = json!({
        "retcode": 0,
        "region_list": [
            {
                "name": "prod_gf_cn",
                "title": "roxy",
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
    println!(
        "[DISPATCH] query_gateway: prod_gf_cn"
    );

    let response = json!({
        "retcode": 0,
        "message": "OK",
        "data": {
            "dispatch_url": "http://127.0.0.1:12401/query_gateway/prod_gf_cn",
            "gateway_url": "http://127.0.0.1:10000"
        }
    });

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        response.to_string(),
    )
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
        TcpListener::bind(
            "127.0.0.1:12401"
        ).await?;

    println!(
        "[DISPATCH] Listening on 127.0.0.1:12401"
    );

    axum::serve(
        listener,
        app,
    )
    .await?;

    Ok(())
}