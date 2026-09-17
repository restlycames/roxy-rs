use crate::rsa;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Response,
    Router,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs,
    net::TcpListener,
    sync::Mutex,
};

const ACCOUNT_DB: &str = "data/accounts.json";

type SharedDatabase = Arc<Mutex<AccountDatabase>>;

#[derive(Debug, Serialize, Deserialize)]
struct AccountDatabase {
    next_uid: u32,
    accounts: HashMap<String, Account>,
}

impl Default for AccountDatabase {
    fn default() -> Self {
        Self {
            next_uid: 10_000_001,
            accounts: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Account {
    uid: u32,
    username: String,
    password_hash: String,
    token: String,
}

#[derive(Debug, Deserialize)]
struct LoginByPasswordRequest {
    account: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct VerifySTokenRequest {
    mid: String,
    stoken: String,
}

#[derive(Debug, Deserialize)]
struct ComboLoginRequest {
    data: String,
    app_id: u32,
    channel_id: u32,
    device: String,
    sign: String,
}

#[derive(Debug, Deserialize)]
struct ComboLoginData {
    uid: String,
    guest: bool,
    token: String,
}

#[derive(Debug, Serialize)]
struct ApiResponse<T: Serialize> {
    retcode: i32,
    message: String,
    data: T,
}

fn json_response<T: Serialize>(
    status: StatusCode,
    value: T,
) -> Response {
    let body = serde_json::to_string(&value).unwrap();

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn error_response(
    retcode: i32,
    message: &str,
) -> Response {
    json_response(
        StatusCode::OK,
        ApiResponse {
            retcode,
            message: message.to_string(),
            data: serde_json::Value::Null,
        },
    )
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();

    hasher.update(password.as_bytes());

    hex::encode(hasher.finalize())
}

fn generate_token(
    uid: u32,
    username: &str,
) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut hasher = Sha256::new();

    hasher.update(uid.to_string().as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(timestamp.to_string().as_bytes());

    hex::encode(hasher.finalize())
}

async fn load_database()
    -> Result<
        AccountDatabase,
        Box<dyn std::error::Error>,
    >
{
    if !Path::new(ACCOUNT_DB).exists() {
        println!(
            "[SDK] No account database found, creating a new one"
        );

        return Ok(AccountDatabase::default());
    }

    let data =
        fs::read_to_string(ACCOUNT_DB).await?;

    let database: AccountDatabase =
        serde_json::from_str(&data)?;

    println!(
        "[SDK] Loaded {} account(s)",
        database.accounts.len()
    );

    Ok(database)
}

async fn save_database(
    database: &AccountDatabase,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) =
        Path::new(ACCOUNT_DB).parent()
    {
        fs::create_dir_all(parent).await?;
    }

    let json =
        serde_json::to_string_pretty(database)?;

    fs::write(
        ACCOUNT_DB,
        json,
    ).await?;

    Ok(())
}

fn decrypt_field(
    value: &str,
) -> Result<String, String> {
    let decrypted =
        rsa::decrypt_base64(value)
            .map_err(|error| {
                format!(
                    "RSA decrypt failed: {error}"
                )
            })?;

    String::from_utf8(decrypted)
        .map_err(|error| {
            format!(
                "UTF-8 decode failed: {error}"
            )
        })
}

fn user_info(
    account: &Account,
) -> serde_json::Value {
    serde_json::json!({
        "aid": account.uid.to_string(),
        "mid": account.uid.to_string(),
        "account_name": "",
        "email": account.username,
        "is_email_verify": 0,
        "area_code": "**",
        "mobile": "",
        "safe_area_code": "",
        "safe_mobile": "",
        "realname": "",
        "identity_code": "",
        "rebind_area_code": "",
        "rebind_mobile": "",
        "rebind_mobile_time": "228",
        "links": [],
        "country": "RU",
        "password_time": "1337",
        "is_adult": 0,
        "unmasked_email": "",
        "unmasked_email_type": 0
    })
}

fn login_response(
    account: &Account,
) -> Response {
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "retcode": 0,
            "message": "OK",
            "data": {
                "token": {
                    "token_type": 1,
                    "token": account.token
                },
                "user_info": user_info(account),
                "ext_user_info": {
                    "guardian_email": "",
                    "birth": "0"
                },
                "reactivate_action_ticket": "",
                "bind_email_action_ticket": ""
            }
        }),
    )
}

async fn handle_login(
    database: SharedDatabase,
    body: String,
) -> Response {
    println!(
        "[SDK] Login request received"
    );

    let request:
        LoginByPasswordRequest =
        match serde_json::from_str(&body) {
            Ok(value) => value,

            Err(error) => {
                println!(
                    "[SDK] Invalid login JSON: {error}"
                );

                return error_response(
                    -1,
                    "Invalid request",
                );
            }
        };

    println!(
        "[SDK] account ciphertext length: {}",
        request.account.len()
    );

    println!(
        "[SDK] password ciphertext length: {}",
        request.password.len()
    );

    let username =
        match decrypt_field(&request.account) {
            Ok(value) => value,

            Err(error) => {
                println!(
                    "[SDK] Account decrypt failed: {error}"
                );

                return error_response(
                    -101,
                    "Login failed. Your client patch might be unsupported.",
                );
            }
        };

    let password =
        match decrypt_field(&request.password) {
            Ok(value) => value,

            Err(error) => {
                println!(
                    "[SDK] Password decrypt failed: {error}"
                );

                return error_response(
                    -101,
                    "Login failed. Your client patch might be unsupported.",
                );
            }
        };

    println!(
        "[SDK] Login username: {}",
        username
    );

    if username.is_empty() {
        return error_response(
            -101,
            "Username is empty",
        );
    }

    if username.len() > 64 {
        return error_response(
            -101,
            "Username is too long",
        );
    }

    let password_hash =
        hash_password(&password);

    let mut database =
        database.lock().await;

    if let Some(account) =
        database.accounts.get(&username)
    {
        if account.password_hash
            != password_hash
        {
            println!(
                "[SDK] Wrong password"
            );

            return error_response(
                -101,
                "Account or password error",
            );
        }

        println!(
            "[SDK] Existing account login: uid={}",
            account.uid
        );

        return login_response(account);
    }

    let uid =
        database.next_uid;

    database.next_uid += 1;

    let account = Account {
        uid,
        username: username.clone(),
        password_hash,
        token: generate_token(
            uid,
            &username,
        ),
    };

    database.accounts.insert(
        username,
        account.clone(),
    );

    if let Err(error) =
        save_database(&database).await
    {
        println!(
            "[SDK] Failed to save account: {error}"
        );

        return error_response(
            -1,
            "Failed to save account",
        );
    }

    println!(
        "[SDK] Account saved: uid={}",
        uid
    );

    login_response(&account)
}

async fn handle_verify_stoken(
    database: SharedDatabase,
    body: String,
) -> Response {
    let request:
        VerifySTokenRequest =
        match serde_json::from_str(&body) {
            Ok(value) => value,

            Err(_) => {
                return error_response(
                    -1,
                    "Invalid request",
                );
            }
        };

    let uid: u32 =
        match request.mid.parse() {
            Ok(value) => value,

            Err(_) => {
                return error_response(
                    -101,
                    "For account safety, please log in again.",
                );
            }
        };

    let database =
        database.lock().await;

    let account =
        database
            .accounts
            .values()
            .find(|account| {
                account.uid == uid
            });

    let Some(account) = account else {
        return error_response(
            -101,
            "For account safety, please log in again.",
        );
    };

    if account.token
        != request.stoken
    {
        return error_response(
            -101,
            "For account safety, please log in again.",
        );
    }

    println!(
        "[SDK] STOKEN verified: uid={}",
        uid
    );

    login_response(account)
}

async fn handle_combo_login(
    database: SharedDatabase,
    body: String,
) -> Response {
    println!(
        "[SDK] Combo login request received"
    );

    let request:
        ComboLoginRequest =
        match serde_json::from_str(&body) {
            Ok(value) => value,

            Err(error) => {
                println!(
                    "[SDK] Invalid combo request JSON: {error}"
                );

                return error_response(
                    -1,
                    "Invalid request",
                );
            }
        };

    println!(
        "[SDK] Combo app_id: {}",
        request.app_id
    );

    println!(
        "[SDK] Combo channel_id: {}",
        request.channel_id
    );

    let data:
        ComboLoginData =
        match serde_json::from_str(
            &request.data
        ) {
            Ok(value) => value,

            Err(error) => {
                println!(
                    "[SDK] Invalid combo data JSON: {error}"
                );

                return error_response(
                    -1,
                    "Invalid combo data",
                );
            }
        };

    let uid: u32 =
        match data.uid.parse() {
            Ok(value) => value,

            Err(_) => {
                println!(
                    "[SDK] Invalid combo uid: {}",
                    data.uid
                );

                return error_response(
                    -101,
                    "Invalid uid",
                );
            }
        };

    let database =
        database.lock().await;

    let account =
        database
            .accounts
            .values()
            .find(|account| {
                account.uid == uid
            });

    let Some(account) = account else {
        println!(
            "[SDK] Combo login: account not found uid={}",
            uid
        );

        return error_response(
            -101,
            "Account not found",
        );
    };

    if account.token
        != data.token
    {
        println!(
            "[SDK] Combo login: invalid token uid={}",
            uid
        );

        return error_response(
            -101,
            "Invalid token",
        );
    }

    println!(
        "[SDK] Combo login successful: uid={}",
        uid
    );

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "retcode": 0,
            "message": "OK",
            "data": {
                "account_type": 1,
                "combo_id": account.uid.to_string(),
                "combo_token": account.token,
                "data": "{\"guest\":false}",
                "heartbeat": false,
                "open_id": account.uid.to_string()
            }
        }),
    )
}

async fn handle_logout() -> Response {
    println!(
        "[SDK] Logout"
    );

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "retcode": 0,
            "message": "OK",
            "data": null
        }),
    )
}

async fn handle_load_config() -> Response {
    println!(
        "[SDK] Load config"
    );

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "retcode": 0,
            "message": "OK",
            "data": {
                "id": 31,
                "game_key": "nap_cn",
                "client": "PC",
                "identity": "I_IDENTITY",
                "guest": false,
                "ignore_versions": "",
                "scene": "S_NORMAL",
                "name": "Nap",
                "disable_regist": false,
                "enable_email_captcha": false,
                "thirdparty": [],
                "disable_mmt": false,
                "server_guest": false,
                "thirdparty_ignore": {},
                "enable_ps_bind_account": false,
                "thirdparty_login_configs": {},
                "initialize_firebase": false,
                "bbs_auth_login": false,
                "bbs_auth_login_ignore": [],
                "fetch_instance_id": false,
                "enable_flash_login": false,
                "enable_logo_18": false,
                "logo_height": "0",
                "logo_width": "0",
                "enable_cx_bind_account": false
            }
        }),
    )
}

async fn handle_data_upload(
    body: String,
) -> Response {
    println!(
        "[SDK] dataUpload: {} bytes",
        body.len()
    );

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "retcode": 0,
            "message": "OK",
            "data": null
        }),
    )
}

async fn handle_request(
    State(database): State<SharedDatabase>,
    request: Request<Body>,
) -> Response {
    let method =
        request.method().clone();

    let path =
        request.uri().path().to_string();

    println!(
        "[SDK] {} {}",
        method,
        path
    );

    let body =
        match axum::body::to_bytes(
            request.into_body(),
            10 * 1024 * 1024,
        )
        .await
        {
            Ok(bytes) => {
                String::from_utf8_lossy(
                    &bytes
                )
                .to_string()
            }

            Err(error) => {
                println!(
                    "[SDK] Failed to read body: {error}"
                );

                return error_response(
                    -1,
                    "Failed to read request",
                );
            }
        };

    match (
        method.as_str(),
        path.as_str(),
    ) {
        (
            "POST",
            "/nap_global/account/ma-passport/api/appLoginByPassword",
        )
        | (
            "POST",
            "/account/ma-passport/api/appLoginByPassword",
        ) => {
            handle_login(
                database,
                body,
            )
            .await
        }

        (
            "POST",
            "/nap_global/account/ma-passport/token/verifySToken",
        )
        | (
            "POST",
            "/account/ma-passport/token/verifySToken",
        ) => {
            handle_verify_stoken(
                database,
                body,
            )
            .await
        }

        (
            "POST",
            "/nap_global/combo/granter/login/v2/login",
        )
        | (
            "POST",
            "/combo/granter/login/v2/login",
        ) => {
            handle_combo_login(
                database,
                body,
            )
            .await
        }

        (
            "POST",
            "/nap_global/account/ma-passport/api/logout",
        )
        | (
            "POST",
            "/account/ma-passport/api/logout",
        ) => {
            handle_logout().await
        }

        (
            "GET",
            "/nap_global/mdk/shield/api/loadConfig",
        )
        | (
            "GET",
            "/mdk/shield/api/loadConfig",
        )
        | (
            "POST",
            "/nap_global/mdk/shield/api/loadConfig",
        )
        | (
            "POST",
            "/mdk/shield/api/loadConfig",
        ) => {
            handle_load_config().await
        }

        (
            "POST",
            "/nap_global/sdk/dataUpload",
        )
        | (
            "POST",
            "/sdk/dataUpload",
        ) => {
            handle_data_upload(
                body
            )
            .await
        }

        _ => {
            println!(
                "[SDK] Unimplemented endpoint: {} {}",
                method,
                path
            );

            error_response(
                -1,
                "Endpoint not implemented",
            )
        }
    }
}

pub async fn run()
    -> Result<(), Box<dyn std::error::Error>>
{
    let database =
        load_database().await?;

    let database:
        SharedDatabase =
        Arc::new(
            Mutex::new(database)
        );

    let app = Router::new()
        .fallback(handle_request)
        .with_state(database);

    let listener =
        TcpListener::bind(
            "127.0.0.1:20100"
        )
        .await?;

    println!(
        "[SDK] Listening on 127.0.0.1:20100"
    );

    axum::serve(
        listener,
        app,
    )
    .await?;

    Ok(())
}