//! End-to-end tests for the JWT validation middleware on `smolvm serve`.
//!
//! Each test:
//!   1. Generates an in-memory RSA keypair.
//!   2. Spawns a tiny mock JWKS server on a random TCP port serving the
//!      public key as a JWK.
//!   3. Builds a smolvm router with `Some(JwtConfig)` pointing at that
//!      JWKS URL and serves it on another random TCP port.
//!   4. Exercises the router with `reqwest`, checking that `/health` is
//!      always public and `/api/v1/*` requires a valid token.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{routing::get, Json, Router};
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use serde_json::json;
use smolvm::api::{auth::JwtConfig, create_router, state::ApiState};
use smolvm::db::SmolvmDb;
use tokio::net::TcpListener;

const KEY_BITS: usize = 2048;

struct TestKey {
    kid: String,
    private_pem: String,
    n_b64: String,
    e_b64: String,
}

impl TestKey {
    fn generate(kid: &str) -> Self {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, KEY_BITS).expect("rsa keygen");
        let public = RsaPublicKey::from(&private);
        let private_pem = private
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("pkcs1 pem")
            .to_string();
        // Drop the helper around `EncodeRsaPublicKey` so the JWK uses raw n/e.
        let _ = public.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF);
        let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(public.n().to_bytes_be());
        let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(public.e().to_bytes_be());
        Self {
            kid: kid.to_string(),
            private_pem,
            n_b64,
            e_b64,
        }
    }

    fn jwk(&self) -> serde_json::Value {
        json!({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": self.kid,
            "n": self.n_b64,
            "e": self.e_b64,
        })
    }

    fn mint(&self, claims: &serde_json::Value) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        let key = EncodingKey::from_rsa_pem(self.private_pem.as_bytes()).expect("encoding key");
        encode(&header, claims, &key).expect("sign jwt")
    }
}

#[derive(Clone, Default, Serialize)]
struct JwksBody {
    keys: Vec<serde_json::Value>,
}

#[derive(Clone, Default)]
struct JwksState {
    body: Arc<parking_lot::RwLock<JwksBody>>,
}

async fn jwks_handler(state: axum::extract::State<JwksState>) -> Json<JwksBody> {
    Json(state.body.read().clone())
}

async fn spawn_jwks(initial: Vec<serde_json::Value>) -> (String, JwksState) {
    let state = JwksState {
        body: Arc::new(parking_lot::RwLock::new(JwksBody { keys: initial })),
    };
    let app = Router::new()
        .route(
            "/.well-known/jwks.json",
            get(jwks_handler).with_state(state.clone()),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        format!("http://{}/.well-known/jwks.json", addr),
        state,
    )
}

async fn spawn_router(jwt: Arc<JwtConfig>) -> String {
    let tmp = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&tmp.path().join("smolvm.redb")).unwrap();
    db.init_tables().unwrap();
    let state = Arc::new(ApiState::with_db(db));
    let router = create_router(state, vec![], Some(jwt));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
        // Hold the tempdir for the lifetime of the spawned server.
        drop(tmp);
    });
    format!("http://{}", addr)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn valid_claims() -> serde_json::Value {
    json!({
        "iss": "https://issuer.example",
        "aud": "smolvm",
        "sub": "user-1",
        "exp": now_secs() + 300,
        "iat": now_secs(),
    })
}

#[tokio::test]
async fn health_is_public() {
    let key = TestKey::generate("k1");
    let (jwks_url, _state) = spawn_jwks(vec![key.jwk()]).await;
    let cfg = JwtConfig::new(
        &jwks_url,
        Some("https://issuer.example".into()),
        vec!["smolvm".into()],
        Duration::from_secs(600),
    )
    .unwrap();
    let base = spawn_router(cfg).await;

    let res = reqwest::get(format!("{}/health", base)).await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn missing_token_returns_401_with_challenge() {
    let key = TestKey::generate("k1");
    let (jwks_url, _state) = spawn_jwks(vec![key.jwk()]).await;
    let cfg = JwtConfig::new(
        &jwks_url,
        Some("https://issuer.example".into()),
        vec!["smolvm".into()],
        Duration::from_secs(600),
    )
    .unwrap();
    let base = spawn_router(cfg).await;

    let res = reqwest::get(format!("{}/api/v1/machines", base))
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    let challenge = res
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .expect("missing WWW-Authenticate")
        .to_str()
        .unwrap()
        .to_string();
    assert!(challenge.starts_with("Bearer"), "got: {}", challenge);
}

#[tokio::test]
async fn valid_token_is_accepted() {
    let key = TestKey::generate("k1");
    let (jwks_url, _state) = spawn_jwks(vec![key.jwk()]).await;
    let cfg = JwtConfig::new(
        &jwks_url,
        Some("https://issuer.example".into()),
        vec!["smolvm".into()],
        Duration::from_secs(600),
    )
    .unwrap();
    let base = spawn_router(cfg).await;

    let token = key.mint(&valid_claims());
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/api/v1/machines", base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let key = TestKey::generate("k1");
    let (jwks_url, _state) = spawn_jwks(vec![key.jwk()]).await;
    let cfg = JwtConfig::new(
        &jwks_url,
        Some("https://issuer.example".into()),
        vec!["smolvm".into()],
        Duration::from_secs(600),
    )
    .unwrap();
    let base = spawn_router(cfg).await;

    let mut claims = valid_claims();
    // Use an expiry well outside the default 60s leeway.
    claims["exp"] = json!(now_secs() - 3600);
    claims["iat"] = json!(now_secs() - 7200);
    let token = key.mint(&claims);
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/api/v1/machines", base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_issuer_is_rejected() {
    let key = TestKey::generate("k1");
    let (jwks_url, _state) = spawn_jwks(vec![key.jwk()]).await;
    let cfg = JwtConfig::new(
        &jwks_url,
        Some("https://issuer.example".into()),
        vec!["smolvm".into()],
        Duration::from_secs(600),
    )
    .unwrap();
    let base = spawn_router(cfg).await;

    let mut claims = valid_claims();
    claims["iss"] = json!("https://attacker.example");
    let token = key.mint(&claims);
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/api/v1/machines", base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_kid_triggers_jwks_refresh_and_succeeds() {
    let key1 = TestKey::generate("k1");
    let key2 = TestKey::generate("k2");
    let (jwks_url, jwks_state) = spawn_jwks(vec![key1.jwk()]).await;
    // Long TTL — refresh must be triggered by the unknown `kid`, not by expiry.
    let cfg = JwtConfig::new(
        &jwks_url,
        Some("https://issuer.example".into()),
        vec!["smolvm".into()],
        Duration::from_secs(3600),
    )
    .unwrap();
    let base = spawn_router(cfg).await;

    // Warm the cache with k1.
    let token1 = key1.mint(&valid_claims());
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/api/v1/machines", base))
        .bearer_auth(&token1)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // Rotate: JWKS now serves k2 instead of k1.
    {
        let mut body = jwks_state.body.write();
        body.keys = vec![key2.jwk()];
    }

    let token2 = key2.mint(&valid_claims());
    let res = client
        .get(format!("{}/api/v1/machines", base))
        .bearer_auth(&token2)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}
