//! JWT bearer-token validation middleware backed by JWKS discovery.
//!
//! Enabled when `smolvm serve start` is launched with `--jwt-jwks-url`. The
//! middleware fetches the JWKS document, caches the parsed `DecodingKey`s by
//! `kid`, and validates `Authorization: Bearer <token>` on every protected
//! request. On success the verified claims are inserted into the request
//! extensions as [`Claims`] so handlers can read them.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use parking_lot::RwLock;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::error::ApiError;

/// Verified JWT claims attached to a request via extensions.
#[derive(Debug, Clone)]
pub struct Claims(pub serde_json::Value);

/// Runtime configuration for JWT validation.
pub struct JwtConfig {
    jwks_url: url::Url,
    issuer: Option<String>,
    audiences: Vec<String>,
    cache_ttl: Duration,
    http: reqwest::Client,
    cache: RwLock<JwksCache>,
}

#[derive(Default)]
struct JwksCache {
    keys: HashMap<String, CachedKey>,
    fetched_at: Option<Instant>,
}

struct CachedKey {
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    #[serde(rename = "alg")]
    algorithm: Option<String>,
    // RSA
    n: Option<String>,
    e: Option<String>,
    // EC
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

impl JwtConfig {
    /// Construct a new config from CLI-supplied values. Validates that
    /// `jwks_url` is parseable and builds an HTTP client up-front.
    pub fn new(
        jwks_url: &str,
        issuer: Option<String>,
        audiences: Vec<String>,
        cache_ttl: Duration,
    ) -> Result<Arc<Self>, String> {
        let jwks_url = url::Url::parse(jwks_url)
            .map_err(|e| format!("invalid --jwt-jwks-url: {}", e))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to build HTTP client: {}", e))?;
        Ok(Arc::new(Self {
            jwks_url,
            issuer,
            audiences,
            cache_ttl,
            http,
            cache: RwLock::new(JwksCache::default()),
        }))
    }

    /// Return the configured JWKS URL (used for diagnostic logging).
    pub fn jwks_url(&self) -> &url::Url {
        &self.jwks_url
    }

    /// Look up a decoding key by `kid`. Refreshes the cache if it's stale or
    /// the key is missing.
    async fn key_for(&self, kid: &str) -> Result<(DecodingKey, Algorithm), ApiError> {
        if let Some((key, alg)) = self.lookup_fresh(kid) {
            return Ok((key, alg));
        }
        self.refresh().await?;
        self.lookup_any(kid).ok_or_else(|| {
            ApiError::Unauthorized(format!("signing key not found for kid {}", kid))
        })
    }

    fn lookup_fresh(&self, kid: &str) -> Option<(DecodingKey, Algorithm)> {
        let cache = self.cache.read();
        let fetched_at = cache.fetched_at?;
        if fetched_at.elapsed() > self.cache_ttl {
            return None;
        }
        cache
            .keys
            .get(kid)
            .map(|k| (k.decoding_key.clone(), k.algorithm))
    }

    fn lookup_any(&self, kid: &str) -> Option<(DecodingKey, Algorithm)> {
        let cache = self.cache.read();
        cache
            .keys
            .get(kid)
            .map(|k| (k.decoding_key.clone(), k.algorithm))
    }

    async fn refresh(&self) -> Result<(), ApiError> {
        let body: JwksDocument = self
            .http
            .get(self.jwks_url.clone())
            .send()
            .await
            .map_err(|e| ApiError::Unauthorized(format!("failed to fetch JWKS: {}", e)))?
            .error_for_status()
            .map_err(|e| ApiError::Unauthorized(format!("JWKS endpoint returned error: {}", e)))?
            .json()
            .await
            .map_err(|e| ApiError::Unauthorized(format!("invalid JWKS body: {}", e)))?;

        let mut keys = HashMap::new();
        for jwk in body.keys {
            let kid = match &jwk.kid {
                Some(k) => k.clone(),
                None => continue,
            };
            match build_key(&jwk) {
                Ok(entry) => {
                    keys.insert(kid, entry);
                }
                Err(e) => {
                    tracing::warn!(kid = %kid, error = %e, "skipping unsupported JWK");
                }
            }
        }

        let mut cache = self.cache.write();
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }
}

fn build_key(jwk: &Jwk) -> Result<CachedKey, String> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk.n.as_deref().ok_or("RSA JWK missing 'n'")?;
            let e = jwk.e.as_deref().ok_or("RSA JWK missing 'e'")?;
            let key = DecodingKey::from_rsa_components(n, e)
                .map_err(|err| format!("invalid RSA components: {}", err))?;
            let alg = parse_algorithm(jwk.algorithm.as_deref()).unwrap_or(Algorithm::RS256);
            Ok(CachedKey {
                decoding_key: key,
                algorithm: alg,
            })
        }
        "EC" => {
            let x = jwk.x.as_deref().ok_or("EC JWK missing 'x'")?;
            let y = jwk.y.as_deref().ok_or("EC JWK missing 'y'")?;
            let key = DecodingKey::from_ec_components(x, y)
                .map_err(|err| format!("invalid EC components: {}", err))?;
            let alg = match jwk.crv.as_deref() {
                Some("P-256") => Algorithm::ES256,
                Some("P-384") => Algorithm::ES384,
                Some(other) => return Err(format!("unsupported EC curve: {}", other)),
                None => parse_algorithm(jwk.algorithm.as_deref()).unwrap_or(Algorithm::ES256),
            };
            Ok(CachedKey {
                decoding_key: key,
                algorithm: alg,
            })
        }
        other => Err(format!("unsupported kty: {}", other)),
    }
}

fn parse_algorithm(alg: Option<&str>) -> Option<Algorithm> {
    match alg? {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        _ => None,
    }
}

fn extract_bearer_token<B>(req: &axum::http::Request<B>) -> Result<&str, ApiError> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".into()))?;
    let value = header
        .to_str()
        .map_err(|_| ApiError::Unauthorized("Authorization header is not valid ASCII".into()))?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(|| ApiError::Unauthorized("expected 'Bearer <token>'".into()))?;
    let token = token.trim();
    if token.is_empty() {
        return Err(ApiError::Unauthorized("empty bearer token".into()));
    }
    Ok(token)
}

/// Axum middleware that requires every request to carry a JWT signed by a key
/// served by the configured JWKS endpoint.
pub async fn jwt_middleware(
    State(cfg): State<Arc<JwtConfig>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = extract_bearer_token(&req)?.to_string();

    let header = decode_header(&token)
        .map_err(|e| ApiError::Unauthorized(format!("malformed token header: {}", e)))?;
    let kid = header
        .kid
        .ok_or_else(|| ApiError::Unauthorized("token header missing 'kid'".into()))?;

    let (key, key_alg) = cfg.key_for(&kid).await?;
    let alg = if header.alg == Algorithm::HS256 {
        // HS* would mean a symmetric secret was published as a public key — refuse.
        return Err(ApiError::Unauthorized(
            "symmetric algorithms are not accepted".into(),
        ));
    } else {
        header.alg
    };
    if alg != key_alg {
        return Err(ApiError::Unauthorized(format!(
            "token alg {:?} does not match key alg {:?}",
            alg, key_alg
        )));
    }

    let mut validation = Validation::new(alg);
    if let Some(iss) = &cfg.issuer {
        validation.set_issuer(&[iss.as_str()]);
    }
    if !cfg.audiences.is_empty() {
        validation.set_audience(&cfg.audiences);
    } else {
        validation.validate_aud = false;
    }

    let data = decode::<serde_json::Value>(&token, &key, &validation)
        .map_err(|e| ApiError::Unauthorized(format!("invalid token: {}", e)))?;

    req.extensions_mut().insert(Claims(data.claims));
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Request};

    fn req_with_auth(value: Option<&str>) -> Request<()> {
        let mut req = Request::builder().uri("/").body(()).unwrap();
        if let Some(v) = value {
            req.headers_mut().insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(v).unwrap(),
            );
        }
        req
    }

    #[test]
    fn missing_header_is_unauthorized() {
        let req = req_with_auth(None);
        let err = extract_bearer_token(&req).unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }

    #[test]
    fn wrong_scheme_is_unauthorized() {
        let req = req_with_auth(Some("Basic abcd"));
        assert!(matches!(
            extract_bearer_token(&req).unwrap_err(),
            ApiError::Unauthorized(_)
        ));
    }

    #[test]
    fn lowercase_bearer_is_accepted() {
        let req = req_with_auth(Some("bearer abc.def.ghi"));
        assert_eq!(extract_bearer_token(&req).unwrap(), "abc.def.ghi");
    }

    #[test]
    fn empty_token_is_unauthorized() {
        let req = req_with_auth(Some("Bearer    "));
        assert!(matches!(
            extract_bearer_token(&req).unwrap_err(),
            ApiError::Unauthorized(_)
        ));
    }

    #[test]
    fn algorithm_parsing_supports_common_set() {
        assert_eq!(parse_algorithm(Some("RS256")), Some(Algorithm::RS256));
        assert_eq!(parse_algorithm(Some("ES384")), Some(Algorithm::ES384));
        assert_eq!(parse_algorithm(Some("PS512")), Some(Algorithm::PS512));
        assert_eq!(parse_algorithm(Some("HS256")), None);
    }
}
