use super::{Claims, SessionResponse, issue_token};
use crate::error::ServerError;
use actix_web::{HttpResponse, Responder, post, web};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use once_cell::sync::Lazy;
use reqwest::header::CACHE_CONTROL;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    io::Write,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static GOOGLE_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);
static GOOGLE_CERT_CACHE: Lazy<Mutex<GoogleCertCache>> =
    Lazy::new(|| Mutex::new(GoogleCertCache::default()));

const GOOGLE_SSO_CLIENT_ID: &str = option_env!("GOOGLE_SSO_CLIENT_ID")
    .expect("GOOGLE_SSO_CLIENT_ID environment variable must be set at compile time");

const GOOGLE_CERTS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_CERTS_FALLBACK_TTL: Duration = Duration::from_secs(3600);

#[derive(Default)]
struct GoogleCertCache {
    keys: HashMap<String, DecodingKey>,
    expires_at: Option<Instant>,
}

#[derive(Debug, Deserialize)]
struct GoogleJwkSet {
    keys: Vec<GoogleJwk>,
}

#[derive(Debug, Deserialize)]
struct GoogleJwk {
    kid: String,
    n: String,
    e: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    kty: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleLoginRequest {
    credential: String,
    #[serde(default)]
    ip: Option<String>,
}

#[post("/api/auth/google")]
pub async fn handler(
    request: web::Json<GoogleLoginRequest>,
) -> Result<impl Responder, ServerError> {
    let header = decode_header(&request.credential)?;
    let kid = header
        .kid
        .ok_or_else(|| ServerError::Internal("Google credential is missing kid".to_string()))?;

    let decoding_key = get_decoding_key(&kid).await?;
    let mut validation = Validation::new(Algorithm::RS256);
    let audience = [GOOGLE_SSO_CLIENT_ID.to_owned()];
    validation.set_audience(&audience);
    let mut issuers = HashSet::with_capacity(2);
    issuers.insert("https://accounts.google.com".to_string());
    issuers.insert("accounts.google.com".to_string());
    validation.iss = Some(issuers);

    let token_data = decode::<GoogleClaims>(&request.credential, &decoding_key, &validation)?;
    let google_claims = token_data.claims;

    if matches!(google_claims.email_verified, Some(false)) {
        return Err(ServerError::Internal(
            "Google account email is not verified".to_string(),
        ));
    }

    if google_claims.email.is_none() {
        return Err(ServerError::Internal(
            "Google credential is missing email".to_string(),
        ));
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let claims = Claims {
        iat: now,
        exp: now + 3600,
        sub: Some(google_claims.sub.clone()),
        email: google_claims.email.clone(),
        name: google_claims.name.clone(),
    };

    let session_token = issue_token(&claims)?;

    record_login_event(
        claims.email.as_deref(),
        claims.name.as_deref(),
        request.ip.as_deref(),
    )?;

    Ok(HttpResponse::Ok().json(SessionResponse::from_claims(session_token, &claims)))
}

async fn get_decoding_key(kid: &str) -> Result<DecodingKey, ServerError> {
    if let Some(key) = {
        let cache = lock_cache();
        if cache.is_fresh() {
            cache.keys.get(kid).cloned()
        } else {
            None
        }
    } {
        return Ok(key);
    }

    refresh_google_keys().await?;

    let cache = lock_cache();
    cache.keys.get(kid).cloned().ok_or_else(|| {
        ServerError::Internal(format!("Unable to find Google signing key for kid {kid}"))
    })
}

async fn refresh_google_keys() -> Result<(), ServerError> {
    let response = GOOGLE_HTTP_CLIENT.get(GOOGLE_CERTS_URL).send().await?;
    let ttl = cache_max_age(response.headers()).unwrap_or(GOOGLE_CERTS_FALLBACK_TTL);
    let jwk_set: GoogleJwkSet = response.json().await?;

    let mut keys = HashMap::with_capacity(jwk_set.keys.len());
    for jwk in jwk_set.keys.into_iter() {
        if !matches!(jwk.kty.as_deref(), Some("RSA")) {
            continue;
        }
        if !matches!(jwk.alg.as_deref(), Some("RS256")) {
            continue;
        }

        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
        keys.insert(jwk.kid, decoding_key);
    }

    let mut cache = lock_cache();
    cache.keys = keys;
    cache.expires_at = Some(Instant::now() + ttl);
    Ok(())
}

fn cache_max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(|header_value| {
            header_value
                .split(',')
                .find_map(|part| match part.trim().strip_prefix("max-age=") {
                    Some(seconds) => seconds.parse::<u64>().ok(),
                    None => None,
                })
        })
        .map(Duration::from_secs)
}

fn record_login_event(
    email: Option<&str>,
    name: Option<&str>,
    ip: Option<&str>,
) -> Result<(), ServerError> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let mut log_entry = format!(
        "[GoogleLogin] User {} logged in at {}",
        email.unwrap_or("unknown"),
        timestamp
    );

    if let Some(name) = name {
        log_entry.push_str(&format!(" (name: {name})"));
    }
    if let Some(ip) = ip {
        log_entry.push_str(&format!(" from {ip}"));
    }

    let mut log_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("data/login_history.log")?;

    writeln!(log_file, "{log_entry}")?;

    Ok(())
}

fn lock_cache() -> MutexGuard<'static, GoogleCertCache> {
    GOOGLE_CERT_CACHE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

impl GoogleCertCache {
    fn is_fresh(&self) -> bool {
        self.expires_at
            .map(|expires_at| expires_at > Instant::now())
            .unwrap_or(false)
    }
}
