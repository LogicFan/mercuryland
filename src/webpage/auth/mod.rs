pub mod google;
pub mod logout;
pub mod tick;

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header as JwtHeader, Validation, decode, encode,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static SESSION_KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut rng = rand::thread_rng();
    let mut bytes = [0_u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
});

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Claims {
    pub(super) iat: u64,
    pub(super) exp: u64,
    #[serde(default)]
    pub(super) sub: Option<String>,
    #[serde(default)]
    pub(super) email: Option<String>,
    #[serde(default)]
    pub(super) name: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct SessionResponse {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl SessionResponse {
    pub(crate) fn from_claims(token: String, claims: &Claims) -> Self {
        Self {
            token,
            email: claims.email.clone(),
            name: claims.name.clone(),
        }
    }
}

pub(crate) fn issue_token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    let header = JwtHeader::new(Algorithm::HS256);
    encode(&header, claims, &EncodingKey::from_secret(session_secret()))
}

pub(crate) fn verify(token: &str, now: u64) -> Option<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(session_secret()),
        &validation,
    )
    .ok()?;
    let claims = data.claims;

    if claims.iat < now && claims.exp > now {
        Some(claims)
    } else {
        None
    }
}

fn session_secret() -> &'static [u8] {
    (&*SESSION_KEY).as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_valid_window() {
        let claims = Claims {
            iat: 100,
            exp: 200,
            sub: None,
            email: None,
            name: None,
        };
        let token = issue_token(&claims).unwrap();

        assert!(verify(&token, 150).is_some());
        assert!(verify(&token, 90).is_none());
        assert!(verify(&token, 250).is_none());
    }

    #[test]
    fn verify_rejects_invalid_token() {
        assert!(verify("invalid", 100).is_none());
    }
}
