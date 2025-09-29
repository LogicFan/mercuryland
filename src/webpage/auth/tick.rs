use super::{SessionResponse, issue_token, verify};
use crate::error::ServerError;
use actix_web::{HttpResponse, Responder, post, web};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct Request {
    token: String,
}

#[post("/api/auth/tick")]
pub async fn handler(request: web::Json<Request>) -> Result<impl Responder, ServerError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    if let Some(mut claims) = verify(&request.token, now) {
        claims.iat = now;
        claims.exp = now + 3600;
        let token = issue_token(&claims)?;
        Ok(HttpResponse::Ok().json(SessionResponse::from_claims(token, &claims)))
    } else {
        Ok(HttpResponse::Forbidden().finish())
    }
}
