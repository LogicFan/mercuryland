use crate::error::ServerError;
use actix_web::{HttpResponse, Responder, post, web};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    ip: Option<String>,
}

#[post("/api/auth/logout")]
pub async fn handler(request: web::Json<LogoutRequest>) -> Result<impl Responder, ServerError> {
    let identifier = request
        .email
        .as_ref()
        .or(request.username.as_ref())
        .map(|value| value.as_str())
        .unwrap_or("unknown");

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    log::info!(
        "[GoogleLogout] User {identifier} logged out at {timestamp}{}",
        request
            .ip
            .as_ref()
            .map(|ip| format!(" from {ip}"))
            .unwrap_or_default()
    );

    Ok(HttpResponse::Ok().finish())
}
