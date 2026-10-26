//! Mailflare's mobile endpoints beside JMAP: password sign-in that returns a
//! device key (`/api/auth/device`), the key revoking itself on sign-out, and
//! APNs registration (`/api/mobile/push`).

use serde_json::{json, Value};
use url::Url;

use crate::error::{CoreError, Result};
use crate::jmap::{self, Credentials};

pub enum DeviceLogin {
	Key { key: String, session_url: String },
	Mfa { challenge_token: String },
}

/// Origins that may host `/api/auth/device` for an address.
pub fn origins(email: &str, server: Option<&str>) -> Result<Vec<String>> {
	let mut out: Vec<String> = Vec::new();
	for candidate in jmap::session_candidates(email, server)? {
		if let Ok(url) = Url::parse(&candidate) {
			let origin = url.origin().ascii_serialization();
			if !out.contains(&origin) {
				out.push(origin);
			}
		}
	}
	Ok(out)
}

/// The origin hosting an account's API, from its stored JMAP API URL.
pub fn api_origin(api_url: &str) -> Result<String> {
	Url::parse(api_url)
		.map(|url| url.origin().ascii_serialization())
		.map_err(|_| CoreError::invalid("The account's server address is not valid"))
}

fn message(body: &Value, fallback: &str) -> String {
	body["error"].as_str().map(str::to_string).unwrap_or_else(|| fallback.to_string())
}

/// One call to `/api/auth/device`. `Ok(None)` means this origin has no such endpoint.
pub async fn login(http: &reqwest::Client, origin: &str, body: Value) -> Result<Option<DeviceLogin>> {
	let url = format!("{origin}/api/auth/device");
	jmap::require_secure(&Url::parse(&url).map_err(|_| CoreError::invalid("Invalid server address"))?)?;
	// One retry: a dropped first connection should not read as "no such endpoint".
	let response = match http.post(&url).json(&body).send().await {
		Ok(response) => response,
		Err(_) => http.post(&url).json(&body).send().await?,
	};
	let status = response.status();
	if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
		return Ok(None);
	}
	if status.is_server_error() {
		return Err(CoreError::server(format!("The server had a problem signing in ({status}). Try again.")));
	}
	let Ok(value) = response.json::<Value>().await else { return Ok(None) };
	match status.as_u16() {
		200 => {}
		401 => return Err(CoreError::Auth { message: message(&value, "The email or password is incorrect.") }),
		403 => return Err(CoreError::Auth { message: message(&value, "This account is disabled.") }),
		429 => return Err(CoreError::server(message(&value, "Too many attempts. Try again in a minute."))),
		_ => return Err(CoreError::server(message(&value, &format!("Sign-in failed ({status})")))),
	}
	if value["mfaRequired"].as_bool() == Some(true) {
		let token = value["challengeToken"].as_str().ok_or_else(|| CoreError::server("Missing challenge"))?;
		return Ok(Some(DeviceLogin::Mfa { challenge_token: token.to_string() }));
	}
	let key = value["key"].as_str().ok_or_else(|| CoreError::server("The server did not return a device key"))?;
	let session_url = value["sessionUrl"].as_str().map(str::to_string).unwrap_or_else(|| format!("{origin}/jmap/session"));
	Ok(Some(DeviceLogin::Key { key: key.to_string(), session_url }))
}

pub fn password_body(email: &str, password: &str, device_name: &str) -> Value {
	json!({ "email": email, "password": password, "deviceName": device_name })
}

pub fn mfa_body(challenge_token: &str, code: &str, device_name: &str) -> Value {
	json!({ "challengeToken": challenge_token, "code": code, "deviceName": device_name })
}

/// Best effort: the key stops working server-side. Local data is removed regardless.
pub async fn revoke(http: &reqwest::Client, origin: &str, credentials: &Credentials) -> Result<()> {
	let response = http
		.delete(format!("{origin}/api/auth/device"))
		.header(reqwest::header::AUTHORIZATION, credentials.authorization())
		.send()
		.await?;
	if response.status().is_success() {
		Ok(())
	} else {
		Err(CoreError::server(format!("Revoking the device failed ({})", response.status())))
	}
}

/// Registers the device. Returns whether the server can actually send pushes
/// (older servers do not say, and are assumed to).
pub async fn register_push(http: &reqwest::Client, origin: &str, credentials: &Credentials, body: Value) -> Result<bool> {
	let response = http
		.put(format!("{origin}/api/mobile/push"))
		.header(reqwest::header::AUTHORIZATION, credentials.authorization())
		.json(&body)
		.send()
		.await?;
	let status = response.status();
	if status.is_success() {
		let value: Value = response.json().await.unwrap_or_default();
		return Ok(value.get("deliverable").and_then(Value::as_bool).unwrap_or(true));
	}
	if status == reqwest::StatusCode::NOT_FOUND {
		return Err(CoreError::server("This server does not support push notifications yet"));
	}
	let value: Value = response.json().await.unwrap_or_default();
	Err(CoreError::server(message(&value, &format!("Push registration failed ({status})"))))
}

pub async fn unregister_push(http: &reqwest::Client, origin: &str, credentials: &Credentials) -> Result<()> {
	let response = http
		.delete(format!("{origin}/api/mobile/push"))
		.header(reqwest::header::AUTHORIZATION, credentials.authorization())
		.send()
		.await?;
	if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
		Ok(())
	} else {
		Err(CoreError::server(format!("Push unregistration failed ({})", response.status())))
	}
}
