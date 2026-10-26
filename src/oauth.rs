//! OAuth2 (authorization code + PKCE) for Gmail and Outlook / Microsoft 365
//! over IMAP and SMTP with SASL XOAUTH2.
//!
//! The app opens the browser (ASWebAuthenticationSession on iOS) and hands the
//! redirect URL back; everything else happens here. The credential store holds
//! one secret per account, so an OAuth account's secret is the JSON of
//! `OAuthSecret`: access token, refresh token, expiry and what is needed to
//! refresh them. Client ids are public identifiers supplied by the app's
//! configuration; no client secret is involved.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

/// Refresh this long before the access token expires.
const EXPIRY_MARGIN_SECS: i64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum OAuthProvider {
	Microsoft,
}

impl OAuthProvider {
	fn authorize_url(self) -> &'static str {
		match self {
			Self::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		}
	}

	fn token_url(self) -> &'static str {
		match self {
			Self::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		}
	}

	fn scope(self) -> &'static str {
		match self {
			Self::Microsoft => "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access",
		}
	}

	fn name(self) -> &'static str {
		match self {
			Self::Microsoft => "Microsoft",
		}
	}
}

/// The app's registration with a provider. Both values are public.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct OAuthClient {
	pub provider: OAuthProvider,
	pub client_id: String,
	/// Must match the registration, e.g. `msauth.<bundle id>://auth`.
	pub redirect_uri: String,
}

/// What to open in the browser, and what to keep until it comes back.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OAuthAuthorization {
	pub url: String,
	pub state: String,
	pub verifier: String,
}

/// The stored secret of an OAuth account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthSecret {
	pub provider: OAuthProvider,
	pub client_id: String,
	pub access_token: String,
	pub refresh_token: String,
	/// Unix seconds.
	pub expires_at: i64,
	/// Where to refresh; kept so it is not re-derived from a newer app version.
	pub token_url: String,
}

impl OAuthSecret {
	pub fn parse(raw: &str) -> Result<Self> {
		serde_json::from_str(raw).map_err(|_| CoreError::Auth { message: "Sign in again to continue.".into() })
	}

	pub fn is_fresh(&self, now: i64) -> bool {
		self.expires_at - EXPIRY_MARGIN_SECS > now
	}
}

fn now() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn random_token(bytes: usize) -> String {
	let mut raw = Vec::with_capacity(bytes + 16);
	while raw.len() < bytes {
		raw.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
	}
	URL_SAFE_NO_PAD.encode(&raw[..bytes])
}

pub fn code_challenge(verifier: &str) -> String {
	URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn authorization(client: &OAuthClient, email: &str) -> Result<OAuthAuthorization> {
	if client.client_id.trim().is_empty() || client.redirect_uri.trim().is_empty() {
		return Err(CoreError::invalid(format!("Sign-in with {} isn't set up in this build.", client.provider.name())));
	}
	let verifier = random_token(48);
	let state = random_token(16);
	let mut url = url::Url::parse(client.provider.authorize_url()).expect("constant URL");
	{
		let mut query = url.query_pairs_mut();
		query
			.append_pair("client_id", client.client_id.trim())
			.append_pair("redirect_uri", client.redirect_uri.trim())
			.append_pair("response_type", "code")
			.append_pair("scope", client.provider.scope())
			.append_pair("state", &state)
			.append_pair("code_challenge", &code_challenge(&verifier))
			.append_pair("code_challenge_method", "S256");
		if !email.trim().is_empty() {
			query.append_pair("login_hint", email.trim());
		}
		match client.provider {
			OAuthProvider::Microsoft => query.append_pair("prompt", "select_account"),
		};
	}
	Ok(OAuthAuthorization { url: url.into(), state, verifier })
}

/// The authorization code in the redirect URL, after checking `state` and for an error.
pub fn code_from_redirect(callback: &str, expected_state: &str) -> Result<String> {
	let url = url::Url::parse(callback).map_err(|_| CoreError::invalid("The sign-in response wasn't understood."))?;
	let mut code = None;
	let mut state = None;
	let mut error = None;
	let mut description = None;
	for (key, value) in url.query_pairs() {
		match key.as_ref() {
			"code" => code = Some(value.into_owned()),
			"state" => state = Some(value.into_owned()),
			"error" => error = Some(value.into_owned()),
			"error_description" => description = Some(value.into_owned()),
			_ => {}
		}
	}
	if let Some(error) = error {
		let detail = description.unwrap_or(error);
		return Err(CoreError::Auth { message: format!("Sign-in was refused: {detail}") });
	}
	if state.as_deref() != Some(expected_state) {
		return Err(CoreError::Auth { message: "The sign-in response didn't match the request. Try again.".into() });
	}
	code.filter(|c| !c.is_empty()).ok_or_else(|| CoreError::Auth { message: "The sign-in response had no authorization code.".into() })
}

#[derive(Deserialize)]
struct TokenResponse {
	access_token: String,
	refresh_token: Option<String>,
	expires_in: Option<i64>,
}

#[derive(Deserialize)]
struct TokenError {
	error: Option<String>,
	error_description: Option<String>,
}

async fn token_request(http: &reqwest::Client, url: &str, form: &[(&str, &str)]) -> Result<TokenResponse> {
	let response = http.post(url).form(form).send().await?;
	let status = response.status();
	let body = response.text().await?;
	if status.is_success() {
		return Ok(serde_json::from_str(&body)?);
	}
	let detail: Option<TokenError> = serde_json::from_str(&body).ok();
	let code = detail.as_ref().and_then(|d| d.error.as_deref()).unwrap_or("");
	let text = detail.as_ref().and_then(|d| d.error_description.clone()).unwrap_or_else(|| code.to_string());
	// invalid_grant: revoked, expired or password changed. Only signing in again helps.
	if status.is_client_error() {
		return Err(CoreError::Auth { message: format!("Sign in again to continue. ({})", text.lines().next().unwrap_or("")) });
	}
	Err(CoreError::server(format!("The sign-in service failed ({status}).")))
}

/// Trades the authorization code for tokens.
pub async fn exchange_code(http: &reqwest::Client, client: &OAuthClient, code: &str, verifier: &str) -> Result<OAuthSecret> {
	let token_url = client.provider.token_url();
	let response = token_request(
		http,
		token_url,
		&[
			("grant_type", "authorization_code"),
			("code", code),
			("client_id", client.client_id.trim()),
			("redirect_uri", client.redirect_uri.trim()),
			("code_verifier", verifier),
		],
	)
	.await?;
	let refresh_token = response
		.refresh_token
		.filter(|t| !t.is_empty())
		.ok_or_else(|| CoreError::Auth { message: "The provider didn't allow ongoing access. Try signing in again.".into() })?;
	Ok(OAuthSecret {
		provider: client.provider,
		client_id: client.client_id.trim().to_string(),
		access_token: response.access_token,
		refresh_token,
		expires_at: now() + response.expires_in.unwrap_or(3600),
		token_url: token_url.to_string(),
	})
}

/// A new access token. Providers may rotate the refresh token (Microsoft does);
/// when none is returned the old one stays.
pub async fn refresh(http: &reqwest::Client, secret: &OAuthSecret) -> Result<OAuthSecret> {
	let mut form = vec![
		("grant_type", "refresh_token"),
		("refresh_token", secret.refresh_token.as_str()),
		("client_id", secret.client_id.as_str()),
	];
	if secret.provider == OAuthProvider::Microsoft {
		form.push(("scope", secret.provider.scope()));
	}
	let response = token_request(http, &secret.token_url, &form).await?;
	Ok(OAuthSecret {
		access_token: response.access_token,
		refresh_token: response.refresh_token.filter(|t| !t.is_empty()).unwrap_or_else(|| secret.refresh_token.clone()),
		expires_at: now() + response.expires_in.unwrap_or(3600),
		..secret.clone()
	})
}

/// The SASL XOAUTH2 initial response (before base64).
pub fn xoauth2_response(user: &str, access_token: &str) -> String {
	format!("user={user}\x01auth=Bearer {access_token}\x01\x01")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pkce_challenge_matches_rfc7636() {
		assert_eq!(code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
	}

	#[test]
	fn authorization_url_carries_pkce_and_scope() {
		let client = OAuthClient { provider: OAuthProvider::Microsoft, client_id: "abc-123".into(), redirect_uri: "app.test:/cb".into() };
		let auth = authorization(&client, "me@outlook.com").unwrap();
		let url = url::Url::parse(&auth.url).unwrap();
		let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
		assert_eq!(query["client_id"], "abc-123");
		assert_eq!(query["code_challenge"], code_challenge(&auth.verifier));
		assert_eq!(query["code_challenge_method"], "S256");
		assert_eq!(query["state"], auth.state);
		assert_eq!(query["login_hint"], "me@outlook.com");
		assert!(query["scope"].contains("IMAP.AccessAsUser.All"));
		assert!(auth.verifier.len() >= 43);
	}

	#[test]
	fn missing_client_id_is_refused() {
		let client = OAuthClient { provider: OAuthProvider::Microsoft, client_id: " ".into(), redirect_uri: "x:/".into() };
		assert!(matches!(authorization(&client, ""), Err(CoreError::InvalidInput { .. })));
	}

	#[test]
	fn redirect_checks_state_and_errors() {
		assert_eq!(code_from_redirect("app:/cb?code=C1&state=S", "S").unwrap(), "C1");
		assert!(matches!(code_from_redirect("app:/cb?code=C1&state=OTHER", "S"), Err(CoreError::Auth { .. })));
		assert!(matches!(code_from_redirect("app:/cb?code=C1", "S"), Err(CoreError::Auth { .. })));
		let denied = code_from_redirect("app:/cb?error=access_denied&state=S", "S").unwrap_err();
		assert!(denied.to_string().contains("access_denied"));
	}

	#[test]
	fn expiry_margin() {
		let secret = OAuthSecret {
			provider: OAuthProvider::Microsoft,
			client_id: "c".into(),
			access_token: "a".into(),
			refresh_token: "r".into(),
			expires_at: 1000,
			token_url: String::new(),
		};
		assert!(secret.is_fresh(800));
		assert!(!secret.is_fresh(900));
		assert!(!secret.is_fresh(2000));
	}

	#[test]
	fn xoauth2_layout() {
		assert_eq!(xoauth2_response("u@x.com", "tok"), "user=u@x.com\x01auth=Bearer tok\x01\x01");
	}
}

#[cfg(test)]
mod network_tests {
	use super::*;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpListener;

	/// Serves one canned HTTP response and returns the request it received.
	async fn token_server(status: &'static str, body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let url = format!("http://{}/token", listener.local_addr().unwrap());
		let handle = tokio::spawn(async move {
			let (mut socket, _) = listener.accept().await.unwrap();
			let mut buffer = vec![0u8; 8192];
			let mut request = String::new();
			// Read until the form body (Content-Length bytes after the blank line) has arrived.
			loop {
				let n = socket.read(&mut buffer).await.unwrap();
				request.push_str(&String::from_utf8_lossy(&buffer[..n]));
				if n == 0 {
					break;
				}
				if let Some((head, rest)) = request.split_once("\r\n\r\n") {
					let length = head
						.lines()
						.find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()))
						.unwrap_or(0);
					if rest.len() >= length {
						break;
					}
				}
			}
			let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
			socket.write_all(response.as_bytes()).await.unwrap();
			request
		});
		(url, handle)
	}

	fn secret(provider: OAuthProvider, token_url: String) -> OAuthSecret {
		OAuthSecret { provider, client_id: "cid".into(), access_token: "old".into(), refresh_token: "r1".into(), expires_at: 0, token_url }
	}

	#[tokio::test]
	async fn refresh_keeps_the_refresh_token_when_none_is_returned() {
		let (url, server) = token_server("200 OK", r#"{"access_token":"new","expires_in":3599}"#).await;
		let renewed = refresh(&reqwest::Client::new(), &secret(OAuthProvider::Microsoft, url)).await.unwrap();
		assert_eq!(renewed.access_token, "new");
		assert_eq!(renewed.refresh_token, "r1");
		assert!(renewed.is_fresh(now()));
		let request = server.await.unwrap();
		assert!(request.contains("grant_type=refresh_token") && request.contains("refresh_token=r1") && request.contains("client_id=cid"));
	}

	#[tokio::test]
	async fn refresh_stores_a_rotated_refresh_token() {
		let (url, server) = token_server("200 OK", r#"{"access_token":"new","refresh_token":"r2","expires_in":3599}"#).await;
		let renewed = refresh(&reqwest::Client::new(), &secret(OAuthProvider::Microsoft, url)).await.unwrap();
		assert_eq!(renewed.refresh_token, "r2");
		assert!(server.await.unwrap().contains("scope="));
	}

	#[tokio::test]
	async fn revoked_grant_asks_to_sign_in_again() {
		let (url, _server) = token_server("400 Bad Request", r#"{"error":"invalid_grant","error_description":"Token has been revoked."}"#).await;
		let error = refresh(&reqwest::Client::new(), &secret(OAuthProvider::Microsoft, url)).await.unwrap_err();
		assert!(matches!(error, CoreError::Auth { .. }), "{error:?}");
	}
}
