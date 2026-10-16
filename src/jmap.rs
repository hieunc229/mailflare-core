//! Minimal JMAP client (RFC 8620 / 8621): session discovery and batched
//! method calls. Arguments and responses stay `serde_json::Value`; the sync
//! engine picks the properties it needs.

use base64::Engine;
use serde_json::{json, Value};
use url::Url;

use crate::error::{CoreError, Result};

pub const CAPABILITY_CORE: &str = "urn:ietf:params:jmap:core";
pub const CAPABILITY_MAIL: &str = "urn:ietf:params:jmap:mail";
pub const CAPABILITY_SUBMISSION: &str = "urn:ietf:params:jmap:submission";

#[derive(Debug, Clone)]
pub struct Credentials {
	pub username: String,
	pub secret: String,
}

impl Credentials {
	/// HTTP Basic with the app password. Mailflare reads the key from the
	/// password and ignores the username; other servers need both.
	pub fn authorization(&self) -> String {
		let raw = format!("{}:{}", self.username, self.secret);
		format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(raw))
	}
}

#[derive(Debug, Clone)]
pub struct Session {
	pub session_url: String,
	pub api_url: String,
	pub download_url: String,
	pub upload_url: String,
	pub account_id: String,
	pub account_name: String,
}

#[derive(Debug, Clone)]
pub struct Invocation {
	pub name: String,
	pub args: Value,
	pub call_id: String,
}

pub fn is_loopback(url: &Url) -> bool {
	match url.host() {
		Some(url::Host::Domain(domain)) => domain == "localhost" || domain.ends_with(".localhost"),
		Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
		Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
		None => false,
	}
}

/// TLS only. Plain HTTP is accepted for loopback hosts so a local
/// `npm run dev` server can be used from the simulator.
pub fn require_secure(url: &Url) -> Result<()> {
	match url.scheme() {
		"https" => Ok(()),
		"http" if is_loopback(url) => Ok(()),
		_ => Err(CoreError::invalid(format!("{} must use https", url.host_str().unwrap_or("The server")))),
	}
}

/// Session URLs to try, in order, for an address and an optional server.
pub fn session_candidates(email: &str, server: Option<&str>) -> Result<Vec<String>> {
	let server = server.map(str::trim).filter(|s| !s.is_empty());
	if let Some(server) = server {
		let with_scheme = if server.contains("://") { server.to_string() } else { format!("https://{server}") };
		let mut url = Url::parse(&with_scheme).map_err(|_| CoreError::invalid("The server address is not valid"))?;
		require_secure(&url)?;
		let path = url.path().trim_end_matches('/').to_string();
		if path.ends_with("/.well-known/jmap") || path.ends_with("/jmap/session") {
			return Ok(vec![url.to_string()]);
		}
		url.set_query(None);
		url.set_fragment(None);
		url.set_path(&format!("{path}/.well-known/jmap"));
		return Ok(vec![url.to_string()]);
	}
	let domain = email
		.rsplit_once('@')
		.map(|(_, domain)| domain.trim().to_ascii_lowercase())
		.filter(|domain| !domain.is_empty() && domain.contains('.'))
		.ok_or_else(|| CoreError::invalid("Enter a full email address"))?;
	Ok(vec![format!("https://{domain}/.well-known/jmap"), format!("https://mail.{domain}/.well-known/jmap")])
}

fn absolute(base: &Url, value: &str) -> Result<String> {
	let url = base.join(value).map_err(|_| CoreError::server("The server returned an invalid URL"))?;
	require_secure(&url)?;
	Ok(url.to_string())
}

pub async fn fetch_session(http: &reqwest::Client, session_url: &str, credentials: &Credentials) -> Result<Session> {
	let response = http
		.get(session_url)
		.header(reqwest::header::AUTHORIZATION, credentials.authorization())
		.header(reqwest::header::ACCEPT, "application/json")
		.send()
		.await?;
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(CoreError::Auth { message: "The email or app password is incorrect.".into() });
	}
	if !status.is_success() {
		return Err(CoreError::Discovery { message: format!("No JMAP server answered at {session_url} ({status})") });
	}
	// Relative URLs in the session resolve against where we ended up after redirects.
	let final_url = response.url().clone();
	let body: Value = response
		.json()
		.await
		.map_err(|_| CoreError::Discovery { message: format!("{session_url} is not a JMAP server") })?;
	let account_id = body["primaryAccounts"][CAPABILITY_MAIL]
		.as_str()
		.ok_or_else(|| CoreError::Discovery { message: "The server does not offer JMAP Mail".into() })?
		.to_string();
	let api_url = body["apiUrl"].as_str().ok_or_else(|| CoreError::server("Session has no apiUrl"))?;
	let download_url = body["downloadUrl"].as_str().unwrap_or_default();
	let upload_url = body["uploadUrl"].as_str().unwrap_or_default();
	Ok(Session {
		session_url: final_url.to_string(),
		api_url: absolute(&final_url, api_url)?,
		download_url: if download_url.is_empty() { String::new() } else { absolute(&final_url, download_url)? },
		upload_url: if upload_url.is_empty() { String::new() } else { absolute(&final_url, upload_url)? },
		account_name: body["accounts"][&account_id]["name"].as_str().unwrap_or_default().to_string(),
		account_id,
	})
}

/// Sends one JMAP request. Per-call `error` responses are left in the result
/// for the caller; transport and request-level failures are errors.
pub async fn request(
	http: &reqwest::Client,
	api_url: &str,
	credentials: &Credentials,
	calls: Vec<(String, Value, String)>,
) -> Result<Vec<Invocation>> {
	let body = json!({
		"using": [CAPABILITY_CORE, CAPABILITY_MAIL, CAPABILITY_SUBMISSION],
		"methodCalls": calls.into_iter().map(|(name, args, id)| json!([name, args, id])).collect::<Vec<_>>(),
	});
	let response = http
		.post(api_url)
		.header(reqwest::header::AUTHORIZATION, credentials.authorization())
		.json(&body)
		.send()
		.await?;
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(CoreError::Auth { message: "The server no longer accepts this app password.".into() });
	}
	let value: Value = response.json().await.map_err(|_| CoreError::server(format!("JMAP request failed ({status})")))?;
	if !status.is_success() {
		let detail = value["detail"].as_str().or(value["type"].as_str()).unwrap_or("request failed");
		return Err(CoreError::server(format!("JMAP {detail} ({status})")));
	}
	let responses = value["methodResponses"].as_array().ok_or_else(|| CoreError::server("Response has no methodResponses"))?;
	Ok(responses
		.iter()
		.filter_map(|item| {
			let parts = item.as_array()?;
			Some(Invocation {
				name: parts.first()?.as_str()?.to_string(),
				args: parts.get(1)?.clone(),
				call_id: parts.get(2)?.as_str()?.to_string(),
			})
		})
		.collect())
}

/// Expands an RFC 6570 level-1 template such as Mailflare's
/// `downloadUrl`: `{name}` values are percent-encoded.
pub fn expand_template(template: &str, values: &[(&str, &str)]) -> String {
	let mut out = template.to_string();
	for (key, value) in values {
		let encoded: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>().replace('+', "%20");
		// URL parsing percent-encodes the braces of a stored template.
		for pattern in [format!("{{{key}}}"), format!("%7B{key}%7D"), format!("%7b{key}%7d")] {
			out = out.replace(&pattern, &encoded);
		}
	}
	out
}

pub async fn upload(http: &reqwest::Client, upload_url: &str, credentials: &Credentials, bytes: Vec<u8>, mime_type: &str, name: &str) -> Result<String> {
	let encoded: String = url::form_urlencoded::byte_serialize(name.as_bytes()).collect::<String>().replace('+', "%20");
	let response = http
		.post(upload_url)
		.header(reqwest::header::AUTHORIZATION, credentials.authorization())
		.header(reqwest::header::CONTENT_TYPE, mime_type)
		.header(reqwest::header::CONTENT_DISPOSITION, format!("attachment; filename*=UTF-8''{encoded}"))
		.body(bytes)
		.send()
		.await?;
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(CoreError::Auth { message: "The server no longer accepts this app password.".into() });
	}
	if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
		return Err(CoreError::invalid(format!("{name} is too large to send")));
	}
	let value: Value = response.json().await.map_err(|_| CoreError::server(format!("Upload failed ({status})")))?;
	value["blobId"].as_str().map(str::to_string).ok_or_else(|| CoreError::server(format!("Upload failed ({status})")))
}

pub async fn download(http: &reqwest::Client, url: &str, credentials: &Credentials) -> Result<Vec<u8>> {
	let response = http.get(url).header(reqwest::header::AUTHORIZATION, credentials.authorization()).send().await?;
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(CoreError::Auth { message: "The server no longer accepts this app password.".into() });
	}
	if status == reqwest::StatusCode::NOT_FOUND {
		return Err(CoreError::not_found("This attachment no longer exists"));
	}
	if !status.is_success() {
		return Err(CoreError::server(format!("Download failed ({status})")));
	}
	Ok(response.bytes().await?.to_vec())
}

/// The response to `call_id` named `name`, or the method-level error.
pub fn response<'a>(responses: &'a [Invocation], call_id: &str, name: &str) -> Result<&'a Value> {
	let invocation = responses
		.iter()
		.find(|item| item.call_id == call_id)
		.ok_or_else(|| CoreError::server(format!("No response for {name}")))?;
	if invocation.name == "error" {
		let kind = invocation.args["type"].as_str().unwrap_or("serverFail");
		let description = invocation.args["description"].as_str().unwrap_or_default();
		return Err(CoreError::server(format!("{name}: {kind} {description}").trim().to_string()));
	}
	if invocation.name != name {
		return Err(CoreError::server(format!("Expected {name}, got {}", invocation.name)));
	}
	Ok(&invocation.args)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn candidates_from_email_domain() {
		let list = session_candidates("me@Example.com", None).unwrap();
		assert_eq!(list[0], "https://example.com/.well-known/jmap");
	}

	#[test]
	fn candidates_from_server() {
		assert_eq!(session_candidates("me@x.com", Some("mail.x.com")).unwrap(), vec!["https://mail.x.com/.well-known/jmap"]);
		assert_eq!(
			session_candidates("me@x.com", Some("http://localhost:3000/")).unwrap(),
			vec!["http://localhost:3000/.well-known/jmap"]
		);
		assert_eq!(
			session_candidates("me@x.com", Some("https://x.com/jmap/session")).unwrap(),
			vec!["https://x.com/jmap/session"]
		);
	}

	#[test]
	fn expands_encoded_templates() {
		let url = Url::parse("https://x.com/jmap/download/{accountId}/{blobId}/{name}?type={type}").unwrap().to_string();
		let out = expand_template(&url, &[("accountId", "u1"), ("blobId", "att~1"), ("name", "a b.pdf"), ("type", "application/pdf")]);
		assert_eq!(out, "https://x.com/jmap/download/u1/att%7E1/a%20b.pdf?type=application%2Fpdf");
	}

	#[test]
	fn plain_http_only_for_loopback() {
		assert!(session_candidates("me@x.com", Some("http://x.com")).is_err());
		assert!(session_candidates("me@x.com", Some("http://127.0.0.1:3000")).is_ok());
	}
}
