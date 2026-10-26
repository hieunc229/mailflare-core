//! IMAP accounts: sign-in with an app password, sync into the same store the
//! JMAP backend fills, and the queued actions replayed over IMAP. Sending goes
//! through `smtp`.
//!
//! Every operation opens its own connection: mobile networks drop idle sockets,
//! and a fresh login is cheap next to the work done on it.

pub mod actions;
pub mod sync;

use std::sync::Arc;
use std::time::Duration;

use async_imap::{Client, Session};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::error::{CoreError, Result};
use crate::types::{TransportSecurity, MailServerConfig, MailEndpoint};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

pub trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug> Stream for T {}

/// How a connection proves who it is.
#[derive(Debug, Clone)]
pub enum Auth {
	/// An app password or account password (LOGIN / PLAIN).
	Password(String),
	/// An OAuth2 access token (SASL XOAUTH2).
	Bearer(String),
}

/// XOAUTH2 initial response; on a failure the server sends a JSON challenge
/// that is answered with an empty line so it can finish with a tagged NO.
struct XOAuth2 {
	response: String,
	sent: bool,
}

impl async_imap::Authenticator for XOAuth2 {
	type Response = String;
	fn process(&mut self, _challenge: &[u8]) -> String {
		if std::mem::replace(&mut self.sent, true) {
			String::new()
		} else {
			self.response.clone()
		}
	}
}

pub type ImapSession = Session<Box<dyn Stream>>;

/// Runs a network future under the command timeout.
pub async fn with_timeout<T>(future: impl std::future::Future<Output = T>) -> Result<T> {
	tokio::time::timeout(COMMAND_TIMEOUT, future)
		.await
		.map_err(|_| CoreError::Network { message: "The mail server took too long to respond.".into() })
}

impl From<async_imap::error::Error> for CoreError {
	fn from(error: async_imap::error::Error) -> Self {
		use async_imap::error::Error;
		match error {
			Error::Io(e) => CoreError::Network { message: format!("Connection to the mail server failed: {e}") },
			Error::ConnectionLost => CoreError::Network { message: "The mail server closed the connection.".into() },
			Error::No(text) => CoreError::server(format!("The mail server refused the request: {text}")),
			Error::Bad(text) => CoreError::server(format!("The mail server did not understand the request: {text}")),
			other => CoreError::server(other.to_string()),
		}
	}
}

pub fn is_loopback(host: &str) -> bool {
	host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

/// Refuses an unencrypted connection to anything but this device.
pub fn require_encryption(endpoint: &MailEndpoint) -> Result<()> {
	if endpoint.security == TransportSecurity::None && !is_loopback(&endpoint.host) {
		return Err(CoreError::invalid("Use SSL/TLS or STARTTLS: unencrypted connections would expose your password."));
	}
	Ok(())
}

pub fn tls_connector() -> TlsConnector {
	let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
	let config = ClientConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
		.with_safe_default_protocol_versions()
		.expect("ring supports the default TLS versions")
		.with_root_certificates(roots)
		.with_no_client_auth();
	TlsConnector::from(Arc::new(config))
}

pub async fn tcp_connect(endpoint: &MailEndpoint) -> Result<TcpStream> {
	require_encryption(endpoint)?;
	let connect = TcpStream::connect((endpoint.host.as_str(), endpoint.port));
	tokio::time::timeout(CONNECT_TIMEOUT, connect)
		.await
		.map_err(|_| CoreError::Network { message: format!("Couldn't reach {}. Check the server address and your connection.", endpoint.host) })?
		.map_err(|e| CoreError::Network { message: format!("Couldn't connect to {}: {e}", endpoint.host) })
}

pub fn server_name(host: &str) -> Result<ServerName<'static>> {
	ServerName::try_from(host.to_string()).map_err(|_| CoreError::invalid(format!("\"{host}\" is not a valid server name")))
}

/// Connects, secures the channel and logs in.
pub async fn connect(config: &MailServerConfig, auth: &Auth) -> Result<ImapSession> {
	let endpoint = &config.incoming;
	let tcp = tcp_connect(endpoint).await?;
	let mut client = match endpoint.security {
		TransportSecurity::Tls => {
			let tls = tls_connector()
				.connect(server_name(&endpoint.host)?, tcp)
				.await
				.map_err(|e| CoreError::Network { message: format!("Couldn't make a secure connection to {}: {e}", endpoint.host) })?;
			let mut client = Client::new(Box::new(tls) as Box<dyn Stream>);
			with_timeout(client.read_response()).await?.map_err(|e| CoreError::Network { message: e.to_string() })?;
			client
		}
		TransportSecurity::StartTls => {
			let mut plain = Client::new(tcp);
			with_timeout(plain.read_response()).await?.map_err(|e| CoreError::Network { message: e.to_string() })?;
			with_timeout(plain.run_command_and_check_ok("STARTTLS", None)).await??;
			let tls = tls_connector()
				.connect(server_name(&endpoint.host)?, plain.into_inner())
				.await
				.map_err(|e| CoreError::Network { message: format!("Couldn't make a secure connection to {}: {e}", endpoint.host) })?;
			Client::new(Box::new(tls) as Box<dyn Stream>)
		}
		TransportSecurity::None => {
			let mut client = Client::new(Box::new(tcp) as Box<dyn Stream>);
			with_timeout(client.read_response()).await?.map_err(|e| CoreError::Network { message: e.to_string() })?;
			client
		}
	};
	let _ = &mut client;
	let outcome = match auth {
		Auth::Password(secret) => with_timeout(client.login(&config.username, secret)).await?,
		Auth::Bearer(token) => {
			let authenticator = XOAuth2 { response: crate::oauth::xoauth2_response(&config.username, token), sent: false };
			with_timeout(client.authenticate("XOAUTH2", authenticator)).await?
		}
	};
	match outcome {
		Ok(session) => Ok(session),
		Err((async_imap::error::Error::No(text), _)) => Err(CoreError::Auth {
			message: match auth {
				Auth::Password(_) => format!("The mail server rejected the password. Providers like Gmail and iCloud need an app password. ({text})"),
				Auth::Bearer(_) => format!("The mail server rejected the sign-in. Sign in again. ({text})"),
			},
		}),
		Err((error, _)) => Err(error.into()),
	}
}

/// IMAP quoted-string for a mailbox name, with the characters that need escaping.
pub fn quote(name: &str) -> String {
	format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
	use super::*;
	use base64::Engine;
	use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
	use tokio::net::TcpListener;

	/// A one-shot IMAP server that only speaks AUTHENTICATE XOAUTH2. With
	/// `reject` it answers with the JSON error challenge Gmail sends.
	async fn fake_server(reject: bool) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let port = listener.local_addr().unwrap().port();
		let handle = tokio::spawn(async move {
			let (socket, _) = listener.accept().await.unwrap();
			let (read, mut write) = socket.into_split();
			let mut lines = BufReader::new(read).lines();
			let mut seen = Vec::new();
			write.write_all(b"* OK ready\r\n").await.unwrap();
			let command = lines.next_line().await.unwrap().unwrap();
			write.write_all(b"+ \r\n").await.unwrap();
			seen.push(command);
			let initial = lines.next_line().await.unwrap().unwrap();
			seen.push(initial);
			if reject {
				write.write_all(b"+ eyJzdGF0dXMiOiI0MDEifQ==\r\n").await.unwrap();
				seen.push(lines.next_line().await.unwrap().unwrap());
				write.write_all(b"A0001 NO [AUTHENTICATIONFAILED] Invalid credentials\r\n").await.unwrap();
			} else {
				write.write_all(b"A0001 OK Authenticated\r\n").await.unwrap();
			}
			seen
		});
		(port, handle)
	}

	fn config(port: u16) -> MailServerConfig {
		let endpoint = MailEndpoint { host: "127.0.0.1".into(), port, security: TransportSecurity::None };
		MailServerConfig { incoming: endpoint.clone(), outgoing: endpoint, username: "me@example.com".into() }
	}

	#[tokio::test]
	async fn xoauth2_login_sends_the_bearer_response() {
		let (port, server) = fake_server(false).await;
		let session = connect(&config(port), &Auth::Bearer("tok123".into())).await;
		assert!(session.is_ok(), "{:?}", session.err());
		let seen = server.await.unwrap();
		assert_eq!(seen[0], "A0001 AUTHENTICATE XOAUTH2");
		let decoded = base64::engine::general_purpose::STANDARD.decode(&seen[1]).unwrap();
		assert_eq!(String::from_utf8(decoded).unwrap(), "user=me@example.com\x01auth=Bearer tok123\x01\x01");
	}

	#[tokio::test]
	async fn xoauth2_rejection_answers_the_error_challenge_and_reports_auth() {
		let (port, server) = fake_server(true).await;
		let result = connect(&config(port), &Auth::Bearer("bad".into())).await;
		assert!(matches!(result, Err(CoreError::Auth { .. })));
		let seen = server.await.unwrap();
		assert_eq!(seen[2], "", "error challenge must be answered with an empty line");
	}
}
