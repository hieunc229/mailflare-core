//! Building and sending mail over SMTP for IMAP accounts.

use lettre::message::header::{ContentType, InReplyTo, References};
use lettre::message::{Attachment as MimeAttachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::Tls;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::compose;
use crate::error::{CoreError, Result};
use crate::imap::{is_loopback, require_encryption, Auth};
use crate::types::{TransportSecurity, EmailAddress, Identity, MailServerConfig, OutgoingMessage};

fn mailbox(address: &EmailAddress) -> Result<Mailbox> {
	let email = address.email.trim().parse().map_err(|_| CoreError::invalid(format!("\"{}\" is not a valid email address", address.email)))?;
	Ok(Mailbox::new(address.name.clone().filter(|n| !n.trim().is_empty()), email))
}

fn angle(id: &str) -> String {
	let trimmed = id.trim().trim_matches(['<', '>']);
	format!("<{trimmed}>")
}

/// The message as it goes on the wire. `attachments` pairs each attachment
/// with its bytes.
pub fn build_message(identity: &Identity, message: &OutgoingMessage, attachments: Vec<(String, String, Vec<u8>)>) -> Result<Message> {
	let mut builder = Message::builder()
		.from(mailbox(&EmailAddress { name: Some(identity.name.clone()), email: identity.email.clone() })?)
		.subject(message.subject.clone());
	for to in &message.to {
		builder = builder.to(mailbox(to)?);
	}
	for cc in &message.cc {
		builder = builder.cc(mailbox(cc)?);
	}
	for bcc in &message.bcc {
		builder = builder.bcc(mailbox(bcc)?);
	}
	if let Some(parent) = message.in_reply_to.as_deref().filter(|p| !p.trim().is_empty()) {
		builder = builder.header(InReplyTo::from(angle(parent)));
	}
	if !message.references.is_empty() {
		builder = builder.header(References::from(message.references.iter().map(|r| angle(r)).collect::<Vec<_>>().join(" ")));
	}
	let html = compose::document_body(&message.html);
	let text = compose::html_to_text(&html);
	let body = MultiPart::alternative()
		.singlepart(SinglePart::plain(text))
		.singlepart(SinglePart::html(html));
	let built = if attachments.is_empty() {
		builder.multipart(body)
	} else {
		let mut mixed = MultiPart::mixed().multipart(body);
		for (name, mime, bytes) in attachments {
			let content_type = ContentType::parse(&mime).unwrap_or_else(|_| ContentType::parse("application/octet-stream").expect("valid"));
			mixed = mixed.singlepart(MimeAttachment::new(name).body(bytes, content_type));
		}
		builder.multipart(mixed)
	};
	built.map_err(|e| CoreError::invalid(format!("Couldn't build the message: {e}")))
}

fn transport(config: &MailServerConfig, auth: &Auth) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
	let endpoint = &config.outgoing;
	require_encryption(endpoint)?;
	let (credentials, mechanisms) = match auth {
		Auth::Password(secret) => (Credentials::new(config.username.clone(), secret.clone()), vec![Mechanism::Plain, Mechanism::Login]),
		Auth::Bearer(token) => (Credentials::new(config.username.clone(), token.clone()), vec![Mechanism::Xoauth2]),
	};
	let builder = match endpoint.security {
		TransportSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&endpoint.host),
		TransportSecurity::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&endpoint.host),
		TransportSecurity::None => {
			debug_assert!(is_loopback(&endpoint.host));
			Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&endpoint.host).tls(Tls::None))
		}
	}
	.map_err(|e| CoreError::invalid(format!("Invalid outgoing server: {e}")))?;
	Ok(builder.port(endpoint.port).credentials(credentials).authentication(mechanisms).timeout(Some(std::time::Duration::from_secs(60))).build())
}

fn map_smtp_error(error: lettre::transport::smtp::Error) -> CoreError {
	let text = error.to_string();
	if error.is_permanent() {
		let lower = text.to_ascii_lowercase();
		if lower.contains("authentication") || lower.contains("credentials") || lower.contains("535") {
			return CoreError::Auth { message: format!("The outgoing server rejected the sign-in. ({text})") };
		}
		CoreError::server(format!("The outgoing server refused the message: {text}"))
	} else if error.is_transient() {
		CoreError::server(format!("The outgoing server asked to try again later: {text}"))
	} else {
		CoreError::Network { message: format!("Couldn't reach the outgoing server: {text}") }
	}
}

pub async fn send(config: &MailServerConfig, auth: &Auth, message: Message) -> Result<()> {
	let transport = transport(config, auth)?;
	transport.send(message).await.map(|_| ()).map_err(map_smtp_error)
}

/// Checks the outgoing server accepts the login, without sending anything.
pub async fn verify(config: &MailServerConfig, auth: &Auth) -> Result<()> {
	let transport = transport(config, auth)?;
	match transport.test_connection().await {
		Ok(true) => Ok(()),
		Ok(false) => Err(CoreError::Network { message: format!("Couldn't reach the outgoing server {}.", config.outgoing.host) }),
		Err(error) => Err(map_smtp_error(error)),
	}
}
