//! End-to-end check of an IMAP + SMTP account:
//!   MAILFLARE_EMAIL=… MAILFLARE_PASSWORD=… MAILFLARE_IMAP_HOST=imap.example.com \
//!   MAILFLARE_SMTP_HOST=smtp.example.com cargo run --example imap
//! Optional: MAILFLARE_IMAP_PORT (993), MAILFLARE_SMTP_PORT (465), MAILFLARE_IMAP_SECURITY and
//! MAILFLARE_SMTP_SECURITY (tls | starttls | none; none only for a server on this machine).
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mailflare_core::{TransportSecurity, CredentialStore, EmailAddress, Folder, MailCore, MailServerConfig, MoveTarget, OutgoingMessage, MailEndpoint};

#[derive(Default)]
struct Memory(Mutex<HashMap<String, String>>);

impl CredentialStore for Memory {
	fn load(&self, account_id: String) -> Option<String> {
		self.0.lock().unwrap().get(&account_id).cloned()
	}
	fn save(&self, account_id: String, secret: String) -> bool {
		self.0.lock().unwrap().insert(account_id, secret);
		true
	}
	fn delete(&self, account_id: String) {
		self.0.lock().unwrap().remove(&account_id);
	}
}

fn env(name: &str) -> Option<String> {
	std::env::var(name).ok()
}

fn security(name: &str, default: TransportSecurity) -> TransportSecurity {
	match env(name).as_deref() {
		Some("starttls") => TransportSecurity::StartTls,
		Some("none") => TransportSecurity::None,
		Some("tls") => TransportSecurity::Tls,
		_ => default,
	}
}

fn main() {
	let email = env("MAILFLARE_EMAIL").expect("MAILFLARE_EMAIL");
	let password = env("MAILFLARE_PASSWORD").expect("MAILFLARE_PASSWORD");
	let imap_host = env("MAILFLARE_IMAP_HOST").expect("MAILFLARE_IMAP_HOST");
	let smtp_host = env("MAILFLARE_SMTP_HOST").expect("MAILFLARE_SMTP_HOST");
	let config = MailServerConfig {
		incoming: MailEndpoint {
			host: imap_host,
			port: env("MAILFLARE_IMAP_PORT").and_then(|p| p.parse().ok()).unwrap_or(993),
			security: security("MAILFLARE_IMAP_SECURITY", TransportSecurity::Tls),
		},
		outgoing: MailEndpoint {
			host: smtp_host,
			port: env("MAILFLARE_SMTP_PORT").and_then(|p| p.parse().ok()).unwrap_or(465),
			security: security("MAILFLARE_SMTP_SECURITY", TransportSecurity::Tls),
		},
		username: env("MAILFLARE_USERNAME").unwrap_or_default(),
	};
	let dir = tempfile::tempdir().unwrap();
	let core = MailCore::new(dir.path().to_string_lossy().into(), Arc::new(Memory::default())).unwrap();
	let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
	rt.block_on(async {
		let account = core.sign_in_imap(email, password, config).await.expect("sign in");
		println!("signed in: {} ({})", account.email, account.server_url);
		let started = std::time::Instant::now();
		core.sync(account.id.clone()).await.expect("sync");
		println!("synced in {:?}", started.elapsed());
		for mailbox in core.mailboxes(account.id.clone()).unwrap() {
			println!("  {:<30} role={:<8} total={} unread={}", mailbox.name, mailbox.role.unwrap_or_default(), mailbox.total_emails, mailbox.unread_emails);
		}
		let inbox = Folder::Role { role: "inbox".into() };
		let messages = core.messages(account.id.clone(), inbox.clone(), 0, 5).unwrap();
		for message in &messages {
			println!("  {} | {} | {} | {}", message.id, message.from_name, message.subject, message.preview);
		}
		if let Some(first) = messages.first() {
			let detail = core.load_message(account.id.clone(), first.id.clone()).await.expect("load");
			println!("body: {} chars, {} attachments, message-id {:?}", detail.html.len(), detail.attachments.len(), detail.message_id);
			core.set_seen(account.id.clone(), vec![first.id.clone()], !first.seen).unwrap();
			core.flush_actions(account.id.clone());
			tokio::time::sleep(std::time::Duration::from_secs(2)).await;
			core.sync(account.id.clone()).await.expect("resync");
			let after = core.message_summary(account.id.clone(), first.id.clone()).unwrap().unwrap();
			println!("seen flipped: {} -> {}", first.seen, after.seen);
		}
		// Only with MAILFLARE_WRITE=1: sends to yourself, moves and deletes mail.
		if env("MAILFLARE_WRITE").is_none() {
			return;
		}
		let me = EmailAddress { name: None, email: core.identities(account.id.clone()).unwrap()[0].email.clone() };
		let outgoing = OutgoingMessage {
			identity_id: core.identities(account.id.clone()).unwrap()[0].id.clone(),
			to: vec![me],
			cc: vec![],
			bcc: vec![],
			subject: "core IMAP test".into(),
			html: "<p>Sent by the IMAP example.</p>".into(),
			in_reply_to: None,
			references: vec![],
			attachments: vec![],
			replaces_draft_id: None,
		};
		core.send(account.id.clone(), outgoing).unwrap();
		tokio::time::sleep(std::time::Duration::from_secs(4)).await;
		core.sync(account.id.clone()).await.expect("sync after send");
		let sent = core.messages(account.id.clone(), Folder::Role { role: "sent".into() }, 0, 5).unwrap();
		println!("sent folder: {:?}", sent.iter().map(|m| m.subject.clone()).collect::<Vec<_>>());
		println!("outbox: {} items", core.outbox(account.id.clone()).unwrap().len());
		if let Some(message) = core.messages(account.id.clone(), inbox.clone(), 0, 1).unwrap().first() {
			core.move_messages(account.id.clone(), vec![message.id.clone()], MoveTarget::Role { role: "trash".into() }).unwrap();
			tokio::time::sleep(std::time::Duration::from_secs(3)).await;
			core.sync(account.id.clone()).await.expect("sync after move");
			let trash = core.messages(account.id.clone(), Folder::Role { role: "trash".into() }, 0, 5).unwrap();
			println!("trash after move: {:?}", trash.iter().map(|m| (m.id.clone(), m.subject.clone())).collect::<Vec<_>>());
			let ids: Vec<String> = trash.iter().map(|m| m.id.clone()).collect();
			core.delete_messages(account.id.clone(), ids).unwrap();
			tokio::time::sleep(std::time::Duration::from_secs(3)).await;
			core.sync(account.id.clone()).await.expect("sync after delete");
			println!("trash after delete: {}", core.message_count(account.id.clone(), Folder::Role { role: "trash".into() }).unwrap());
		}
	});
}
