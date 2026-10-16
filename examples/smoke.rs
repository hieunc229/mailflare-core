//! End-to-end check against a running server:
//!   MAILFLARE_EMAIL=… MAILFLARE_KEY=… MAILFLARE_SERVER=http://localhost:3000 cargo run --example smoke
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mailflare_core::{CredentialStore, Folder, MailCore};

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

fn main() {
	let email = std::env::var("MAILFLARE_EMAIL").expect("MAILFLARE_EMAIL");
	let key = std::env::var("MAILFLARE_KEY").expect("MAILFLARE_KEY");
	let server = std::env::var("MAILFLARE_SERVER").ok();
	let dir = tempfile::tempdir().unwrap();
	let core = MailCore::new(dir.path().to_string_lossy().into(), Arc::new(Memory::default())).unwrap();
	let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
	rt.block_on(async {
		let account = core.sign_in(email, key, server).await.expect("sign in");
		println!("signed in: {} ({})", account.email, account.server_url);
		let started = std::time::Instant::now();
		core.sync(account.id.clone()).await.expect("sync");
		println!("synced in {:?}", started.elapsed());
		for mailbox in core.mailboxes(account.id.clone()).unwrap() {
			println!("  {:<40} role={:<8} total={} unread={}", mailbox.name, mailbox.role.unwrap_or_default(), mailbox.total_emails, mailbox.unread_emails);
		}
		let inbox = Folder::Role { role: "inbox".into() };
		let page = core.messages(account.id.clone(), inbox.clone(), 0, 50).unwrap();
		println!("inbox: {} local, {} unread", page.len(), core.unread_count(account.id.clone(), inbox).unwrap());
		for m in &page {
			println!("  {} | {:<24} | {}", if m.seen { " " } else { "*" }, m.from_name, m.subject);
		}
		if let Some(first) = page.first() {
			let detail = core.load_message(account.id.clone(), first.id.clone()).await.expect("load");
			println!("body: {} bytes html, remote={}, {} attachments", detail.html.len(), detail.has_remote_content, detail.attachments.len());
			core.set_flagged(account.id.clone(), vec![first.id.clone()], !first.flagged).unwrap();
			core.sync(account.id.clone()).await.expect("sync after flag");
			let after = core.message_summary(account.id.clone(), first.id.clone()).unwrap().unwrap();
			println!("flag toggled: {} -> {} (pending {})", first.flagged, after.flagged, core.pending_action_count(account.id.clone()).unwrap());
			core.set_flagged(account.id.clone(), vec![first.id.clone()], first.flagged).unwrap();
			core.sync(account.id.clone()).await.expect("sync restore");
		}
		println!("search 'invoice': {}", core.search(account.id.clone(), "invoice".into(), 10).unwrap().len());
		println!("older: {}", core.fetch_older(account.id.clone(), Folder::Role { role: "sent".into() }).await.unwrap());
	});
}
