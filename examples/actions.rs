//! End-to-end check of milestone 2 actions against a running server:
//!   MAILFLARE_EMAIL=… MAILFLARE_KEY=… MAILFLARE_SERVER=http://localhost:3000 cargo run --example actions
//! Sends one message to the account's own first address and leaves it in Sent.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mailflare_core::{CredentialStore, EmailAddress, Folder, MailCore, MoveTarget, OutgoingAttachment, OutgoingMessage, ReplyKind};

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

async fn settle(core: &MailCore, account: &str) {
	for _ in 0..60 {
		if core.pending_action_count(account.to_string()).unwrap() == 0 {
			break;
		}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
	let outbox = core.outbox(account.to_string()).unwrap();
	assert!(outbox.is_empty(), "outbox not drained: {outbox:?}");
	core.sync(account.to_string()).await.expect("sync");
}

fn main() {
	let dir = tempfile::tempdir().unwrap();
	let core = MailCore::new(dir.path().to_string_lossy().into(), Arc::new(Memory::default())).unwrap();
	let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
	rt.block_on(async {
		let account = core
			.sign_in(std::env::var("MAILFLARE_EMAIL").unwrap(), std::env::var("MAILFLARE_KEY").unwrap(), std::env::var("MAILFLARE_SERVER").ok())
			.await
			.expect("sign in");
		let a = account.id.clone();
		core.sync(a.clone()).await.expect("sync");
		let identities = core.identities(a.clone()).unwrap();
		println!("identities: {:?}", identities.iter().map(|i| &i.email).collect::<Vec<_>>());
		let me = identities.first().expect("an identity").clone();

		// Draft with an attachment.
		let file = dir.path().join("note.txt");
		std::fs::write(&file, b"hello from the mobile core").unwrap();
		let draft = OutgoingMessage {
			identity_id: me.id.clone(),
			to: vec![EmailAddress { name: Some("Self".into()), email: me.email.clone() }],
			cc: vec![],
			bcc: vec![],
			subject: "Core draft check".into(),
			html: "<p>Draft <b>body</b></p>".into(),
			in_reply_to: None,
			references: vec![],
			attachments: vec![OutgoingAttachment {
				file_path: Some(file.to_string_lossy().into()),
				blob_id: None,
				name: "note.txt".into(),
				mime_type: "text/plain".into(),
				size: 26,
			}],
			replaces_draft_id: None,
		};
		core.save_draft(a.clone(), draft.clone()).unwrap();
		settle(&core, &a).await;
		let drafts = core.messages(a.clone(), Folder::Role { role: "drafts".into() }, 0, 50).unwrap();
		let stored = drafts.iter().find(|m| m.subject == "Core draft check").expect("draft on server");
		println!("draft stored: {} (attachment: {})", stored.id, stored.has_attachment);

		// Reopen and download its attachment.
		let template = core.draft_template(a.clone(), stored.id.clone()).await.unwrap();
		let detail = core.load_message(a.clone(), stored.id.clone()).await.unwrap();
		let path = core.download_attachment(a.clone(), detail.attachments[0].clone()).await.unwrap();
		println!("attachment downloaded: {:?}", std::fs::read_to_string(&path).unwrap());

		// Send it (replaces the draft).
		let mut outgoing = draft.clone();
		outgoing.subject = "Core send check".into();
		outgoing.attachments = template.attachments.clone();
		outgoing.replaces_draft_id = template.replaces_draft_id.clone();
		core.send(a.clone(), outgoing).unwrap();
		settle(&core, &a).await;
		let sent = core.messages(a.clone(), Folder::Role { role: "sent".into() }, 0, 50).unwrap();
		println!("sent: {}", sent.iter().any(|m| m.subject == "Core send check"));
		let drafts = core.messages(a.clone(), Folder::Role { role: "drafts".into() }, 0, 50).unwrap();
		println!("draft replaced: {}", !drafts.iter().any(|m| m.subject.starts_with("Core ")));

		// Reply template for an inbox message.
		let inbox = core.messages(a.clone(), Folder::Role { role: "inbox".into() }, 0, 5).unwrap();
		let first = inbox.first().expect("inbox mail").clone();
		let reply = core.compose_template(a.clone(), first.id.clone(), ReplyKind::ReplyAll).await.unwrap();
		println!("reply: {:?} to {:?} in-reply-to {:?}", reply.subject, reply.to.iter().map(|t| &t.email).collect::<Vec<_>>(), reply.in_reply_to);

		// Archive, then back to Inbox.
		core.move_messages(a.clone(), vec![first.id.clone()], MoveTarget::Role { role: "archive".into() }).unwrap();
		settle(&core, &a).await;
		let archived = core.message_summary(a.clone(), first.id.clone()).unwrap().unwrap();
		println!("archived: {}", archived.mailbox_id.ends_with("~archive"));
		core.move_messages(a.clone(), vec![first.id.clone()], MoveTarget::Role { role: "inbox".into() }).unwrap();
		settle(&core, &a).await;

		// Trash the sent copy, then delete it permanently.
		let sent_copy = core.messages(a.clone(), Folder::Role { role: "sent".into() }, 0, 50).unwrap().into_iter().find(|m| m.subject == "Core send check").unwrap();
		core.delete_messages(a.clone(), vec![sent_copy.id.clone()]).unwrap();
		settle(&core, &a).await;
		println!("trashed: {}", core.message_summary(a.clone(), sent_copy.id.clone()).unwrap().map(|m| m.mailbox_id.ends_with("~trash")).unwrap_or(false));
		core.delete_messages(a.clone(), vec![sent_copy.id.clone()]).unwrap();
		settle(&core, &a).await;
		println!("deleted: {}", core.message_summary(a.clone(), sent_copy.id).unwrap().is_none());

		let found = core.search_server(a.clone(), "invoice".into(), 20).await.unwrap();
		println!("server search 'invoice': {}", found.len());
	});
}
