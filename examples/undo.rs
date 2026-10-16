//! Archive then immediately move back; the server must end where it started.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mailflare_core::{CredentialStore, Folder, MailCore, MoveTarget};

#[derive(Default)]
struct Memory(Mutex<HashMap<String, String>>);
impl CredentialStore for Memory {
	fn load(&self, a: String) -> Option<String> { self.0.lock().unwrap().get(&a).cloned() }
	fn save(&self, a: String, s: String) -> bool { self.0.lock().unwrap().insert(a, s); true }
	fn delete(&self, a: String) { self.0.lock().unwrap().remove(&a); }
}

fn main() {
	let dir = tempfile::tempdir().unwrap();
	let core = MailCore::new(dir.path().to_string_lossy().into(), Arc::new(Memory::default())).unwrap();
	let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
	rt.block_on(async {
		let account = core.sign_in(std::env::var("MAILFLARE_EMAIL").unwrap(), std::env::var("MAILFLARE_KEY").unwrap(), std::env::var("MAILFLARE_SERVER").ok()).await.unwrap();
		let a = account.id.clone();
		core.sync(a.clone()).await.unwrap();
		let m = core.messages(a.clone(), Folder::Role { role: "inbox".into() }, 0, 1).unwrap().remove(0);
		let origin = m.mailbox_id.clone();
		core.move_messages(a.clone(), vec![m.id.clone()], MoveTarget::Role { role: "archive".into() }).unwrap();
		tokio::time::sleep(Duration::from_millis(std::env::var("GAP").ok().and_then(|g| g.parse().ok()).unwrap_or(300))).await;
		core.move_messages(a.clone(), vec![m.id.clone()], MoveTarget::Mailbox { id: origin.clone() }).unwrap();
		for _ in 0..40 {
			if core.pending_action_count(a.clone()).unwrap() == 0 { break; }
			tokio::time::sleep(Duration::from_millis(250)).await;
		}
		core.sync(a.clone()).await.unwrap();
		let after = core.message_summary(a.clone(), m.id.clone()).unwrap().unwrap();
		println!("{} back in {}: {}", m.id, origin, after.mailbox_id == origin);
	});
}
