//! Milestone 3 against a running Mailflare: password sign-in (device key),
//! delta sync through Email/changes, push registration, revoking sign-out.
//!   MAILFLARE_EMAIL=… MAILFLARE_PASSWORD=… MAILFLARE_SERVER=http://localhost:3000 cargo run --example device
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mailflare_core::{CredentialStore, Folder, MailCore, PasswordSignIn, PushEnvironment, PushRegistration};

#[derive(Default)]
struct Memory(Mutex<HashMap<String, String>>);
impl CredentialStore for Memory {
	fn load(&self, a: String) -> Option<String> { self.0.lock().unwrap().get(&a).cloned() }
	fn save(&self, a: String, s: String) -> bool { self.0.lock().unwrap().insert(a, s); true }
	fn delete(&self, a: String) { self.0.lock().unwrap().remove(&a); }
}

fn main() {
	let dir = tempfile::tempdir().unwrap();
	let creds = Arc::new(Memory::default());
	let core = MailCore::new(dir.path().to_string_lossy().into(), creds.clone()).unwrap();
	// A second client changes things server-side.
	let other_dir = tempfile::tempdir().unwrap();
	let other = MailCore::new(other_dir.path().to_string_lossy().into(), Arc::new(Memory::default())).unwrap();
	let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
	rt.block_on(async {
		let email = std::env::var("MAILFLARE_EMAIL").unwrap();
		let server = std::env::var("MAILFLARE_SERVER").ok();
		let wrong = core.sign_in_with_password(email.clone(), "wrong".into(), server.clone(), "Example".into()).await;
		println!("wrong password rejected: {}", wrong.is_err());
		let result = core
			.sign_in_with_password(email.clone(), std::env::var("MAILFLARE_PASSWORD").unwrap(), server.clone(), "Core example".into())
			.await
			.expect("sign in");
		let PasswordSignIn::SignedIn { account } = result else { panic!("unexpected MFA") };
		let a = account.id.clone();
		let key = creds.load(a.clone()).unwrap();
		println!("device key received: {}", key.starts_with("ep_"));

		core.sync(a.clone()).await.unwrap();
		let inbox = Folder::Role { role: "inbox".into() };
		let first = core.messages(a.clone(), inbox.clone(), 0, 1).unwrap().remove(0);
		println!("window sync: inbox has {}", core.message_count(a.clone(), inbox.clone()).unwrap());

		let o = other.sign_in(email.clone(), key.clone(), server.clone()).await.unwrap().id;
		other.sync(o.clone()).await.unwrap();
		other.set_flagged(o.clone(), vec![first.id.clone()], !first.flagged).unwrap();
		other.sync(o.clone()).await.unwrap();

		core.sync(a.clone()).await.unwrap();
		let after = core.message_summary(a.clone(), first.id.clone()).unwrap().unwrap();
		println!("delta sync saw the flag change: {}", after.flagged != first.flagged);
		other.set_flagged(o.clone(), vec![first.id.clone()], first.flagged).unwrap();
		other.sync(o.clone()).await.unwrap();

		let registration = PushRegistration {
			token: "ab".repeat(32),
			environment: PushEnvironment::Sandbox,
			topic: "xyz.hieunguyen.mailflare-ios".into(),
			public_key: None,
			previews: false,
		};
		println!("push registered: {:?}", core.register_push(a.clone(), registration).await);
		other.sign_out(o).unwrap();
		core.sign_out(a.clone()).unwrap();
		tokio::time::sleep(std::time::Duration::from_millis(800)).await;
		let reuse = other.sign_in(email, key, server).await;
		println!("device key revoked after sign-out: {}", reuse.is_err());
	});
}
