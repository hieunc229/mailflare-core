//! Mailflare mobile core. Owns protocols, sync and the local store; the
//! native UIs read through the paged queries on [`MailCore`] and subscribe to
//! [`CoreEvent`]s.

mod error;
mod jmap;
mod sanitize;
mod store;
mod sync;
mod types;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use error::CoreError;
pub use types::*;

use error::Result;
use jmap::Credentials;
use store::Store;

uniffi::setup_scaffolding!();

/// Secrets live in the platform keychain, never in the database. The app
/// implements this over Keychain Services (iOS) or the Keystore (Android).
#[uniffi::export(with_foreign)]
pub trait CredentialStore: Send + Sync {
	fn load(&self, account_id: String) -> Option<String>;
	fn save(&self, account_id: String, secret: String) -> bool;
	fn delete(&self, account_id: String);
}

#[uniffi::export(with_foreign)]
pub trait CoreListener: Send + Sync {
	fn on_event(&self, event: CoreEvent);
}

struct Inner {
	store: Store,
	http: reqwest::Client,
	credentials: Arc<dyn CredentialStore>,
	listener: Mutex<Option<Arc<dyn CoreListener>>>,
	/// One sync or flush at a time per account.
	locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Inner {
	fn emit(&self, event: CoreEvent) {
		let listener = self.listener.lock().unwrap_or_else(|e| e.into_inner()).clone();
		if let Some(listener) = listener {
			listener.on_event(event);
		}
	}

	fn lock_for(&self, account_id: &str) -> Arc<tokio::sync::Mutex<()>> {
		self.locks.lock().unwrap_or_else(|e| e.into_inner()).entry(account_id.to_string()).or_default().clone()
	}

	fn context(&self, account_id: &str) -> Result<sync::Context<'_>> {
		let endpoint = self.store.endpoint(account_id)?;
		let secret = self
			.credentials
			.load(account_id.to_string())
			.ok_or_else(|| CoreError::Auth { message: "Sign in again to continue.".into() })?;
		Ok(sync::Context {
			store: &self.store,
			http: &self.http,
			credentials: Credentials { username: endpoint.email.clone(), secret },
			endpoint,
		})
	}

	async fn sync(&self, account_id: &str) -> Result<()> {
		let lock = self.lock_for(account_id);
		let _guard = lock.lock().await;
		let ctx = self.context(account_id)?;
		self.emit(CoreEvent::SyncStarted { account_id: account_id.to_string() });
		let result = async {
			// Push local changes first so the window re-query sees them.
			let _ = sync::flush_actions(&ctx, account_id).await;
			let mailboxes = sync::sync_mailboxes(&ctx, account_id).await?;
			self.emit(CoreEvent::MailboxesChanged { account_id: account_id.to_string() });
			sync::sync_messages(&ctx, account_id, &mailboxes).await?;
			self.emit(CoreEvent::MessagesChanged { account_id: account_id.to_string() });
			Ok(())
		}
		.await;
		self.emit(CoreEvent::SyncFinished {
			account_id: account_id.to_string(),
			error: result.as_ref().err().map(|e: &CoreError| e.to_string()),
		});
		result
	}

	async fn flush(&self, account_id: &str) -> Result<u32> {
		let lock = self.lock_for(account_id);
		let _guard = lock.lock().await;
		let ctx = self.context(account_id)?;
		sync::flush_actions(&ctx, account_id).await
	}
}

#[derive(uniffi::Object)]
pub struct MailCore {
	inner: Arc<Inner>,
	runtime: tokio::runtime::Runtime,
}

impl MailCore {
	/// Runs network work on the core's own Tokio runtime and awaits it from
	/// whatever executor the foreign side polls with.
	async fn run<T, F>(&self, work: impl FnOnce(Arc<Inner>) -> F) -> Result<T>
	where
		T: Send + 'static,
		F: std::future::Future<Output = Result<T>> + Send + 'static,
	{
		let future = work(self.inner.clone());
		self.runtime.spawn(future).await.map_err(|e| CoreError::server(format!("Task failed: {e}")))?
	}

	fn schedule_flush(&self, account_id: String) {
		let inner = self.inner.clone();
		self.runtime.spawn(async move {
			let _ = inner.flush(&account_id).await;
		});
	}
}

#[uniffi::export]
impl MailCore {
	/// Opens (or creates) the store in `data_dir`.
	#[uniffi::constructor]
	pub fn new(data_dir: String, credentials: Arc<dyn CredentialStore>) -> Result<Arc<Self>> {
		let dir = PathBuf::from(data_dir);
		std::fs::create_dir_all(&dir).map_err(|e| CoreError::Storage { message: e.to_string() })?;
		let store = Store::open(&dir.join("mailflare.sqlite"))?;
		let http = reqwest::Client::builder()
			.user_agent(concat!("Mailflare-Mobile/", env!("CARGO_PKG_VERSION")))
			.connect_timeout(Duration::from_secs(15))
			.timeout(Duration::from_secs(60))
			.https_only(false) // enforced per URL by jmap::require_secure (loopback may be http)
			.build()
			.map_err(|e| CoreError::Network { message: e.to_string() })?;
		let runtime = tokio::runtime::Builder::new_multi_thread()
			.worker_threads(2)
			.thread_name("mailflare-core")
			.enable_all()
			.build()
			.map_err(|e| CoreError::Storage { message: e.to_string() })?;
		Ok(Arc::new(Self {
			inner: Arc::new(Inner {
				store,
				http,
				credentials,
				listener: Mutex::new(None),
				locks: Mutex::new(HashMap::new()),
			}),
			runtime,
		}))
	}

	pub fn set_listener(&self, listener: Option<Arc<dyn CoreListener>>) {
		*self.inner.listener.lock().unwrap_or_else(|e| e.into_inner()) = listener;
	}

	pub fn accounts(&self) -> Result<Vec<Account>> {
		self.inner.store.accounts()
	}

	/// Discovers the JMAP session for `email` (or `server_url`), verifies the
	/// app password and stores the account. Signing in again to the same
	/// account replaces its secret.
	pub async fn sign_in(&self, email: String, app_password: String, server_url: Option<String>) -> Result<Account> {
		self.run(move |inner| async move {
			let email = email.trim().to_string();
			if email.is_empty() || app_password.trim().is_empty() {
				return Err(CoreError::invalid("Enter your email and app password"));
			}
			let credentials = Credentials { username: email.clone(), secret: app_password.trim().to_string() };
			let mut last_error = None;
			let mut session = None;
			for candidate in jmap::session_candidates(&email, server_url.as_deref())? {
				match jmap::fetch_session(&inner.http, &candidate, &credentials).await {
					Ok(found) => {
						session = Some((candidate, found));
						break;
					}
					Err(error @ CoreError::Auth { .. }) => return Err(error),
					Err(error) => last_error = Some(error),
				}
			}
			let Some((candidate, session)) = session else {
				return Err(match last_error {
					Some(CoreError::Network { .. }) | None => CoreError::Discovery {
						message: "Couldn't find a mail server for this address. Enter the server address.".into(),
					},
					Some(error) => error,
				});
			};
			let server = url::Url::parse(&candidate).map(|u| u.origin().ascii_serialization()).unwrap_or(candidate);
			let id = inner.store.find_account_id(&email, &server)?.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
			if !inner.credentials.save(id.clone(), credentials.secret.clone()) {
				return Err(CoreError::Storage { message: "Couldn't save the password to the keychain".into() });
			}
			let display_name = if session.account_name.is_empty() { email.clone() } else { session.account_name.clone() };
			inner.store.insert_account(store::NewAccount {
				id: &id,
				email: &email,
				display_name: &display_name,
				server_url: &server,
				session_url: &session.session_url,
				api_url: &session.api_url,
				download_url: &session.download_url,
				jmap_account_id: &session.account_id,
			})?;
			Ok(Account { id, email, display_name, server_url: server })
		})
		.await
	}

	/// Removes the account, its cached mail, queued actions and its secret.
	pub fn sign_out(&self, account_id: String) -> Result<()> {
		self.inner.store.delete_account(&account_id)?;
		self.inner.credentials.delete(account_id);
		Ok(())
	}

	pub fn mailboxes(&self, account_id: String) -> Result<Vec<Mailbox>> {
		self.inner.store.mailboxes(&account_id)
	}

	/// One page of a folder, newest first.
	pub fn messages(&self, account_id: String, folder: Folder, offset: u32, limit: u32) -> Result<Vec<MessageSummary>> {
		self.inner.store.messages(&account_id, &folder, offset, limit.min(500))
	}

	/// Messages of the folder held locally.
	pub fn message_count(&self, account_id: String, folder: Folder) -> Result<u32> {
		self.inner.store.count(&account_id, &folder, false)
	}

	/// Unread count as the server reports it, adjusted for local actions.
	pub fn unread_count(&self, account_id: String, folder: Folder) -> Result<u32> {
		self.inner.store.server_unread(&account_id, &folder)
	}

	/// Local full-text search over sender, subject and preview.
	pub fn search(&self, account_id: String, query: String, limit: u32) -> Result<Vec<MessageSummary>> {
		self.inner.store.search(&account_id, &query, limit.min(500))
	}

	pub async fn sync(&self, account_id: String) -> Result<()> {
		self.run(move |inner| async move { inner.sync(&account_id).await }).await
	}

	/// Pages the next older batch of a folder from the server. Returns the
	/// number of messages received; 0 means the folder is fully loaded.
	pub async fn fetch_older(&self, account_id: String, folder: Folder) -> Result<u32> {
		self.run(move |inner| async move {
			let lock = inner.lock_for(&account_id);
			let _guard = lock.lock().await;
			let ctx = inner.context(&account_id)?;
			let count = sync::fetch_older(&ctx, &account_id, &folder).await?;
			if count > 0 {
				inner.emit(CoreEvent::MessagesChanged { account_id: account_id.clone() });
			}
			Ok(count)
		})
		.await
	}

	/// The message with its body if the body is cached, without touching the network.
	pub fn cached_message(&self, account_id: String, message_id: String) -> Result<Option<MessageDetail>> {
		self.inner.store.detail(&account_id, &message_id)
	}

	pub fn message_summary(&self, account_id: String, message_id: String) -> Result<Option<MessageSummary>> {
		self.inner.store.summary(&account_id, &message_id)
	}

	/// Fetches, sanitizes and caches the body.
	pub async fn load_message(&self, account_id: String, message_id: String) -> Result<MessageDetail> {
		self.run(move |inner| async move {
			let ctx = inner.context(&account_id)?;
			sync::load_message(&ctx, &account_id, &message_id).await
		})
		.await
	}

	pub fn set_seen(&self, account_id: String, message_ids: Vec<String>, seen: bool) -> Result<()> {
		self.set_keyword(account_id, message_ids, "$seen", seen)
	}

	pub fn set_flagged(&self, account_id: String, message_ids: Vec<String>, flagged: bool) -> Result<()> {
		self.set_keyword(account_id, message_ids, "$flagged", flagged)
	}

	pub fn pending_action_count(&self, account_id: String) -> Result<u32> {
		Ok(self.inner.store.pending_actions(&account_id)?.len() as u32)
	}

	/// Retries queued actions, e.g. when connectivity returns.
	pub fn flush_actions(&self, account_id: String) {
		self.schedule_flush(account_id);
	}
}

impl MailCore {
	fn set_keyword(&self, account_id: String, message_ids: Vec<String>, keyword: &str, value: bool) -> Result<()> {
		let client_id = uuid::Uuid::new_v4().to_string();
		let payload = serde_json::to_string(&sync::KeywordAction { ids: message_ids.clone(), keyword: keyword.into(), value })?;
		let changed = self.inner.store.apply_keyword(&account_id, &message_ids, keyword, value, &client_id, &payload)?;
		if !changed.is_empty() {
			self.inner.emit(CoreEvent::MessagesChanged { account_id: account_id.clone() });
			if keyword == "$seen" {
				self.inner.emit(CoreEvent::MailboxesChanged { account_id: account_id.clone() });
			}
			self.schedule_flush(account_id);
		}
		Ok(())
	}
}
