//! Mailflare mobile core. Owns protocols, sync and the local store; the
//! native UIs read through the paged queries on [`MailCore`] and subscribe to
//! [`CoreEvent`]s.

mod actions;
mod compose;
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

/// Plain text for an HTML body (used to edit a stored draft as text).
#[uniffi::export]
pub fn html_to_plain_text(html: String) -> String {
	compose::html_to_text(&html)
}

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
	data_dir: PathBuf,
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
			account_id: account_id.to_string(),
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
			if let Ok(report) = actions::flush(&ctx, account_id, &self.data_dir).await {
				self.report(account_id, &report);
			}
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

	async fn flush(&self, account_id: &str) -> Result<actions::FlushReport> {
		let lock = self.lock_for(account_id);
		let _guard = lock.lock().await;
		let ctx = self.context(account_id)?;
		let report = actions::flush(&ctx, account_id, &self.data_dir).await?;
		self.report(account_id, &report);
		Ok(report)
	}

	fn report(&self, account_id: &str, report: &actions::FlushReport) {
		for subject in &report.sent {
			self.emit(CoreEvent::MessageSent { account_id: account_id.to_string(), subject: subject.clone() });
		}
		if report.outbox_changed {
			self.emit(CoreEvent::OutboxChanged { account_id: account_id.to_string() });
		}
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

	/// Replays the queue in the background; a send or draft save is followed
	/// by a sync so Sent and Drafts show the server's copy.
	fn schedule_flush(&self, account_id: String) {
		let inner = self.inner.clone();
		self.runtime.spawn(async move {
			if let Ok(report) = inner.flush(&account_id).await {
				if report.needs_sync {
					let _ = inner.sync(&account_id).await;
				}
			}
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
				data_dir: dir,
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
				upload_url: &session.upload_url,
				jmap_account_id: &session.account_id,
			})?;
			Ok(Account { id, email, display_name, server_url: server })
		})
		.await
	}

	/// Removes the account, its cached mail, queued actions and its secret.
	pub fn sign_out(&self, account_id: String) -> Result<()> {
		for action in self.inner.store.pending_actions(&account_id)? {
			let _ = std::fs::remove_dir_all(actions::outbox_dir(&self.inner.data_dir, &action.client_id));
		}
		let _ = std::fs::remove_dir_all(self.inner.data_dir.join("attachments").join(&account_id));
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
		let payload = serde_json::to_string(&actions::KeywordAction { ids: message_ids.clone(), keyword: keyword.into(), value })?;
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

	fn enqueue_outgoing(&self, account_id: String, mut message: OutgoingMessage, send: bool) -> Result<String> {
		if send && message.to.is_empty() && message.cc.is_empty() && message.bcc.is_empty() {
			return Err(CoreError::invalid("Add at least one recipient"));
		}
		if !self.inner.store.identities(&account_id)?.iter().any(|i| i.id == message.identity_id) {
			return Err(CoreError::invalid("Choose an address to send from"));
		}
		let client_id = uuid::Uuid::new_v4().to_string();
		// Own a copy of every local file, so the app's temporary files can go.
		let dir = actions::outbox_dir(&self.inner.data_dir, &client_id);
		for (index, attachment) in message.attachments.iter_mut().enumerate() {
			let Some(path) = attachment.file_path.clone() else { continue };
			std::fs::create_dir_all(&dir).map_err(|e| CoreError::Storage { message: e.to_string() })?;
			let target = dir.join(format!("{index}"));
			std::fs::copy(&path, &target)
				.map_err(|e| CoreError::Storage { message: format!("Couldn't attach {}: {e}", attachment.name) })?;
			attachment.file_path = Some(target.to_string_lossy().into_owned());
		}
		let summary = serde_json::to_string(&actions::OutboxSummary::of(&message))?;
		let payload = serde_json::to_string(&actions::OutgoingAction {
			message,
			send,
			uploaded: vec![],
			draft_id: None,
			submit_attempted: false,
		})?;
		self.inner.store.enqueue(&account_id, &client_id, if send { "send" } else { "draft" }, &payload, &summary)?;
		self.inner.emit(CoreEvent::OutboxChanged { account_id: account_id.clone() });
		self.schedule_flush(account_id);
		Ok(client_id)
	}

	async fn detail_for(&self, account_id: String, message_id: String) -> Result<MessageDetail> {
		if let Some(detail) = self.inner.store.detail(&account_id, &message_id)? {
			if detail.message_id.is_some() || detail.summary.mailbox_id.ends_with("~drafts") {
				return Ok(detail);
			}
		}
		self.load_message(account_id, message_id).await
	}
}

/// Milestone 2: composing, moving, deleting, attachments and server search.
#[uniffi::export]
impl MailCore {
	/// Known correspondents matching `prefix`, for the recipient fields.
	pub fn suggest_contacts(&self, account_id: String, prefix: String, limit: u32) -> Result<Vec<EmailAddress>> {
		self.inner.store.suggest_contacts(&account_id, &prefix, limit.min(50))
	}

	/// Addresses the account may send from.
	pub fn identities(&self, account_id: String) -> Result<Vec<Identity>> {
		self.inner.store.identities(&account_id)
	}

	/// A prefilled composer for replying to or forwarding `message_id`.
	pub async fn compose_template(&self, account_id: String, message_id: String, kind: ReplyKind) -> Result<ComposeTemplate> {
		let detail = self.detail_for(account_id.clone(), message_id).await?;
		Ok(compose::template(&detail, kind, &self.inner.store.identities(&account_id)?))
	}

	/// A stored draft, reopened for editing. Saving or sending replaces it.
	pub async fn draft_template(&self, account_id: String, message_id: String) -> Result<ComposeTemplate> {
		let detail = self.detail_for(account_id.clone(), message_id).await?;
		Ok(compose::draft_template(&detail, &self.inner.store.identities(&account_id)?))
	}

	/// Queues a message for sending and returns its outbox id. It is sent as
	/// soon as the server is reachable; failures stay in the outbox.
	pub fn send(&self, account_id: String, message: OutgoingMessage) -> Result<String> {
		self.enqueue_outgoing(account_id, message, true)
	}

	/// Queues saving a draft to the server's Drafts.
	pub fn save_draft(&self, account_id: String, message: OutgoingMessage) -> Result<String> {
		self.enqueue_outgoing(account_id, message, false)
	}

	pub fn outbox(&self, account_id: String) -> Result<Vec<OutboxItem>> {
		Ok(self.inner.store.pending_actions(&account_id)?.iter().filter_map(actions::outbox_item).collect())
	}

	/// Retries a stalled outbox item now.
	pub fn retry_outbox_item(&self, account_id: String, client_id: String) -> Result<()> {
		self.inner.store.reset_action(&account_id, &client_id)?;
		self.inner.emit(CoreEvent::OutboxChanged { account_id: account_id.clone() });
		self.schedule_flush(account_id);
		Ok(())
	}

	/// Drops an outbox item that has not been sent. A partially stored draft
	/// on the server is left for the user to delete.
	pub fn discard_outbox_item(&self, account_id: String, client_id: String) -> Result<()> {
		self.inner.store.delete_action(&account_id, &client_id)?;
		let _ = std::fs::remove_dir_all(actions::outbox_dir(&self.inner.data_dir, &client_id));
		self.inner.emit(CoreEvent::OutboxChanged { account_id });
		Ok(())
	}

	/// Moves messages. A role target resolves per message to that role's
	/// mailbox for the same address; messages already there are skipped.
	pub fn move_messages(&self, account_id: String, message_ids: Vec<String>, target: MoveTarget) -> Result<u32> {
		let mut moves = std::collections::BTreeMap::new();
		for id in &message_ids {
			let Some(summary) = self.inner.store.summary(&account_id, id)? else { continue };
			let destination = match &target {
				MoveTarget::Mailbox { id } => Some(id.clone()),
				MoveTarget::Role { role } => self.inner.store.sibling_with_role(&account_id, &summary.mailbox_id, role)?,
			};
			if let Some(destination) = destination.filter(|d| d != &summary.mailbox_id) {
				moves.insert(id.clone(), destination);
			}
		}
		if moves.is_empty() {
			return Ok(0);
		}
		let client_id = uuid::Uuid::new_v4().to_string();
		let pairs: Vec<(String, String)> = moves.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
		let payload = serde_json::to_string(&actions::MoveAction { moves })?;
		let changed = self.inner.store.apply_move(&account_id, &pairs, &client_id, &payload)?;
		if changed > 0 {
			self.inner.emit(CoreEvent::MessagesChanged { account_id: account_id.clone() });
			self.inner.emit(CoreEvent::MailboxesChanged { account_id: account_id.clone() });
			self.schedule_flush(account_id);
		}
		Ok(changed as u32)
	}

	/// Moves messages to Trash; messages already in Trash or Drafts are
	/// deleted permanently. Returns how many were deleted permanently.
	pub fn delete_messages(&self, account_id: String, message_ids: Vec<String>) -> Result<u32> {
		let mut permanent = Vec::new();
		let mut to_trash = Vec::new();
		for id in message_ids {
			let Some(summary) = self.inner.store.summary(&account_id, &id)? else { continue };
			match self.inner.store.mailbox_role(&account_id, &summary.mailbox_id)?.as_deref() {
				Some("trash") | Some("drafts") => permanent.push(id),
				_ => to_trash.push(id),
			}
		}
		if !to_trash.is_empty() {
			self.move_messages(account_id.clone(), to_trash, MoveTarget::Role { role: "trash".into() })?;
		}
		if permanent.is_empty() {
			return Ok(0);
		}
		let client_id = uuid::Uuid::new_v4().to_string();
		let payload = serde_json::to_string(&actions::DestroyAction { ids: permanent.clone() })?;
		let changed = self.inner.store.apply_destroy(&account_id, &permanent, &client_id, &payload)?;
		if changed > 0 {
			self.inner.emit(CoreEvent::MessagesChanged { account_id: account_id.clone() });
			self.inner.emit(CoreEvent::MailboxesChanged { account_id: account_id.clone() });
			self.schedule_flush(account_id);
		}
		Ok(changed as u32)
	}

	/// Searches the server (mail outside the synced windows). Results are
	/// cached, so local search finds them afterwards.
	pub async fn search_server(&self, account_id: String, query: String, limit: u32) -> Result<Vec<MessageSummary>> {
		self.run(move |inner| async move {
			if query.trim().is_empty() {
				return Ok(vec![]);
			}
			let ctx = inner.context(&account_id)?;
			sync::search_server(&ctx, &account_id, query.trim(), limit).await
		})
		.await
	}

	/// Downloads an attachment into the core's cache and returns the file
	/// path. A cached file is returned without the network.
	pub async fn download_attachment(&self, account_id: String, attachment: Attachment) -> Result<String> {
		self.run(move |inner| async move {
			let safe = |value: &str| -> String {
				let cleaned: String = value.chars().map(|c| if c == '/' || c == '\\' || c == ':' || c.is_control() { '_' } else { c }).collect();
				let trimmed = cleaned.trim_start_matches('.').trim().to_string();
				if trimmed.is_empty() { "attachment".into() } else { trimmed }
			};
			let dir = inner.data_dir.join("attachments").join(&account_id).join(safe(&attachment.blob_id));
			let name = safe(attachment.name.as_deref().unwrap_or("attachment"));
			let path = dir.join(&name);
			if path.exists() {
				return Ok(path.to_string_lossy().into_owned());
			}
			let ctx = inner.context(&account_id)?;
			let bytes = ctx.download(&attachment.blob_id, &name, &attachment.mime_type).await?;
			std::fs::create_dir_all(&dir).map_err(|e| CoreError::Storage { message: e.to_string() })?;
			let partial = dir.join(format!(".{name}.part"));
			std::fs::write(&partial, bytes).map_err(|e| CoreError::Storage { message: e.to_string() })?;
			std::fs::rename(&partial, &path).map_err(|e| CoreError::Storage { message: e.to_string() })?;
			Ok(path.to_string_lossy().into_owned())
		})
		.await
	}
}
