//! Mailflare mobile core. Owns protocols, sync and the local store; the
//! native UIs read through the paged queries on [`MailCore`] and subscribe to
//! [`CoreEvent`]s.

mod actions;
mod compose;
mod device;
mod error;
mod folders;
mod jmap;
mod sanitize;
mod store;
mod imap;
mod oauth;
mod smtp;
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
use oauth::{OAuthAuthorization, OAuthClient};
use store::Store;

uniffi::setup_scaffolding!();

/// The browser URL for an OAuth sign-in plus the PKCE verifier and state to
/// pass back to `sign_in_oauth` with the redirect URL.
#[uniffi::export]
pub fn oauth_authorization(client: OAuthClient, email: String) -> Result<OAuthAuthorization> {
	oauth::authorization(&client, &email)
}

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

	fn is_imap(&self, account_id: &str) -> Result<bool> {
		Ok(self.store.protocol(account_id)? == "imap")
	}

	/// Connection settings and a usable credential. An OAuth access token is
	/// refreshed here when it is about to expire, so every connection starts
	/// with a valid one.
	async fn imap_context(&self, account_id: &str) -> Result<imap::sync::ImapContext<'_>> {
		let (email, config) = self.store.mail_config(account_id)?;
		let secret = self
			.credentials
			.load(account_id.to_string())
			.ok_or_else(|| CoreError::Auth { message: "Sign in again to continue.".into() })?;
		let auth = if self.store.auth_kind(account_id)? == "oauth" {
			imap::Auth::Bearer(self.fresh_access_token(account_id, &secret).await?)
		} else {
			imap::Auth::Password(secret)
		};
		Ok(imap::sync::ImapContext { account_id: account_id.to_string(), store: &self.store, email, config, auth })
	}

	async fn fresh_access_token(&self, account_id: &str, raw: &str) -> Result<String> {
		let secret = oauth::OAuthSecret::parse(raw)?;
		if secret.is_fresh(chrono::Utc::now().timestamp()) {
			return Ok(secret.access_token);
		}
		let renewed = oauth::refresh(&self.http, &secret).await?;
		if !self.credentials.save(account_id.to_string(), serde_json::to_string(&renewed)?) {
			return Err(CoreError::Storage { message: "Couldn't save the new access token to the keychain".into() });
		}
		Ok(renewed.access_token)
	}

	/// Checks the login on both servers, then stores the account.
	async fn add_imap_account(
		&self,
		email: &str,
		config: MailServerConfig,
		auth: imap::Auth,
		stored_secret: String,
		auth_kind: &str,
	) -> Result<Account> {
		let mut session = imap::connect(&config, &auth).await?;
		let _ = session.logout().await;
		smtp::verify(&config, &auth).await?;
		let server = format!("imap://{}", config.incoming.host);
		let id = self.store.find_account_id(email, &server)?.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
		if !self.credentials.save(id.clone(), stored_secret) {
			return Err(CoreError::Storage { message: "Couldn't save the credentials to the keychain".into() });
		}
		self.store.insert_imap_account(&id, email, email, &server, &config, auth_kind)?;
		self.store.replace_identities(&id, &[Identity { id: "imap".into(), name: String::new(), email: email.to_string() }])?;
		Ok(Account { id, email: email.to_string(), display_name: email.to_string(), server_url: server })
	}

	async fn sync_imap(&self, account_id: &str) -> Result<()> {
		let lock = self.lock_for(account_id);
		let _guard = lock.lock().await;
		let ctx = self.imap_context(account_id).await?;
		self.emit(CoreEvent::SyncStarted { account_id: account_id.to_string() });
		let result = async {
			if let Ok(report) = imap::actions::flush(&ctx, &self.data_dir).await {
				self.report(account_id, &report);
			}
			let mut session = ctx.connect().await?;
			let mailboxes = imap::sync::sync_mailboxes(&ctx, &mut session).await?;
			self.emit(CoreEvent::MailboxesChanged { account_id: account_id.to_string() });
			let progress = || self.emit(CoreEvent::MessagesChanged { account_id: account_id.to_string() });
			let account = account_id.to_string();
			let announce = |message: &store::StoredMessage| {
				let from = if message.from_name.trim().is_empty() { message.from_email.clone() } else { message.from_name.clone() };
				self.emit(CoreEvent::NewMail { account_id: account.clone(), message_id: message.id.clone(), from, subject: message.subject.clone() });
			};
			let synced = imap::sync::sync_messages(&ctx, &mut session, &mailboxes, &progress, &announce).await;
			let _ = session.logout().await;
			synced?;
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

	/// Inbox-only sync for background wake-ups; see `imap::sync::sync_inbox_quick`.
	async fn sync_quick_imap(&self, account_id: &str) -> Result<()> {
		// An account that was never fully synced (added but not yet opened) has
		// no inbox to look at; do the full sync once so it is not skipped forever.
		let has_inbox = self.store.mailboxes(account_id)?.iter().any(|m| m.role.as_deref() == Some("inbox"));
		if !has_inbox {
			return self.sync_imap(account_id).await;
		}
		let lock = self.lock_for(account_id);
		let _guard = lock.lock().await;
		let ctx = self.imap_context(account_id).await?;
		let progress = || self.emit(CoreEvent::MessagesChanged { account_id: account_id.to_string() });
		let account = account_id.to_string();
		let announce = |message: &store::StoredMessage| {
			let from = if message.from_name.trim().is_empty() { message.from_email.clone() } else { message.from_name.clone() };
			self.emit(CoreEvent::NewMail { account_id: account.clone(), message_id: message.id.clone(), from, subject: message.subject.clone() });
		};
		imap::sync::sync_inbox_quick(&ctx, &progress, &announce).await
	}

	async fn sync(&self, account_id: &str) -> Result<()> {
		if self.is_imap(account_id)? {
			return self.sync_imap(account_id).await;
		}
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
			// Deltas when the server keeps a change log; otherwise (or when the
			// state expired) re-query the windows. The state is read before the
			// windows so changes made meanwhile are replayed next time.
			let delta = match self.store.email_state(account_id)? {
				Some(since) => sync::delta_sync(&ctx, account_id, &since).await?,
				None => None,
			};
			let state = match delta {
				Some(state) => Some(state),
				None => {
					let state = sync::email_state(&ctx).await?;
					let progress = || self.emit(CoreEvent::MessagesChanged { account_id: account_id.to_string() });
						sync::sync_messages(&ctx, account_id, &mailboxes, &progress).await?;
					state
				}
			};
			self.store.set_email_state(account_id, state.as_deref())?;
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

	/// Verifies `secret` against the first session URL that answers and stores the account.
	async fn add_account(&self, email: &str, secret: &str, candidates: Vec<String>, auth_kind: &str) -> Result<Account> {
		let credentials = Credentials { username: email.to_string(), secret: secret.to_string() };
		let mut last_error = None;
		let mut session = None;
		for candidate in candidates {
			match jmap::fetch_session(&self.http, &candidate, &credentials).await {
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
				Some(CoreError::Network { .. }) | None => {
					CoreError::Discovery { message: "Couldn't find a mail server for this address. Enter the server address.".into() }
				}
				Some(error) => error,
			});
		};
		let server = url::Url::parse(&candidate).map(|u| u.origin().ascii_serialization()).unwrap_or(candidate);
		let id = self.store.find_account_id(email, &server)?.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
		// Replacing a device key: revoke the previous one.
		if self.store.auth_kind(&id).ok().as_deref() == Some("device") {
			if let Some(previous) = self.credentials.load(id.clone()).filter(|p| p != secret) {
				let old = Credentials { username: email.to_string(), secret: previous };
				if let Ok(origin) = device::api_origin(&session.api_url) {
					let _ = device::revoke(&self.http, &origin, &old).await;
				}
			}
		}
		if !self.credentials.save(id.clone(), secret.to_string()) {
			return Err(CoreError::Storage { message: "Couldn't save the password to the keychain".into() });
		}
		let display_name = if session.account_name.is_empty() { email.to_string() } else { session.account_name.clone() };
		self.store.insert_account(store::NewAccount {
			id: &id,
			email,
			display_name: &display_name,
			server_url: &server,
			session_url: &session.session_url,
			api_url: &session.api_url,
			download_url: &session.download_url,
			upload_url: &session.upload_url,
			jmap_account_id: &session.account_id,
		})?;
		self.store.set_auth_kind(&id, auth_kind)?;
		Ok(Account { id, email: email.to_string(), display_name, server_url: server })
	}

	async fn flush(&self, account_id: &str) -> Result<actions::FlushReport> {
		let lock = self.lock_for(account_id);
		let _guard = lock.lock().await;
		if self.is_imap(account_id)? {
			let ctx = self.imap_context(account_id).await?;
			let report = imap::actions::flush(&ctx, &self.data_dir).await?;
			self.report(account_id, &report);
			return Ok(report);
		}
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
			let candidates = jmap::session_candidates(&email, server_url.as_deref())?;
			inner.add_account(&email, app_password.trim(), candidates, "app_password").await
		})
		.await
	}

	/// Signs in to an IMAP account with an app password: checks the login on the
	/// incoming and the outgoing server, then stores the account. Mail arrives
	/// with the first sync.
	pub async fn sign_in_imap(&self, email: String, password: String, config: MailServerConfig) -> Result<Account> {
		self.run(move |inner| async move {
			let email = email.trim().to_string();
			if email.is_empty() || password.is_empty() {
				return Err(CoreError::invalid("Enter your email and password"));
			}
			if config.incoming.host.trim().is_empty() || config.outgoing.host.trim().is_empty() {
				return Err(CoreError::invalid("Enter the incoming and outgoing server"));
			}
			let config = MailServerConfig {
				incoming: MailEndpoint { host: config.incoming.host.trim().to_string(), ..config.incoming },
				outgoing: MailEndpoint { host: config.outgoing.host.trim().to_string(), ..config.outgoing },
				username: if config.username.trim().is_empty() { email.clone() } else { config.username.trim().to_string() },
			};
			inner.add_imap_account(&email, config, imap::Auth::Password(password.clone()), password, "app_password").await
		})
		.await
	}

	/// Signs in to Gmail or Outlook with the redirect URL the browser sign-in
	/// ended on (see `oauth_authorization`). `config` holds the provider's IMAP
	/// and SMTP servers; the login is the email address.
	pub async fn sign_in_oauth(
		&self,
		email: String,
		client: OAuthClient,
		authorization: OAuthAuthorization,
		redirect_url: String,
		config: MailServerConfig,
	) -> Result<Account> {
		self.run(move |inner| async move {
			let email = email.trim().to_string();
			if email.is_empty() {
				return Err(CoreError::invalid("Enter your email"));
			}
			let code = oauth::code_from_redirect(&redirect_url, &authorization.state)?;
			let secret = oauth::exchange_code(&inner.http, &client, &code, &authorization.verifier).await?;
			let config = MailServerConfig {
				incoming: MailEndpoint { host: config.incoming.host.trim().to_string(), ..config.incoming },
				outgoing: MailEndpoint { host: config.outgoing.host.trim().to_string(), ..config.outgoing },
				username: email.clone(),
			};
			let stored = serde_json::to_string(&secret)?;
			inner.add_imap_account(&email, config, imap::Auth::Bearer(secret.access_token), stored, "oauth").await
		})
		.await
	}

	/// Signs in to a Mailflare server with the account password. The server
	/// returns a device key, which is stored like an app password and revoked
	/// on sign-out. With two-factor on, returns `MfaRequired`.
	pub async fn sign_in_with_password(
		&self,
		email: String,
		password: String,
		server_url: Option<String>,
		device_name: String,
	) -> Result<PasswordSignIn> {
		self.run(move |inner| async move {
			let email = email.trim().to_string();
			if email.is_empty() || password.is_empty() {
				return Err(CoreError::invalid("Enter your email and password"));
			}
			let body = device::password_body(&email, &password, &device_name);
			let mut last_network = None;
			for origin in device::origins(&email, server_url.as_deref())? {
				match device::login(&inner.http, &origin, body.clone()).await {
					Ok(Some(device::DeviceLogin::Key { key, session_url })) => {
						let account = inner.add_account(&email, &key, vec![session_url], "device").await?;
						return Ok(PasswordSignIn::SignedIn { account });
					}
					Ok(Some(device::DeviceLogin::Mfa { challenge_token })) => {
						return Ok(PasswordSignIn::MfaRequired { challenge_token, server_url: origin });
					}
					Ok(None) => continue,
					Err(error @ CoreError::Network { .. }) => {
						last_network = Some(error);
						continue;
					}
					Err(error) => return Err(error),
				}
			}
			if let Some(error) = last_network {
				return Err(error);
			}
			Err(CoreError::Discovery {
				message: "This server doesn't offer password sign-in. Use an app password, or enter the server address.".into(),
			})
		})
		.await
	}

	/// Finishes a password sign-in with a TOTP or recovery code.
	pub async fn complete_mfa(
		&self,
		email: String,
		challenge_token: String,
		code: String,
		server_url: String,
		device_name: String,
	) -> Result<Account> {
		self.run(move |inner| async move {
			let body = device::mfa_body(&challenge_token, code.trim(), &device_name);
			match device::login(&inner.http, &server_url, body).await? {
				Some(device::DeviceLogin::Key { key, session_url }) => inner.add_account(email.trim(), &key, vec![session_url], "device").await,
				Some(device::DeviceLogin::Mfa { .. }) => Err(CoreError::Auth { message: "The code was not accepted.".into() }),
				None => Err(CoreError::Discovery { message: "The server stopped answering this sign-in. Start again.".into() }),
			}
		})
		.await
	}

	/// Removes the account, its cached mail, queued actions and its secret.
	/// A device key from a password sign-in is also revoked on the server
	/// (best effort; the local data goes regardless).
	pub fn sign_out(&self, account_id: String) -> Result<()> {
		if self.inner.store.auth_kind(&account_id)? == "device" {
			if let (Ok(endpoint), Some(secret)) = (self.inner.store.endpoint(&account_id), self.inner.credentials.load(account_id.clone())) {
				let http = self.inner.http.clone();
				let credentials = Credentials { username: endpoint.email.clone(), secret };
				if let Ok(origin) = device::api_origin(&endpoint.api_url) {
					self.runtime.spawn(async move {
						let _ = device::revoke(&http, &origin, &credentials).await;
					});
				}
			}
		}
		for action in self.inner.store.pending_actions(&account_id)? {
			let _ = std::fs::remove_dir_all(actions::outbox_dir(&self.inner.data_dir, &action.client_id));
		}
		let _ = std::fs::remove_dir_all(self.inner.data_dir.join("attachments").join(&account_id));
		self.inner.store.delete_account(&account_id)?;
		self.inner.credentials.delete(account_id);
		Ok(())
	}

	/// Registers this device's APNs token for new-mail pushes.
	/// Returns false when the server accepted the registration but cannot send
	/// pushes (no APNs configuration), so the app can say so.
	pub async fn register_push(&self, account_id: String, registration: PushRegistration) -> Result<bool> {
		self.run(move |inner| async move {
			// IMAP servers have no push to forward; those accounts announce new
			// mail from sync instead (`CoreEvent::NewMail`).
			if inner.is_imap(&account_id)? {
				return Ok(true);
			}
			let ctx = inner.context(&account_id)?;
			let origin = device::api_origin(&ctx.endpoint.api_url)?;
			let body = serde_json::json!({
				"platform": "apns",
				"token": registration.token,
				"environment": match registration.environment { PushEnvironment::Production => "production", PushEnvironment::Sandbox => "sandbox" },
				"topic": registration.topic,
				"publicKey": registration.public_key,
				"previews": registration.previews,
				// Echoed back in pushes so a tap opens this account.
				"accountRef": account_id,
			});
			device::register_push(&inner.http, &origin, &ctx.credentials, body).await
		})
		.await
	}

	pub async fn unregister_push(&self, account_id: String) -> Result<()> {
		self.run(move |inner| async move {
			if inner.is_imap(&account_id)? {
				return Ok(());
			}
			let ctx = inner.context(&account_id)?;
			let origin = device::api_origin(&ctx.endpoint.api_url)?;
			device::unregister_push(&inner.http, &origin, &ctx.credentials).await
		})
		.await
	}

	/// What this account allows for folders, and how to word it (Gmail calls them labels).
	pub fn folder_support(&self, account_id: String) -> Result<folders::FolderSupport> {
		if !self.inner.is_imap(&account_id)? {
			return Ok(folders::support(false, ""));
		}
		let (_, config) = self.inner.store.mail_config(&account_id)?;
		Ok(folders::support(true, &config.incoming.host))
	}

	/// Creates a folder under `parent_id` (an account's top-level mailbox when None), then re-reads the list.
	pub async fn create_folder(&self, account_id: String, parent_id: Option<String>, name: String) -> Result<()> {
		self.run(move |inner| async move {
			{
				let lock = inner.lock_for(&account_id);
				let _guard = lock.lock().await;
				if inner.is_imap(&account_id)? {
					folders::imap_create(&inner.imap_context(&account_id).await?, parent_id.as_deref(), &name).await?;
				} else {
					folders::jmap_create(&inner.context(&account_id)?, parent_id.as_deref(), &name).await?;
				}
			}
			inner.sync(&account_id).await
		})
		.await
	}

	/// Renames a folder. IMAP ids carry the path, so mail in a renamed folder is read again from the server.
	pub async fn rename_folder(&self, account_id: String, mailbox_id: String, name: String) -> Result<()> {
		self.run(move |inner| async move {
			{
				let lock = inner.lock_for(&account_id);
				let _guard = lock.lock().await;
				if inner.is_imap(&account_id)? {
					folders::imap_rename(&inner.imap_context(&account_id).await?, &mailbox_id, &name).await?;
				} else {
					folders::jmap_rename(&inner.context(&account_id)?, &mailbox_id, &name).await?;
				}
			}
			inner.sync(&account_id).await
		})
		.await
	}

	/// Deletes a folder. See `FolderSupport::delete_note` for what happens to its mail.
	pub async fn delete_folder(&self, account_id: String, mailbox_id: String) -> Result<()> {
		self.run(move |inner| async move {
			{
				let lock = inner.lock_for(&account_id);
				let _guard = lock.lock().await;
				if inner.is_imap(&account_id)? {
					folders::imap_delete(&inner.imap_context(&account_id).await?, &mailbox_id).await?;
				} else {
					folders::jmap_delete(&inner.context(&account_id)?, &mailbox_id).await?;
				}
			}
			inner.sync(&account_id).await
		})
		.await
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

	/// A cheap refresh for background wake-ups: IMAP accounts sync only their
	/// inbox on one connection; other accounts use their normal delta sync.
	pub async fn sync_quick(&self, account_id: String) -> Result<()> {
		self.run(move |inner| async move {
			if inner.is_imap(&account_id)? {
				inner.sync_quick_imap(&account_id).await
			} else {
				inner.sync(&account_id).await
			}
		})
		.await
	}

	/// Pages the next older batch of a folder from the server. Returns the
	/// number of messages received; 0 means the folder is fully loaded.
	pub async fn fetch_older(&self, account_id: String, folder: Folder) -> Result<u32> {
		self.run(move |inner| async move {
			let lock = inner.lock_for(&account_id);
			let _guard = lock.lock().await;
			let count = if inner.is_imap(&account_id)? {
				imap::sync::fetch_older(&inner.imap_context(&account_id).await?, &folder).await?
			} else {
				let ctx = inner.context(&account_id)?;
				sync::fetch_older(&ctx, &account_id, &folder).await?
			};
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

	/// The AI summary saved for a message, if one was made.
	pub fn ai_summary(&self, account_id: String, message_id: String) -> Result<Option<String>> {
		self.inner.store.ai_summary(&account_id, &message_id)
	}

	/// Saves (replacing) the AI summary the app generated for a message.
	pub fn save_ai_summary(&self, account_id: String, message_id: String, text: String) -> Result<()> {
		self.inner.store.save_ai_summary(&account_id, &message_id, &text)
	}

	/// Fetches, sanitizes and caches the body.
	pub async fn load_message(&self, account_id: String, message_id: String) -> Result<MessageDetail> {
		self.run(move |inner| async move {
			if inner.is_imap(&account_id)? {
				return imap::sync::load_message(&inner.imap_context(&account_id).await?, &message_id).await;
			}
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
			let is_draft = self.inner.store.mailbox_role(&account_id, &detail.summary.mailbox_id)?.as_deref() == Some("drafts");
			if detail.message_id.is_some() || is_draft {
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
			if inner.is_imap(&account_id)? {
				return imap::sync::search_server(&inner.imap_context(&account_id).await?, query.trim(), limit).await;
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
			// `<message id>#raw` names the whole message as received (headers and MIME body), for
			// "Show original": fetched from the IMAP server, or as the message's own blob on JMAP.
			let raw_of = attachment.blob_id.strip_suffix("#raw");
			let bytes = if inner.is_imap(&account_id)? {
				let ctx = inner.imap_context(&account_id).await?;
				match raw_of {
					Some(id) => imap::sync::fetch_raw(&ctx, id).await?,
					None => imap::sync::download_attachment(&ctx, &attachment.blob_id).await?,
				}
			} else {
				let ctx = inner.context(&account_id)?;
				let blob_id = raw_of.map(|id| format!("msg~{id}")).unwrap_or_else(|| attachment.blob_id.clone());
				ctx.download(&blob_id, &name, &attachment.mime_type).await?
			};
			std::fs::create_dir_all(&dir).map_err(|e| CoreError::Storage { message: e.to_string() })?;
			let partial = dir.join(format!(".{name}.part"));
			std::fs::write(&partial, bytes).map_err(|e| CoreError::Storage { message: e.to_string() })?;
			std::fs::rename(&partial, &path).map_err(|e| CoreError::Storage { message: e.to_string() })?;
			Ok(path.to_string_lossy().into_owned())
		})
		.await
	}
}
