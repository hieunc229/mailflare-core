//! SQLite store. The core owns the database; the UI only sees paged rows.
//!
//! Two connections in WAL mode: sync writes never block list reads.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};

use crate::error::Result;
use crate::types::{Account, Attachment, EmailAddress, Folder, Identity, Mailbox, MessageDetail, MessageSummary};

const SCHEMA_VERSION: i32 = 4;

const SCHEMA_V1: &str = r#"
CREATE TABLE accounts (
	id TEXT PRIMARY KEY,
	email TEXT NOT NULL,
	display_name TEXT NOT NULL DEFAULT '',
	server_url TEXT NOT NULL,
	session_url TEXT NOT NULL,
	api_url TEXT NOT NULL,
	download_url TEXT NOT NULL,
	jmap_account_id TEXT NOT NULL,
	created_at INTEGER NOT NULL
);

CREATE TABLE mailboxes (
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	id TEXT NOT NULL,
	name TEXT NOT NULL,
	parent_id TEXT,
	role TEXT,
	sort_order INTEGER NOT NULL DEFAULT 0,
	total_emails INTEGER NOT NULL DEFAULT 0,
	unread_emails INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (account_id, id)
);

CREATE TABLE messages (
	pk INTEGER PRIMARY KEY,
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	id TEXT NOT NULL,
	thread_id TEXT NOT NULL,
	mailbox_id TEXT NOT NULL,
	from_name TEXT NOT NULL DEFAULT '',
	from_email TEXT NOT NULL DEFAULT '',
	subject TEXT NOT NULL DEFAULT '',
	preview TEXT NOT NULL DEFAULT '',
	received_at INTEGER NOT NULL,
	seen INTEGER NOT NULL DEFAULT 0,
	flagged INTEGER NOT NULL DEFAULT 0,
	has_attachment INTEGER NOT NULL DEFAULT 0,
	size INTEGER NOT NULL DEFAULT 0,
	UNIQUE (account_id, id)
);
CREATE INDEX messages_by_mailbox ON messages (account_id, mailbox_id, received_at DESC);
CREATE INDEX messages_by_flag ON messages (account_id, flagged, received_at DESC);

CREATE TABLE bodies (
	account_id TEXT NOT NULL,
	id TEXT NOT NULL,
	html TEXT NOT NULL,
	has_remote_content INTEGER NOT NULL DEFAULT 0,
	to_json TEXT NOT NULL DEFAULT '[]',
	cc_json TEXT NOT NULL DEFAULT '[]',
	reply_to_json TEXT NOT NULL DEFAULT '[]',
	attachments_json TEXT NOT NULL DEFAULT '[]',
	fetched_at INTEGER NOT NULL,
	PRIMARY KEY (account_id, id),
	FOREIGN KEY (account_id, id) REFERENCES messages (account_id, id) ON DELETE CASCADE
);

-- Persistent, idempotent action queue. Every server write goes through it.
CREATE TABLE actions (
	seq INTEGER PRIMARY KEY,
	client_id TEXT NOT NULL UNIQUE,
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	kind TEXT NOT NULL,
	payload TEXT NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 0,
	last_error TEXT,
	created_at INTEGER NOT NULL
);

CREATE VIRTUAL TABLE messages_fts USING fts5 (
	subject, from_name, from_email, preview,
	content = 'messages', content_rowid = 'pk',
	tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
	INSERT INTO messages_fts (rowid, subject, from_name, from_email, preview)
	VALUES (new.pk, new.subject, new.from_name, new.from_email, new.preview);
END;
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
	INSERT INTO messages_fts (messages_fts, rowid, subject, from_name, from_email, preview)
	VALUES ('delete', old.pk, old.subject, old.from_name, old.from_email, old.preview);
END;
CREATE TRIGGER messages_fts_update AFTER UPDATE OF subject, from_name, from_email, preview ON messages BEGIN
	INSERT INTO messages_fts (messages_fts, rowid, subject, from_name, from_email, preview)
	VALUES ('delete', old.pk, old.subject, old.from_name, old.from_email, old.preview);
	INSERT INTO messages_fts (rowid, subject, from_name, from_email, preview)
	VALUES (new.pk, new.subject, new.from_name, new.from_email, new.preview);
END;
"#;

const SCHEMA_V2: &str = r#"
ALTER TABLE accounts ADD COLUMN upload_url TEXT NOT NULL DEFAULT '';
ALTER TABLE bodies ADD COLUMN message_id TEXT;
ALTER TABLE bodies ADD COLUMN references_json TEXT NOT NULL DEFAULT '[]';
-- Short JSON shown in the outbox (subject, recipients) for send and draft actions.
ALTER TABLE actions ADD COLUMN summary TEXT NOT NULL DEFAULT '';

CREATE TABLE identities (
	account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	id TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	email TEXT NOT NULL,
	PRIMARY KEY (account_id, id)
);
"#;

const SCHEMA_V3: &str = r#"
ALTER TABLE messages ADD COLUMN to_display TEXT NOT NULL DEFAULT '';
"#;

const SCHEMA_V4: &str = r#"
-- The JMAP Email state the store reflects; `Email/changes` continues from it.
ALTER TABLE accounts ADD COLUMN email_state TEXT;
-- 'app_password' or 'device' (a key from a password sign-in, revoked on sign-out).
ALTER TABLE accounts ADD COLUMN auth_kind TEXT NOT NULL DEFAULT 'app_password';
"#;

const SUMMARY_COLUMNS: &str =
	"id, thread_id, mailbox_id, from_name, from_email, subject, preview, received_at, seen, flagged, has_attachment, to_display";

/// Everything the JMAP client needs to talk to an account's server.
#[derive(Debug, Clone)]
pub struct AccountEndpoint {
	pub email: String,
	pub api_url: String,
	pub jmap_account_id: String,
	pub session_url: String,
	pub download_url: String,
	pub upload_url: String,
}

pub struct NewAccount<'a> {
	pub id: &'a str,
	pub email: &'a str,
	pub display_name: &'a str,
	pub server_url: &'a str,
	pub session_url: &'a str,
	pub api_url: &'a str,
	pub download_url: &'a str,
	pub upload_url: &'a str,
	pub jmap_account_id: &'a str,
}

/// A message row as received from the server.
#[derive(Debug, Clone)]
pub struct StoredMessage {
	pub id: String,
	pub thread_id: String,
	pub mailbox_id: String,
	pub from_name: String,
	pub from_email: String,
	pub to_display: String,
	pub subject: String,
	pub preview: String,
	pub received_at: i64,
	pub seen: bool,
	pub flagged: bool,
	pub has_attachment: bool,
	pub size: i64,
}

pub struct StoredBody {
	pub html: String,
	pub has_remote_content: bool,
	pub to: Vec<EmailAddress>,
	pub cc: Vec<EmailAddress>,
	pub reply_to: Vec<EmailAddress>,
	pub attachments: Vec<Attachment>,
	/// The message's Message-ID, without angle brackets.
	pub message_id: Option<String>,
	pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PendingAction {
	pub seq: i64,
	pub client_id: String,
	pub kind: String,
	pub payload: String,
	pub attempts: u32,
	pub last_error: Option<String>,
	pub summary: String,
}

pub struct Store {
	writer: Mutex<Connection>,
	reader: Mutex<Connection>,
}

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn configure(conn: &Connection) -> Result<()> {
	conn.pragma_update(None, "journal_mode", "WAL")?;
	conn.pragma_update(None, "synchronous", "NORMAL")?;
	conn.pragma_update(None, "foreign_keys", true)?;
	conn.busy_timeout(std::time::Duration::from_secs(5))?;
	Ok(())
}

fn summary_from_row(row: &Row) -> rusqlite::Result<MessageSummary> {
	Ok(MessageSummary {
		id: row.get(0)?,
		thread_id: row.get(1)?,
		mailbox_id: row.get(2)?,
		from_name: row.get(3)?,
		from_email: row.get(4)?,
		subject: row.get(5)?,
		preview: row.get(6)?,
		received_at: row.get(7)?,
		seen: row.get(8)?,
		flagged: row.get(9)?,
		has_attachment: row.get(10)?,
		to_display: row.get(11)?,
	})
}

/// The WHERE clause (after `account_id = ?1`) selecting a folder, and its one parameter.
fn folder_clause(folder: &Folder) -> (&'static str, Option<String>) {
	match folder {
		Folder::Role { role } => (
			"mailbox_id IN (SELECT id FROM mailboxes WHERE account_id = ?1 AND role = ?2)",
			Some(role.clone()),
		),
		Folder::Mailbox { id } => ("mailbox_id = ?2", Some(id.clone())),
		Folder::Starred => ("flagged = 1", None),
	}
}

/// Turns free text into an FTS5 prefix query: every word must match, quoted so
/// user input can never be read as FTS syntax.
pub fn fts_query(input: &str) -> Option<String> {
	let terms: Vec<String> = input
		.split_whitespace()
		.map(|word| word.replace('"', ""))
		.filter(|word| !word.is_empty())
		.map(|word| format!("\"{word}\"*"))
		.collect();
	if terms.is_empty() {
		None
	} else {
		Some(terms.join(" "))
	}
}

impl Store {
	pub fn open(path: &Path) -> Result<Self> {
		let writer = Connection::open(path)?;
		configure(&writer)?;
		migrate(&writer)?;
		let reader = Connection::open(path)?;
		configure(&reader)?;
		Ok(Self { writer: Mutex::new(writer), reader: Mutex::new(reader) })
	}

	fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
		let conn = self.reader.lock().unwrap_or_else(|e| e.into_inner());
		f(&conn)
	}

	fn write<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T>) -> Result<T> {
		let mut conn = self.writer.lock().unwrap_or_else(|e| e.into_inner());
		f(&mut conn)
	}

	// Accounts

	pub fn insert_account(&self, account: NewAccount) -> Result<()> {
		self.write(|conn| {
			conn.execute(
				"INSERT INTO accounts (id, email, display_name, server_url, session_url, api_url, download_url, jmap_account_id, created_at, upload_url)
				 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
				 ON CONFLICT (id) DO UPDATE SET display_name = excluded.display_name, server_url = excluded.server_url,
				 	session_url = excluded.session_url, api_url = excluded.api_url, download_url = excluded.download_url,
				 	jmap_account_id = excluded.jmap_account_id, upload_url = excluded.upload_url",
				params![
					account.id,
					account.email,
					account.display_name,
					account.server_url,
					account.session_url,
					account.api_url,
					account.download_url,
					account.jmap_account_id,
					now(),
					account.upload_url
				],
			)?;
			Ok(())
		})
	}

	pub fn find_account_id(&self, email: &str, server_url: &str) -> Result<Option<String>> {
		self.read(|conn| {
			Ok(conn
				.query_row(
					"SELECT id FROM accounts WHERE lower(email) = lower(?1) AND server_url = ?2",
					params![email, server_url],
					|row| row.get(0),
				)
				.optional()?)
		})
	}

	pub fn accounts(&self) -> Result<Vec<Account>> {
		self.read(|conn| {
			let mut stmt = conn.prepare_cached("SELECT id, email, display_name, server_url FROM accounts ORDER BY created_at")?;
			let rows = stmt.query_map([], |row| {
				Ok(Account { id: row.get(0)?, email: row.get(1)?, display_name: row.get(2)?, server_url: row.get(3)? })
			})?;
			Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
		})
	}

	pub fn endpoint(&self, account_id: &str) -> Result<AccountEndpoint> {
		self.read(|conn| {
			conn.query_row(
				"SELECT email, api_url, jmap_account_id, session_url, download_url, upload_url FROM accounts WHERE id = ?1",
				params![account_id],
				|row| {
					Ok(AccountEndpoint {
						email: row.get(0)?,
						api_url: row.get(1)?,
						jmap_account_id: row.get(2)?,
						session_url: row.get(3)?,
						download_url: row.get(4)?,
						upload_url: row.get(5)?,
					})
				},
			)
			.optional()?
			.ok_or_else(|| crate::error::CoreError::not_found("Account not found"))
		})
	}

	pub fn delete_account(&self, account_id: &str) -> Result<()> {
		self.write(|conn| {
			let tx = conn.transaction()?;
			// Bodies reference messages, so they cascade; mailboxes, messages and actions cascade from accounts.
			tx.execute("DELETE FROM bodies WHERE account_id = ?1", params![account_id])?;
			tx.execute("DELETE FROM accounts WHERE id = ?1", params![account_id])?;
			tx.commit()?;
			Ok(())
		})
	}

	// Mailboxes

	pub fn replace_mailboxes(&self, account_id: &str, mailboxes: &[Mailbox]) -> Result<()> {
		self.write(|conn| {
			let tx = conn.transaction()?;
			{
				let mut upsert = tx.prepare_cached(
					"INSERT INTO mailboxes (account_id, id, name, parent_id, role, sort_order, total_emails, unread_emails)
					 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
					 ON CONFLICT (account_id, id) DO UPDATE SET name = excluded.name, parent_id = excluded.parent_id,
					 	role = excluded.role, sort_order = excluded.sort_order, total_emails = excluded.total_emails,
					 	unread_emails = excluded.unread_emails",
				)?;
				for mailbox in mailboxes {
					upsert.execute(params![
						account_id,
						mailbox.id,
						mailbox.name,
						mailbox.parent_id,
						mailbox.role,
						mailbox.sort_order,
						mailbox.total_emails,
						mailbox.unread_emails
					])?;
				}
			}
			let ids: Vec<&str> = mailboxes.iter().map(|m| m.id.as_str()).collect();
			let placeholders = vec!["?"; ids.len()].join(",");
			let keep = if ids.is_empty() { String::new() } else { format!(" AND id NOT IN ({placeholders})") };
			let mut values: Vec<&str> = vec![account_id];
			values.extend(ids.iter().copied());
			tx.execute(
				&format!("DELETE FROM mailboxes WHERE account_id = ?{keep}"),
				params_from_iter(values.iter()),
			)?;
			tx.execute(
				"DELETE FROM messages WHERE account_id = ?1 AND mailbox_id NOT IN (SELECT id FROM mailboxes WHERE account_id = ?1)",
				params![account_id],
			)?;
			tx.commit()?;
			Ok(())
		})
	}

	pub fn mailboxes(&self, account_id: &str) -> Result<Vec<Mailbox>> {
		self.read(|conn| {
			let mut stmt = conn.prepare_cached(
				"SELECT id, account_id, name, parent_id, role, sort_order, total_emails, unread_emails
				 FROM mailboxes WHERE account_id = ?1 ORDER BY sort_order, name",
			)?;
			let rows = stmt.query_map(params![account_id], |row| {
				Ok(Mailbox {
					id: row.get(0)?,
					account_id: row.get(1)?,
					name: row.get(2)?,
					parent_id: row.get(3)?,
					role: row.get(4)?,
					sort_order: row.get(5)?,
					total_emails: row.get(6)?,
					unread_emails: row.get(7)?,
				})
			})?;
			Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
		})
	}

	pub fn mailbox_ids_for(&self, account_id: &str, folder: &Folder) -> Result<Vec<String>> {
		match folder {
			Folder::Mailbox { id } => Ok(vec![id.clone()]),
			Folder::Starred => Ok(vec![]),
			Folder::Role { role } => self.read(|conn| {
				let mut stmt = conn.prepare_cached("SELECT id FROM mailboxes WHERE account_id = ?1 AND role = ?2")?;
				let rows = stmt.query_map(params![account_id, role], |row| row.get(0))?;
				Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
			}),
		}
	}

	// Messages

	pub fn messages(&self, account_id: &str, folder: &Folder, offset: u32, limit: u32) -> Result<Vec<MessageSummary>> {
		let (clause, param) = folder_clause(folder);
		self.read(|conn| {
			let sql = format!(
				"SELECT {SUMMARY_COLUMNS} FROM messages WHERE account_id = ?1 AND {clause}
				 ORDER BY received_at DESC, id LIMIT {limit} OFFSET {offset}"
			);
			let mut stmt = conn.prepare_cached(&sql)?;
			let rows = match &param {
				Some(value) => stmt.query_map(params![account_id, value], summary_from_row)?.collect::<rusqlite::Result<Vec<_>>>(),
				None => stmt.query_map(params![account_id], summary_from_row)?.collect::<rusqlite::Result<Vec<_>>>(),
			}?;
			Ok(rows)
		})
	}

	pub fn count(&self, account_id: &str, folder: &Folder, unread_only: bool) -> Result<u32> {
		let (clause, param) = folder_clause(folder);
		let unread = if unread_only { " AND seen = 0" } else { "" };
		self.read(|conn| {
			let sql = format!("SELECT count(*) FROM messages WHERE account_id = ?1 AND {clause}{unread}");
			let mut stmt = conn.prepare_cached(&sql)?;
			let count: u32 = match &param {
				Some(value) => stmt.query_row(params![account_id, value], |row| row.get(0))?,
				None => stmt.query_row(params![account_id], |row| row.get(0))?,
			};
			Ok(count)
		})
	}

	/// Server-reported unread count: exact even for mail outside the synced window.
	pub fn server_unread(&self, account_id: &str, folder: &Folder) -> Result<u32> {
		match folder {
			Folder::Starred => self.count(account_id, folder, true),
			Folder::Role { role } => self.read(|conn| {
				Ok(conn.query_row(
					"SELECT coalesce(sum(unread_emails), 0) FROM mailboxes WHERE account_id = ?1 AND role = ?2",
					params![account_id, role],
					|row| row.get(0),
				)?)
			}),
			Folder::Mailbox { id } => self.read(|conn| {
				Ok(conn
					.query_row(
						"SELECT unread_emails FROM mailboxes WHERE account_id = ?1 AND id = ?2",
						params![account_id, id],
						|row| row.get(0),
					)
					.optional()?
					.unwrap_or(0))
			}),
		}
	}

	pub fn search(&self, account_id: &str, query: &str, limit: u32) -> Result<Vec<MessageSummary>> {
		let Some(fts) = fts_query(query) else { return Ok(vec![]) };
		self.read(|conn| {
			let sql = format!(
				"SELECT {SUMMARY_COLUMNS} FROM messages WHERE account_id = ?1
				 AND pk IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?2)
				 ORDER BY received_at DESC LIMIT ?3"
			);
			let mut stmt = conn.prepare_cached(&sql)?;
			let rows = stmt.query_map(params![account_id, fts, limit], summary_from_row)?;
			Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
		})
	}

	pub fn summary(&self, account_id: &str, message_id: &str) -> Result<Option<MessageSummary>> {
		self.read(|conn| {
			let sql = format!("SELECT {SUMMARY_COLUMNS} FROM messages WHERE account_id = ?1 AND id = ?2");
			Ok(conn.query_row(&sql, params![account_id, message_id], summary_from_row).optional()?)
		})
	}

	pub fn local_count_in_mailbox(&self, account_id: &str, mailbox_id: &str) -> Result<u32> {
		self.count(account_id, &Folder::Mailbox { id: mailbox_id.to_string() }, false)
	}

	/// Upserts server rows. Messages with a queued keyword change or move keep
	/// their local `seen`/`flagged`/`mailbox_id` until the queue flushes, so a
	/// sync never flickers an action the user just took.
	pub fn upsert_messages(&self, account_id: &str, rows: &[StoredMessage]) -> Result<()> {
		self.write(|conn| {
			let tx = conn.transaction()?;
			{
				let mut upsert = tx.prepare_cached(
					"INSERT INTO messages (account_id, id, thread_id, mailbox_id, from_name, from_email, subject, preview,
					 	received_at, seen, flagged, has_attachment, size, to_display)
					 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?15)
					 ON CONFLICT (account_id, id) DO UPDATE SET thread_id = excluded.thread_id,
					 	from_name = excluded.from_name, from_email = excluded.from_email, subject = excluded.subject,
					 	preview = excluded.preview, received_at = excluded.received_at,
					 	mailbox_id = CASE WHEN ?14 THEN messages.mailbox_id ELSE excluded.mailbox_id END,
					 	seen = CASE WHEN ?14 THEN messages.seen ELSE excluded.seen END,
					 	flagged = CASE WHEN ?14 THEN messages.flagged ELSE excluded.flagged END,
					 	has_attachment = excluded.has_attachment, size = excluded.size, to_display = excluded.to_display
					 WHERE messages.thread_id IS NOT excluded.thread_id OR messages.mailbox_id IS NOT excluded.mailbox_id
					 	OR messages.subject IS NOT excluded.subject OR messages.preview IS NOT excluded.preview
					 	OR messages.from_name IS NOT excluded.from_name OR messages.received_at IS NOT excluded.received_at
					 	OR messages.seen IS NOT excluded.seen OR messages.flagged IS NOT excluded.flagged
					 	OR messages.has_attachment IS NOT excluded.has_attachment OR messages.to_display IS NOT excluded.to_display",
				)?;
				let mut pending = tx.prepare_cached(
					"SELECT 1 FROM actions WHERE account_id = ?1 AND kind IN ('keywords', 'move') AND payload LIKE ?2 LIMIT 1",
				)?;
				let mut destroying =
					tx.prepare_cached("SELECT 1 FROM actions WHERE account_id = ?1 AND kind = 'destroy' AND payload LIKE ?2 LIMIT 1")?;
				for row in rows {
					let pattern = format!("%\"{}\"%", row.id);
					// Deleted here but not yet on the server: don't resurrect it.
					if destroying.exists(params![account_id, pattern])? {
						continue;
					}
					let has_pending = pending.exists(params![account_id, pattern])?;
					upsert.execute(params![
						account_id,
						row.id,
						row.thread_id,
						row.mailbox_id,
						row.from_name,
						row.from_email,
						row.subject,
						row.preview,
						row.received_at,
						row.seen,
						row.flagged,
						row.has_attachment,
						row.size,
						has_pending,
						row.to_display
					])?;
				}
			}
			tx.commit()?;
			Ok(())
		})
	}

	/// Window diff: drops local rows of `mailbox_id` that the server no longer
	/// lists. `since` bounds the window (rows older than it are outside what the
	/// server returned, so they are kept); `None` means the server listed all.
	pub fn prune_mailbox(&self, account_id: &str, mailbox_id: &str, keep: &[String], since: Option<i64>) -> Result<usize> {
		self.write(|conn| {
			let tx = conn.transaction()?;
			tx.execute("CREATE TEMP TABLE IF NOT EXISTS keep_ids (id TEXT PRIMARY KEY)", [])?;
			tx.execute("DELETE FROM keep_ids", [])?;
			{
				let mut insert = tx.prepare_cached("INSERT OR IGNORE INTO keep_ids (id) VALUES (?1)")?;
				for id in keep {
					insert.execute(params![id])?;
				}
			}
			let removed = tx.execute(
				"DELETE FROM messages WHERE account_id = ?1 AND mailbox_id = ?2 AND received_at >= ?3
				 AND id NOT IN (SELECT id FROM keep_ids)",
				params![account_id, mailbox_id, since.unwrap_or(i64::MIN)],
			)?;
			tx.execute("DELETE FROM keep_ids", [])?;
			tx.commit()?;
			Ok(removed)
		})
	}

	/// Applies a keyword change locally and queues it for the server in one
	/// transaction. Returns the ids that actually changed.
	pub fn apply_keyword(
		&self,
		account_id: &str,
		ids: &[String],
		keyword: &str,
		value: bool,
		client_id: &str,
		payload: &str,
	) -> Result<Vec<String>> {
		let column = match keyword {
			"$seen" => "seen",
			"$flagged" => "flagged",
			_ => return Err(crate::error::CoreError::invalid("Unsupported keyword")),
		};
		self.write(|conn| {
			let tx = conn.transaction()?;
			let mut changed = Vec::new();
			{
				let mut select = tx.prepare_cached(&format!(
					"SELECT mailbox_id FROM messages WHERE account_id = ?1 AND id = ?2 AND {column} != ?3"
				))?;
				let mut update = tx.prepare_cached(&format!("UPDATE messages SET {column} = ?3 WHERE account_id = ?1 AND id = ?2"))?;
				let mut adjust = tx.prepare_cached(
					"UPDATE mailboxes SET unread_emails = max(0, unread_emails + ?3) WHERE account_id = ?1 AND id = ?2",
				)?;
				for id in ids {
					let mailbox: Option<String> = select.query_row(params![account_id, id, value], |row| row.get(0)).optional()?;
					let Some(mailbox) = mailbox else { continue };
					update.execute(params![account_id, id, value])?;
					if column == "seen" {
						adjust.execute(params![account_id, mailbox, if value { -1 } else { 1 }])?;
					}
					changed.push(id.clone());
				}
			}
			if !changed.is_empty() {
				tx.execute(
					"INSERT INTO actions (client_id, account_id, kind, payload, created_at) VALUES (?1, ?2, 'keywords', ?3, ?4)",
					params![client_id, account_id, payload, now()],
				)?;
			}
			tx.commit()?;
			Ok(changed)
		})
	}

	pub fn pending_actions(&self, account_id: &str) -> Result<Vec<PendingAction>> {
		self.read(|conn| {
			let mut stmt =
				conn.prepare_cached("SELECT seq, client_id, kind, payload, attempts, last_error, summary FROM actions WHERE account_id = ?1 ORDER BY seq")?;
			let rows = stmt.query_map(params![account_id], |row| {
				Ok(PendingAction {
					seq: row.get(0)?,
					client_id: row.get(1)?,
					kind: row.get(2)?,
					payload: row.get(3)?,
					attempts: row.get(4)?,
					last_error: row.get(5)?,
					summary: row.get(6)?,
				})
			})?;
			Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
		})
	}

	pub fn complete_action(&self, seq: i64) -> Result<()> {
		self.write(|conn| {
			conn.execute("DELETE FROM actions WHERE seq = ?1", params![seq])?;
			Ok(())
		})
	}

	pub fn fail_action(&self, seq: i64, error: &str) -> Result<()> {
		self.write(|conn| {
			conn.execute(
				"UPDATE actions SET attempts = attempts + 1, last_error = ?2 WHERE seq = ?1",
				params![seq, error],
			)?;
			Ok(())
		})
	}

	// Bodies

	pub fn body(&self, account_id: &str, message_id: &str) -> Result<Option<StoredBody>> {
		self.read(|conn| {
			let row = conn
				.query_row(
					"SELECT html, has_remote_content, to_json, cc_json, reply_to_json, attachments_json, message_id, references_json
					 FROM bodies WHERE account_id = ?1 AND id = ?2",
					params![account_id, message_id],
					|row| {
						Ok((
							row.get::<_, String>(0)?,
							row.get::<_, bool>(1)?,
							row.get::<_, String>(2)?,
							row.get::<_, String>(3)?,
							row.get::<_, String>(4)?,
							row.get::<_, String>(5)?,
							row.get::<_, Option<String>>(6)?,
							row.get::<_, String>(7)?,
						))
					},
				)
				.optional()?;
			Ok(row.map(|(html, has_remote_content, to, cc, reply_to, attachments, message_id, references)| StoredBody {
				html,
				has_remote_content,
				to: serde_json::from_str(&to).unwrap_or_default(),
				cc: serde_json::from_str(&cc).unwrap_or_default(),
				reply_to: serde_json::from_str(&reply_to).unwrap_or_default(),
				attachments: serde_json::from_str(&attachments).unwrap_or_default(),
				message_id,
				references: serde_json::from_str(&references).unwrap_or_default(),
			}))
		})
	}

	pub fn save_body(&self, account_id: &str, message_id: &str, body: &StoredBody) -> Result<()> {
		let to = serde_json::to_string(&body.to)?;
		let cc = serde_json::to_string(&body.cc)?;
		let reply_to = serde_json::to_string(&body.reply_to)?;
		let attachments = serde_json::to_string(&body.attachments)?;
		let references = serde_json::to_string(&body.references)?;
		self.write(|conn| {
			conn.execute(
				"INSERT INTO bodies (account_id, id, html, has_remote_content, to_json, cc_json, reply_to_json, attachments_json,
				 	message_id, references_json, fetched_at)
				 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
				 ON CONFLICT (account_id, id) DO UPDATE SET html = excluded.html, has_remote_content = excluded.has_remote_content,
				 	to_json = excluded.to_json, cc_json = excluded.cc_json, reply_to_json = excluded.reply_to_json,
				 	attachments_json = excluded.attachments_json, message_id = excluded.message_id,
				 	references_json = excluded.references_json, fetched_at = excluded.fetched_at",
				params![
					account_id,
					message_id,
					body.html,
					body.has_remote_content,
					to,
					cc,
					reply_to,
					attachments,
					body.message_id,
					references,
					now()
				],
			)?;
			Ok(())
		})
	}

	pub fn detail(&self, account_id: &str, message_id: &str) -> Result<Option<MessageDetail>> {
		let Some(summary) = self.summary(account_id, message_id)? else { return Ok(None) };
		let Some(body) = self.body(account_id, message_id)? else { return Ok(None) };
		Ok(Some(MessageDetail {
			summary,
			to: body.to,
			cc: body.cc,
			reply_to: body.reply_to,
			html: body.html,
			has_remote_content: body.has_remote_content,
			attachments: body.attachments,
			message_id: body.message_id,
			references: body.references,
		}))
	}
}

/// Milestone 2: identities, moves, deletes and the send/draft outbox.
impl Store {
	pub fn email_state(&self, account_id: &str) -> Result<Option<String>> {
		self.read(|conn| {
			Ok(conn
				.query_row("SELECT email_state FROM accounts WHERE id = ?1", params![account_id], |row| row.get(0))
				.optional()?
				.flatten())
		})
	}

	pub fn set_email_state(&self, account_id: &str, state: Option<&str>) -> Result<()> {
		self.write(|conn| {
			conn.execute("UPDATE accounts SET email_state = ?2 WHERE id = ?1", params![account_id, state])?;
			Ok(())
		})
	}

	pub fn auth_kind(&self, account_id: &str) -> Result<String> {
		self.read(|conn| {
			Ok(conn
				.query_row("SELECT auth_kind FROM accounts WHERE id = ?1", params![account_id], |row| row.get(0))
				.optional()?
				.unwrap_or_else(|| "app_password".into()))
		})
	}

	pub fn set_auth_kind(&self, account_id: &str, kind: &str) -> Result<()> {
		self.write(|conn| {
			conn.execute("UPDATE accounts SET auth_kind = ?2 WHERE id = ?1", params![account_id, kind])?;
			Ok(())
		})
	}

	/// Removes messages the server destroyed.
	pub fn remove_messages(&self, account_id: &str, ids: &[String]) -> Result<usize> {
		self.write(|conn| {
			let tx = conn.transaction()?;
			let mut removed = 0;
			{
				let mut bodies = tx.prepare_cached("DELETE FROM bodies WHERE account_id = ?1 AND id = ?2")?;
				let mut messages = tx.prepare_cached("DELETE FROM messages WHERE account_id = ?1 AND id = ?2")?;
				for id in ids {
					bodies.execute(params![account_id, id])?;
					removed += messages.execute(params![account_id, id])?;
				}
			}
			tx.commit()?;
			Ok(removed)
		})
	}

	/// Refreshes the URLs from a re-fetched session (accounts added before
	/// uploads existed have none).
	pub fn update_session_urls(&self, account_id: &str, api_url: &str, download_url: &str, upload_url: &str) -> Result<()> {
		self.write(|conn| {
			conn.execute(
				"UPDATE accounts SET api_url = ?2, download_url = ?3, upload_url = ?4 WHERE id = ?1",
				params![account_id, api_url, download_url, upload_url],
			)?;
			Ok(())
		})
	}

	/// Addresses seen as senders, best match first, for recipient completion.
	pub fn suggest_contacts(&self, account_id: &str, prefix: &str, limit: u32) -> Result<Vec<EmailAddress>> {
		let prefix = prefix.trim().to_lowercase().replace(['%', '_'], "");
		if prefix.is_empty() {
			return Ok(vec![]);
		}
		self.read(|conn| {
			let mut stmt = conn.prepare_cached(
				"SELECT from_email, max(from_name), count(*) AS uses FROM messages
				 WHERE account_id = ?1 AND from_email != ''
				 	AND (lower(from_email) LIKE ?2 || '%' OR lower(from_name) LIKE ?2 || '%' OR lower(from_name) LIKE '% ' || ?2 || '%')
				 GROUP BY lower(from_email) ORDER BY uses DESC, from_email LIMIT ?3",
			)?;
			let rows = stmt.query_map(params![account_id, prefix, limit], |row| {
				let name: String = row.get(1)?;
				Ok(EmailAddress { email: row.get(0)?, name: (!name.is_empty()).then_some(name) })
			})?;
			Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
		})
	}

	pub fn replace_identities(&self, account_id: &str, identities: &[Identity]) -> Result<()> {
		self.write(|conn| {
			let tx = conn.transaction()?;
			tx.execute("DELETE FROM identities WHERE account_id = ?1", params![account_id])?;
			{
				let mut insert = tx.prepare_cached("INSERT OR REPLACE INTO identities (account_id, id, name, email) VALUES (?1, ?2, ?3, ?4)")?;
				for identity in identities {
					insert.execute(params![account_id, identity.id, identity.name, identity.email])?;
				}
			}
			tx.commit()?;
			Ok(())
		})
	}

	pub fn identities(&self, account_id: &str) -> Result<Vec<Identity>> {
		self.read(|conn| {
			let mut stmt = conn.prepare_cached("SELECT id, name, email FROM identities WHERE account_id = ?1 ORDER BY email")?;
			let rows = stmt.query_map(params![account_id], |row| Ok(Identity { id: row.get(0)?, name: row.get(1)?, email: row.get(2)? }))?;
			Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
		})
	}

	/// The mailbox with `role` that shares `mailbox_id`'s parent (Mailflare
	/// keeps one set of system mailboxes per address).
	pub fn sibling_with_role(&self, account_id: &str, mailbox_id: &str, role: &str) -> Result<Option<String>> {
		self.read(|conn| {
			Ok(conn
				.query_row(
					"SELECT s.id FROM mailboxes m JOIN mailboxes s ON s.account_id = m.account_id
					 	AND s.parent_id IS coalesce(m.parent_id, m.id) AND s.role = ?3
					 WHERE m.account_id = ?1 AND m.id = ?2",
					params![account_id, mailbox_id, role],
					|row| row.get(0),
				)
				.optional()?)
		})
	}

	pub fn mailbox_role(&self, account_id: &str, mailbox_id: &str) -> Result<Option<String>> {
		self.read(|conn| {
			Ok(conn
				.query_row("SELECT role FROM mailboxes WHERE account_id = ?1 AND id = ?2", params![account_id, mailbox_id], |row| row.get(0))
				.optional()?
				.flatten())
		})
	}

	pub fn enqueue(&self, account_id: &str, client_id: &str, kind: &str, payload: &str, summary: &str) -> Result<()> {
		self.write(|conn| {
			conn.execute(
				"INSERT INTO actions (client_id, account_id, kind, payload, summary, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
				params![client_id, account_id, kind, payload, summary, now()],
			)?;
			Ok(())
		})
	}

	/// Persists progress of a multi-step action (uploaded blobs, created draft id)
	/// so a replay resumes instead of repeating server writes.
	pub fn update_action_payload(&self, seq: i64, payload: &str) -> Result<()> {
		self.write(|conn| {
			conn.execute("UPDATE actions SET payload = ?2 WHERE seq = ?1", params![seq, payload])?;
			Ok(())
		})
	}

	pub fn delete_action(&self, account_id: &str, client_id: &str) -> Result<Option<String>> {
		self.write(|conn| {
			let payload: Option<String> = conn
				.query_row("SELECT payload FROM actions WHERE account_id = ?1 AND client_id = ?2", params![account_id, client_id], |row| {
					row.get(0)
				})
				.optional()?;
			conn.execute("DELETE FROM actions WHERE account_id = ?1 AND client_id = ?2", params![account_id, client_id])?;
			Ok(payload)
		})
	}

	pub fn reset_action(&self, account_id: &str, client_id: &str) -> Result<()> {
		self.write(|conn| {
			conn.execute(
				"UPDATE actions SET attempts = 0, last_error = NULL WHERE account_id = ?1 AND client_id = ?2",
				params![account_id, client_id],
			)?;
			Ok(())
		})
	}

	/// Moves messages locally and queues the server move in one transaction.
	/// `moves` pairs message ids with target mailbox ids.
	pub fn apply_move(&self, account_id: &str, moves: &[(String, String)], client_id: &str, payload: &str) -> Result<usize> {
		self.write(|conn| {
			let tx = conn.transaction()?;
			let mut changed = 0;
			{
				let mut select = tx.prepare_cached("SELECT mailbox_id, seen FROM messages WHERE account_id = ?1 AND id = ?2")?;
				let mut update = tx.prepare_cached("UPDATE messages SET mailbox_id = ?3 WHERE account_id = ?1 AND id = ?2")?;
				let mut adjust = tx.prepare_cached(
					"UPDATE mailboxes SET unread_emails = max(0, unread_emails + ?3), total_emails = max(0, total_emails + ?4)
					 WHERE account_id = ?1 AND id = ?2",
				)?;
				for (id, target) in moves {
					let current: Option<(String, bool)> =
						select.query_row(params![account_id, id], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
					let Some((from, seen)) = current else { continue };
					if &from == target {
						continue;
					}
					update.execute(params![account_id, id, target])?;
					let unread = if seen { 0 } else { 1 };
					adjust.execute(params![account_id, from, -unread, -1])?;
					adjust.execute(params![account_id, target, unread, 1])?;
					changed += 1;
				}
			}
			if changed > 0 {
				tx.execute(
					"INSERT INTO actions (client_id, account_id, kind, payload, created_at) VALUES (?1, ?2, 'move', ?3, ?4)",
					params![client_id, account_id, payload, now()],
				)?;
			}
			tx.commit()?;
			Ok(changed)
		})
	}

	/// Deletes messages locally (permanently) and queues the server destroy.
	pub fn apply_destroy(&self, account_id: &str, ids: &[String], client_id: &str, payload: &str) -> Result<usize> {
		self.write(|conn| {
			let tx = conn.transaction()?;
			let mut changed = 0;
			{
				let mut select = tx.prepare_cached("SELECT mailbox_id, seen FROM messages WHERE account_id = ?1 AND id = ?2")?;
				let mut delete = tx.prepare_cached("DELETE FROM messages WHERE account_id = ?1 AND id = ?2")?;
				let mut adjust = tx.prepare_cached(
					"UPDATE mailboxes SET unread_emails = max(0, unread_emails - ?3), total_emails = max(0, total_emails - 1)
					 WHERE account_id = ?1 AND id = ?2",
				)?;
				for id in ids {
					let current: Option<(String, bool)> =
						select.query_row(params![account_id, id], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
					let Some((mailbox, seen)) = current else { continue };
					tx.execute("DELETE FROM bodies WHERE account_id = ?1 AND id = ?2", params![account_id, id])?;
					delete.execute(params![account_id, id])?;
					adjust.execute(params![account_id, mailbox, if seen { 0 } else { 1 }])?;
					changed += 1;
				}
			}
			if changed > 0 {
				tx.execute(
					"INSERT INTO actions (client_id, account_id, kind, payload, created_at) VALUES (?1, ?2, 'destroy', ?3, ?4)",
					params![client_id, account_id, payload, now()],
				)?;
			}
			tx.commit()?;
			Ok(changed)
		})
	}
}

fn migrate(conn: &Connection) -> Result<()> {
	let version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
	if version < 1 {
		conn.execute_batch(&format!("BEGIN; {SCHEMA_V1} PRAGMA user_version = 1; COMMIT;"))?;
	}
	if version < 2 {
		conn.execute_batch(&format!("BEGIN; {SCHEMA_V2} PRAGMA user_version = 2; COMMIT;"))?;
	}
	if version < 3 {
		conn.execute_batch(&format!("BEGIN; {SCHEMA_V3} PRAGMA user_version = 3; COMMIT;"))?;
	}
	if version < 4 {
		conn.execute_batch(&format!("BEGIN; {SCHEMA_V4} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"))?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn message(id: &str, mailbox: &str, received_at: i64) -> StoredMessage {
		StoredMessage {
			id: id.into(),
			thread_id: id.into(),
			mailbox_id: mailbox.into(),
			from_name: "Ann Example".into(),
			from_email: "ann@example.com".into(),
			to_display: String::new(),
			subject: format!("Subject {id}"),
			preview: "Quarterly numbers inside".into(),
			received_at,
			seen: false,
			flagged: false,
			has_attachment: false,
			size: 1,
		}
	}

	fn store() -> (tempfile::TempDir, Store) {
		let dir = tempfile::tempdir().unwrap();
		let store = Store::open(&dir.path().join("t.sqlite")).unwrap();
		store
			.insert_account(NewAccount {
				id: "a",
				email: "me@x.com",
				display_name: "Me",
				server_url: "https://x.com",
				session_url: "https://x.com/jmap/session",
				api_url: "https://x.com/jmap/api",
				download_url: "",
				upload_url: "",
				jmap_account_id: "u1",
			})
			.unwrap();
		let mailbox = |id: &str, role: Option<&str>| Mailbox {
			id: id.into(),
			account_id: "a".into(),
			name: id.into(),
			parent_id: Some("mb".into()),
			role: role.map(str::to_string),
			sort_order: 0,
			total_emails: 0,
			unread_emails: 3,
		};
		store.replace_mailboxes("a", &[mailbox("mb~inbox", Some("inbox")), mailbox("mb~trash", Some("trash"))]).unwrap();
		(dir, store)
	}

	#[test]
	fn pages_newest_first_and_prunes_window() {
		let (_dir, store) = store();
		let rows: Vec<_> = (0..5).map(|i| message(&format!("m{i}"), "mb~inbox", 100 + i)).collect();
		store.upsert_messages("a", &rows).unwrap();
		let inbox = Folder::Role { role: "inbox".into() };
		let page = store.messages("a", &inbox, 0, 2).unwrap();
		assert_eq!(page.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), ["m4", "m3"]);
		// Window covers m2..m4; m3 vanished on the server, m0/m1 are older than the window.
		store.prune_mailbox("a", "mb~inbox", &["m4".into(), "m2".into()], Some(102)).unwrap();
		assert_eq!(store.count("a", &inbox, false).unwrap(), 4);
		assert!(store.summary("a", "m3").unwrap().is_none());
	}

	#[test]
	fn keyword_actions_queue_and_survive_sync() {
		let (_dir, store) = store();
		store.upsert_messages("a", &[message("m1", "mb~inbox", 1)]).unwrap();
		let changed = store.apply_keyword("a", &["m1".into()], "$seen", true, "c1", "{\"ids\":[\"m1\"]}").unwrap();
		assert_eq!(changed, ["m1"]);
		assert_eq!(store.server_unread("a", &Folder::Role { role: "inbox".into() }).unwrap(), 2);
		// A sync that still reports it unseen must not undo the queued change.
		store.upsert_messages("a", &[message("m1", "mb~inbox", 1)]).unwrap();
		assert!(store.summary("a", "m1").unwrap().unwrap().seen);
		assert_eq!(store.pending_actions("a").unwrap().len(), 1);
		// Repeating the same change is a no-op and queues nothing.
		assert!(store.apply_keyword("a", &["m1".into()], "$seen", true, "c2", "{}").unwrap().is_empty());
	}

	#[test]
	fn full_text_search_matches_prefixes() {
		let (_dir, store) = store();
		store.upsert_messages("a", &[message("m1", "mb~inbox", 1), message("m2", "mb~trash", 2)]).unwrap();
		assert_eq!(store.search("a", "quart", 10).unwrap().len(), 2);
		assert_eq!(store.search("a", "subject m2", 10).unwrap().len(), 1);
		assert!(store.search("a", "\"unbalanced", 10).unwrap().is_empty());
	}

	#[test]
	fn deleting_account_cascades() {
		let (_dir, store) = store();
		store.upsert_messages("a", &[message("m1", "mb~inbox", 1)]).unwrap();
		store.delete_account("a").unwrap();
		assert!(store.accounts().unwrap().is_empty());
		assert!(store.summary("a", "m1").unwrap().is_none());
	}

	#[test]
	fn moves_and_deletes_survive_sync_until_flushed() {
		let (_dir, store) = store();
		store.upsert_messages("a", &[message("m1", "mb~inbox", 1), message("m2", "mb~inbox", 2)]).unwrap();
		assert_eq!(store.sibling_with_role("a", "mb~inbox", "trash").unwrap().as_deref(), Some("mb~trash"));
		store.apply_move("a", &[("m1".into(), "mb~trash".into())], "c1", "{\"moves\":{\"m1\":\"mb~trash\"}}").unwrap();
		store.apply_destroy("a", &["m2".into()], "c2", "{\"ids\":[\"m2\"]}").unwrap();
		// The server still reports the old state.
		store.upsert_messages("a", &[message("m1", "mb~inbox", 1), message("m2", "mb~inbox", 2)]).unwrap();
		assert_eq!(store.summary("a", "m1").unwrap().unwrap().mailbox_id, "mb~trash");
		assert!(store.summary("a", "m2").unwrap().is_none());
		// Once flushed, the server's state wins again.
		for action in store.pending_actions("a").unwrap() {
			store.complete_action(action.seq).unwrap();
		}
		store.upsert_messages("a", &[message("m1", "mb~inbox", 1)]).unwrap();
		assert_eq!(store.summary("a", "m1").unwrap().unwrap().mailbox_id, "mb~inbox");
	}
}
