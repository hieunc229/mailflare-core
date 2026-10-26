//! IMAP sync into the shared store. The shape mirrors the JMAP backend: one
//! top-level "address" mailbox per account with every folder beneath it, a
//! window of the newest messages per folder re-read each sync, and older mail
//! paged in on demand.
//!
//! Ids: a mailbox is `m/<path>`; a message is `<mailbox id>:<uid>`. UIDVALIDITY
//! is not tracked, so a server that renumbers a folder needs the account added
//! again.

use std::collections::{HashMap, HashSet};

use async_imap::types::{Flag, NameAttribute};
use futures::TryStreamExt;
use mail_parser::{Address, MessageParser, MimeHeaders};

use crate::compose;
use crate::error::{CoreError, Result};
use crate::imap::{self, with_timeout, ImapSession};
use crate::sanitize;
use crate::store::{StoredBody, StoredMessage, Store};
use crate::sync::{PAGE, WINDOW};
use crate::types::{Attachment, EmailAddress, Folder, Identity, Mailbox, MailServerConfig, MessageDetail, MessageSummary};

/// The top-level mailbox that stands for the account's address.
pub const ADDRESS_ID: &str = "address";
/// Bytes fetched per message for the list: all headers plus the start of the body.
const SUMMARY_BYTES: usize = 6144;
/// The window for a message whose headers did not fit in `SUMMARY_BYTES`.
const LARGE_SUMMARY_BYTES: usize = 256 * 1024;
const UIDS_PER_FETCH: usize = 100;

pub struct ImapContext<'a> {
	pub account_id: String,
	pub store: &'a Store,
	pub email: String,
	pub config: MailServerConfig,
	pub auth: imap::Auth,
}

impl ImapContext<'_> {
	pub async fn connect(&self) -> Result<ImapSession> {
		imap::connect(&self.config, &self.auth).await
	}
}

pub fn mailbox_id(path: &str) -> String {
	format!("m/{path}")
}

pub fn mailbox_path(id: &str) -> Option<&str> {
	id.strip_prefix("m/")
}

pub fn message_id(mailbox_id: &str, uid: u32) -> String {
	format!("{mailbox_id}:{uid}")
}

/// `(mailbox id, uid)` of a message id.
pub fn split_message_id(id: &str) -> Option<(&str, u32)> {
	let (mailbox, uid) = id.rsplit_once(':')?;
	Some((mailbox, uid.parse().ok()?))
}

/// The role of a folder: the server's special-use attribute first, then the
/// names providers commonly use.
pub fn role_for(path: &str, attributes: &[NameAttribute<'_>]) -> Option<&'static str> {
	for attribute in attributes {
		match attribute {
			NameAttribute::Sent => return Some("sent"),
			NameAttribute::Drafts => return Some("drafts"),
			NameAttribute::Trash => return Some("trash"),
			NameAttribute::Junk => return Some("junk"),
			NameAttribute::Archive | NameAttribute::All => return Some("archive"),
			_ => {}
		}
	}
	if path.eq_ignore_ascii_case("INBOX") {
		return Some("inbox");
	}
	let leaf = path.rsplit(['/', '.']).next().unwrap_or(path).to_ascii_lowercase();
	match leaf.as_str() {
		"sent" | "sent items" | "sent mail" | "sent messages" => Some("sent"),
		"drafts" | "draft" => Some("drafts"),
		"trash" | "deleted items" | "deleted messages" | "bin" => Some("trash"),
		"junk" | "spam" | "junk email" | "junk e-mail" | "bulk mail" => Some("junk"),
		"archive" | "archives" | "all mail" => Some("archive"),
		_ => None,
	}
}

fn sort_order(role: Option<&str>) -> u32 {
	match role {
		Some("inbox") => 0,
		Some("drafts") => 1,
		Some("sent") => 2,
		Some("archive") => 3,
		Some("junk") => 4,
		Some("trash") => 5,
		_ => 10,
	}
}

pub async fn sync_mailboxes(ctx: &ImapContext<'_>, session: &mut ImapSession) -> Result<Vec<Mailbox>> {
	struct Folder {
		path: String,
		delimiter: Option<String>,
		role: Option<&'static str>,
	}
	let names: Vec<_> = with_timeout(async {
		let stream = session.list(Some(""), Some("*")).await?;
		stream.try_collect::<Vec<_>>().await
	})
	.await?
	.map_err(CoreError::from)?;
	let mut folders = Vec::new();
	for name in &names {
		let attributes = name.attributes();
		// Folders that only hold other folders, and Gmail's virtual views that
		// repeat mail from elsewhere.
		let skip = attributes.iter().any(|a| matches!(a, NameAttribute::NoSelect | NameAttribute::Flagged))
			|| attributes.iter().any(|a| matches!(a, NameAttribute::Extension(e) if e.eq_ignore_ascii_case("\\Important")));
		if skip {
			continue;
		}
		folders.push(Folder {
			path: name.name().to_string(),
			delimiter: name.delimiter().map(str::to_string),
			role: role_for(name.name(), attributes),
		});
	}
	// One folder per role: a second "Sent" would double-file mail.
	let mut seen_roles = HashSet::new();
	for folder in &mut folders {
		if let Some(role) = folder.role {
			if !seen_roles.insert(role) {
				folder.role = None;
			}
		}
	}

	let mut mailboxes = vec![Mailbox {
		id: ADDRESS_ID.into(),
		account_id: ctx.account_id.clone(),
		name: ctx.email.clone(),
		parent_id: None,
		role: None,
		sort_order: 0,
		total_emails: 0,
		unread_emails: 0,
	}];
	for folder in folders {
		let status = with_timeout(session.status(&folder.path, "(MESSAGES UNSEEN)")).await?.ok();
		let display = match &folder.delimiter {
			Some(delimiter) if !delimiter.is_empty() => folder.path.replace(delimiter.as_str(), " / "),
			_ => folder.path.clone(),
		};
		mailboxes.push(Mailbox {
			id: mailbox_id(&folder.path),
			account_id: ctx.account_id.clone(),
			name: if folder.role == Some("inbox") { "Inbox".into() } else { display },
			parent_id: Some(ADDRESS_ID.into()),
			role: folder.role.map(str::to_string),
			sort_order: sort_order(folder.role),
			total_emails: status.as_ref().map(|s| s.exists).unwrap_or(0),
			unread_emails: status.as_ref().and_then(|s| s.unseen).unwrap_or(0),
		});
	}
	ctx.store.replace_mailboxes(&ctx.account_id, &mailboxes)?;
	ctx.store.replace_identities(
		&ctx.account_id,
		&[Identity { id: "imap".into(), name: String::new(), email: ctx.email.clone() }],
	)?;
	Ok(mailboxes)
}

fn addr_name(address: &mail_parser::Addr<'_>) -> String {
	address.name.as_deref().map(str::trim).unwrap_or_default().to_string()
}

fn first_address(address: Option<&Address<'_>>) -> (String, String) {
	address
		.and_then(|a| a.first())
		.map(|a| (addr_name(a), a.address.as_deref().unwrap_or_default().to_string()))
		.unwrap_or_default()
}

fn address_list(address: Option<&Address<'_>>) -> Vec<EmailAddress> {
	address
		.map(|a| {
			a.iter()
				.filter_map(|item| {
					let email = item.address.as_deref().unwrap_or_default().to_string();
					let name = Some(addr_name(item)).filter(|n| !n.is_empty());
					(!email.is_empty() || name.is_some()).then_some(EmailAddress { name, email })
				})
				.collect()
		})
		.unwrap_or_default()
}

fn one_line(text: &str, max: usize) -> String {
	let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
	collapsed.chars().take(max).collect()
}

/// A summary row from the head of a message (headers and the start of the body).
pub fn parse_summary(
	mailbox: &str,
	uid: u32,
	flags: &[Flag<'_>],
	received_fallback: i64,
	size: i64,
	bytes: &[u8],
) -> StoredMessage {
	let id = message_id(mailbox, uid);
	let parsed = MessageParser::default().parse(bytes);
	let seen = flags.iter().any(|f| matches!(f, Flag::Seen));
	let flagged = flags.iter().any(|f| matches!(f, Flag::Flagged));
	let Some(message) = parsed else {
		return StoredMessage {
			thread_id: id.clone(),
			id,
			mailbox_id: mailbox.into(),
			from_name: String::new(),
			from_email: String::new(),
			to_display: String::new(),
			subject: String::new(),
			preview: String::new(),
			received_at: received_fallback,
			seen,
			flagged,
			has_attachment: false,
			size,
		};
	};
	let (from_name, from_email) = first_address(message.from());
	let to = address_list(message.to());
	let mut to_display = to
		.iter()
		.take(3)
		.map(|a| a.name.clone().unwrap_or_else(|| a.email.split('@').next().unwrap_or_default().to_string()))
		.collect::<Vec<_>>()
		.join(", ");
	if to.len() > 3 {
		to_display.push_str(&format!(" +{}", to.len() - 3));
	}
	let preview_source = message
		.body_text(0)
		.map(|t| t.to_string())
		.or_else(|| message.body_html(0).map(|h| compose::html_to_text(&h)))
		.unwrap_or_default();
	let thread_id = message
		.references()
		.as_text_list()
		.and_then(|list| list.first().map(|s| s.to_string()))
		.or_else(|| message.in_reply_to().as_text().map(str::to_string))
		.or_else(|| message.message_id().map(str::to_string))
		.map(|root| format!("t/{root}"))
		.unwrap_or_else(|| id.clone());
	let has_attachment = message
		.root_part()
		.content_type()
		.map(|ct| ct.ctype().eq_ignore_ascii_case("multipart") && ct.subtype().unwrap_or_default().eq_ignore_ascii_case("mixed"))
		.unwrap_or(false);
	StoredMessage {
		id,
		thread_id,
		mailbox_id: mailbox.into(),
		from_name,
		from_email,
		to_display,
		subject: message.subject().unwrap_or_default().trim().to_string(),
		preview: one_line(&preview_source, 160),
		received_at: message.date().map(|d| d.to_timestamp()).unwrap_or(received_fallback),
		seen,
		flagged,
		has_attachment,
		size,
	}
}

/// True once the header block has ended, i.e. the fetched bytes include the blank line after it.
fn headers_complete(bytes: &[u8]) -> bool {
	bytes.windows(4).any(|w| w == b"\r\n\r\n") || bytes.windows(2).any(|w| w == b"\n\n")
}

/// Fetches summaries for `uids` of the selected mailbox. A message whose headers outrun the
/// summary window (Google's notification mail carries several KB of ARC and DKIM headers ahead of
/// `From` and `Subject`) is fetched again with a much larger one, so it is not stored blank.
async fn fetch_summaries(session: &mut ImapSession, mailbox: &str, uids: &[u32]) -> Result<Vec<StoredMessage>> {
	let mut rows = Vec::with_capacity(uids.len());
	let mut truncated: Vec<u32> = Vec::new();
	fetch_window(session, mailbox, uids, SUMMARY_BYTES, &mut rows, Some(&mut truncated)).await?;
	if !truncated.is_empty() {
		fetch_window(session, mailbox, &truncated, LARGE_SUMMARY_BYTES, &mut rows, None).await?;
	}
	Ok(rows)
}

/// Fetches the first `window` bytes of each message into `rows`. With `truncated` given, a message
/// whose headers did not fit is left out of `rows` and its uid collected there instead.
async fn fetch_window(
	session: &mut ImapSession,
	mailbox: &str,
	uids: &[u32],
	window: usize,
	rows: &mut Vec<StoredMessage>,
	mut truncated: Option<&mut Vec<u32>>,
) -> Result<()> {
	for chunk in uids.chunks(UIDS_PER_FETCH) {
		let set = chunk.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
		let query = format!("(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[]<0.{window}>)");
		let fetched: Vec<_> = with_timeout(async {
			let stream = session.uid_fetch(&set, &query).await?;
			stream.try_collect::<Vec<_>>().await
		})
		.await?
		.map_err(CoreError::from)?;
		for fetch in &fetched {
			let Some(uid) = fetch.uid else { continue };
			let body = fetch.body().unwrap_or_default();
			let size = fetch.size.unwrap_or(0) as usize;
			if let Some(truncated) = truncated.as_deref_mut() {
				if !headers_complete(body) && size > body.len() {
					truncated.push(uid);
					continue;
				}
			}
			let flags: Vec<Flag<'_>> = fetch.flags().collect();
			let received = fetch.internal_date().map(|d| d.timestamp()).unwrap_or(0);
			rows.push(parse_summary(mailbox, uid, &flags, received, size as i64, body));
		}
	}
	Ok(())
}

/// Flags for `uids`, to refresh messages already stored.
async fn fetch_flags(session: &mut ImapSession, uids: &[u32]) -> Result<HashMap<u32, (bool, bool)>> {
	let mut out = HashMap::new();
	for chunk in uids.chunks(UIDS_PER_FETCH * 5) {
		let set = chunk.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
		let fetched: Vec<_> = with_timeout(async {
			let stream = session.uid_fetch(&set, "(UID FLAGS)").await?;
			stream.try_collect::<Vec<_>>().await
		})
		.await?
		.map_err(CoreError::from)?;
		for fetch in &fetched {
			let Some(uid) = fetch.uid else { continue };
			let flags: Vec<Flag<'_>> = fetch.flags().collect();
			out.insert(uid, (flags.iter().any(|f| matches!(f, Flag::Seen)), flags.iter().any(|f| matches!(f, Flag::Flagged))));
		}
	}
	Ok(out)
}

/// Sequence range holding the `count` newest messages after skipping `skip`
/// of the `exists` in the selected folder. Sequence numbers run oldest to
/// newest, so this needs no search over the whole folder.
fn newest_range(exists: u32, skip: u32, count: u32) -> Option<(u32, u32)> {
	let hi = exists.checked_sub(skip).filter(|hi| *hi > 0)?;
	Some((hi.saturating_sub(count - 1).max(1), hi))
}

/// UIDs of the newest `count` messages after skipping `skip`, newest first.
/// One small `FETCH <seq range> (UID)` instead of `UID SEARCH ALL`, which on a
/// folder like Gmail's All Mail returns tens of thousands of UIDs.
async fn newest_uids(session: &mut ImapSession, exists: u32, skip: u32, count: u32) -> Result<Vec<u32>> {
	let Some((lo, hi)) = newest_range(exists, skip, count) else { return Ok(vec![]) };
	let fetched: Vec<_> = with_timeout(async {
		let stream = session.fetch(format!("{lo}:{hi}"), "(UID)").await?;
		stream.try_collect::<Vec<_>>().await
	})
	.await?
	.map_err(CoreError::from)?;
	let mut uids: Vec<u32> = fetched.iter().filter_map(|f| f.uid).collect();
	uids.sort_unstable_by(|a, b| b.cmp(a));
	Ok(uids)
}

/// Re-reads the newest `WINDOW` messages of one folder.
/// Mail older than this is never announced, so an account that was closed for
/// a while does not produce a burst of old notifications.
const NOTIFY_WITHIN_SECS: i64 = 2 * 24 * 3600;

/// Syncs one folder; returns the unread inbox messages that are new since the
/// last sync (empty for the first sync of an account, `announce == false`).
async fn sync_folder(ctx: &ImapContext<'_>, session: &mut ImapSession, mailbox: &Mailbox, announce: bool) -> Result<Vec<StoredMessage>> {
	let Some(path) = mailbox_path(&mailbox.id) else { return Ok(vec![]) };
	let selected = with_timeout(session.select(path)).await?.map_err(CoreError::from)?;
	let window = newest_uids(session, selected.exists, 0, WINDOW).await?;
	let complete = selected.exists <= WINDOW;
	let local: HashSet<String> = ctx.store.message_ids_in_mailbox(&ctx.account_id, &mailbox.id)?.into_iter().collect();

	let (known, new): (Vec<u32>, Vec<u32>) = window.iter().partition(|uid| local.contains(&message_id(&mailbox.id, **uid)));
	let mut rows = fetch_summaries(session, &mailbox.id, &new).await?;
	let arrived: Vec<StoredMessage> = if announce && mailbox.role.as_deref() == Some("inbox") {
		let cutoff = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) - NOTIFY_WITHIN_SECS;
		rows.iter().filter(|r| !r.seen && r.received_at >= cutoff).cloned().collect()
	} else {
		vec![]
	};
	if !known.is_empty() {
		let flags = fetch_flags(session, &known).await?;
		let ids: Vec<String> = known.iter().map(|uid| message_id(&mailbox.id, *uid)).collect();
		let mut blank: Vec<u32> = Vec::new();
		for mut row in ctx.store.stored_messages(&ctx.account_id, &ids)? {
			// Stored blank by an earlier, too-small summary window: read it again below.
			if row.from_email.is_empty() && row.subject.is_empty() && row.preview.is_empty() {
				if let Some((_, uid)) = split_message_id(&row.id) {
					blank.push(uid);
					continue;
				}
			}
			if let Some((_, uid)) = split_message_id(&row.id) {
				if let Some((seen, flagged)) = flags.get(&uid) {
					row.seen = *seen;
					row.flagged = *flagged;
				}
			}
			rows.push(row);
		}
		if !blank.is_empty() {
			rows.extend(fetch_summaries(session, &mailbox.id, &blank).await?);
		}
	}
	ctx.store.upsert_messages(&ctx.account_id, &rows)?;
	let keep: Vec<String> = window.iter().map(|uid| message_id(&mailbox.id, *uid)).collect();
	let since = if complete { None } else { rows.iter().map(|r| r.received_at).min() };
	ctx.store.prune_mailbox(&ctx.account_id, &mailbox.id, &keep, since)?;
	Ok(arrived)
}

/// Extra connections used to sync folders alongside the first one. Gmail
/// allows about 15 per account; the rest of the app needs a few too.
const EXTRA_CONNECTIONS: usize = 3;

fn timing() -> bool {
	std::env::var_os("MAILFLARE_TIMING").is_some()
}

/// Syncs every folder: the inbox first on `session`, reported at once so the
/// app can show it, then the rest spread over a few connections with archive
/// views such as Gmail's All Mail last.
/// `on_new` runs for each unread inbox message that arrived since the previous sync.
pub async fn sync_messages(
	ctx: &ImapContext<'_>,
	session: &mut ImapSession,
	mailboxes: &[Mailbox],
	on_progress: &(dyn Fn() + Sync),
	on_new: &(dyn Fn(&StoredMessage) + Sync),
) -> Result<()> {
	let started = std::time::Instant::now();
	// The first sync of an account fills an empty store; nothing in it is news.
	let announce = mailboxes.iter().filter(|m| m.parent_id.is_some()).any(|m| ctx.store.local_count_in_mailbox(&ctx.account_id, &m.id).unwrap_or(0) > 0);
	let mut folders: Vec<&Mailbox> = mailboxes.iter().filter(|m| m.parent_id.is_some()).collect();
	// Archive views repeat mail from elsewhere and are the largest; they go last.
	folders.sort_by_key(|m| (m.role.as_deref() == Some("archive"), m.sort_order));
	let split = folders.iter().take_while(|m| m.role.as_deref() == Some("inbox")).count();
	let (first, rest) = folders.split_at(split);
	for mailbox in first {
		for message in sync_folder(ctx, session, mailbox, announce).await? {
			on_new(&message);
		}
		on_progress();
		if timing() {
			eprintln!("[imap-sync] {} done at {:?}", mailbox.id, started.elapsed());
		}
	}
	if rest.is_empty() {
		return Ok(());
	}

	let queue = std::sync::Mutex::new(rest.iter().copied().collect::<std::collections::VecDeque<&Mailbox>>());
	let next = || queue.lock().unwrap().pop_front();
	let work = async |session: &mut ImapSession| -> Result<()> {
		while let Some(mailbox) = next() {
			for message in sync_folder(ctx, session, mailbox, announce).await? {
				on_new(&message);
			}
			on_progress();
			if timing() {
				eprintln!("[imap-sync] {} done at {:?}", mailbox.id, started.elapsed());
			}
		}
		Ok(())
	};
	let extra = EXTRA_CONNECTIONS.min(rest.len().saturating_sub(1));
	let mut sessions = futures::future::join_all((0..extra).map(|_| ctx.connect())).await.into_iter().filter_map(|s| s.ok()).collect::<Vec<_>>();
	let (own, others) = {
		let results = futures::future::join(work(session), futures::future::join_all(sessions.iter_mut().map(|s| work(s)))).await;
		results
	};
	for mut session in sessions {
		let _ = session.logout().await;
	}
	own?;
	others.into_iter().collect::<Result<Vec<_>>>()?;
	if timing() {
		eprintln!("[imap-sync] all folders done at {:?}", started.elapsed());
	}
	Ok(())
}

/// A light sync for background wake-ups, which get roughly 30 seconds and
/// should not spend the provider's daily IMAP download or connection quotas:
/// one connection, only the inbox folders already known (no LIST, no STATUS
/// of every label), the newest `WINDOW` UIDs by sequence range and summaries
/// only for messages not yet stored. Falls back to nothing when the account
/// has never had a full sync.
pub async fn sync_inbox_quick(
	ctx: &ImapContext<'_>,
	on_progress: &(dyn Fn() + Sync),
	on_new: &(dyn Fn(&StoredMessage) + Sync),
) -> Result<()> {
	let started = std::time::Instant::now();
	let inboxes: Vec<Mailbox> = ctx.store.mailboxes(&ctx.account_id)?.into_iter().filter(|m| m.role.as_deref() == Some("inbox") && m.parent_id.is_some()).collect();
	if inboxes.is_empty() {
		return Ok(());
	}
	let mut session = ctx.connect().await?;
	let result = async {
		for mailbox in &inboxes {
			// Never announce into an empty store: that is a first sync, not news.
			let announce = ctx.store.local_count_in_mailbox(&ctx.account_id, &mailbox.id)? > 0;
			let Some(path) = mailbox_path(&mailbox.id) else { continue };
			if let Ok(Ok(status)) = with_timeout(session.status(path, "(MESSAGES UNSEEN)")).await {
				ctx.store.set_mailbox_counts(&ctx.account_id, &mailbox.id, status.exists, status.unseen.unwrap_or(0))?;
			}
			for message in sync_folder(ctx, &mut session, mailbox, announce).await? {
				on_new(&message);
			}
			on_progress();
		}
		Ok(())
	}
	.await;
	let _ = session.logout().await;
	if timing() {
		eprintln!("[imap-sync] quick inbox sync took {:?}", started.elapsed());
	}
	result
}

/// Pages older mail of a folder into the store; returns how many arrived.
pub async fn fetch_older(ctx: &ImapContext<'_>, folder: &Folder) -> Result<u32> {
	let targets = match folder {
		Folder::Starred => return Ok(0),
		_ => ctx.store.mailbox_ids_for(&ctx.account_id, folder)?,
	};
	if targets.is_empty() {
		return Ok(0);
	}
	let mut session = ctx.connect().await?;
	let mut fetched = 0;
	for mailbox in targets {
		let Some(path) = mailbox_path(&mailbox) else { continue };
		let selected = with_timeout(session.select(path)).await?.map_err(CoreError::from)?;
		let skip = ctx.store.local_count_in_mailbox(&ctx.account_id, &mailbox)? as u32;
		let page = newest_uids(&mut session, selected.exists, skip, PAGE).await?;
		let rows = fetch_summaries(&mut session, &mailbox, &page).await?;
		fetched += rows.len() as u32;
		ctx.store.upsert_messages(&ctx.account_id, &rows)?;
	}
	let _ = session.logout().await;
	Ok(fetched)
}

/// Server-side text search across the folders.
pub async fn search_server(ctx: &ImapContext<'_>, query: &str, limit: u32) -> Result<Vec<MessageSummary>> {
	let mut session = ctx.connect().await?;
	let quoted = imap::quote(query);
	let mut found = Vec::new();
	let folders: Vec<Mailbox> = ctx.store.mailboxes(&ctx.account_id)?.into_iter().filter(|m| m.parent_id.is_some()).collect();
	for mailbox in folders {
		let Some(path) = mailbox_path(&mailbox.id) else { continue };
		if matches!(mailbox.role.as_deref(), Some("trash") | Some("junk")) {
			continue;
		}
		if with_timeout(session.select(path)).await?.is_err() {
			continue;
		}
		let result = match with_timeout(session.uid_search(format!("CHARSET UTF-8 TEXT {quoted}"))).await? {
			Ok(set) => set,
			Err(_) => with_timeout(session.uid_search(format!("TEXT {quoted}"))).await?.map_err(CoreError::from)?,
		};
		let mut uids: Vec<u32> = result.into_iter().collect();
		uids.sort_unstable_by(|a, b| b.cmp(a));
		uids.truncate(limit as usize);
		let rows = fetch_summaries(&mut session, &mailbox.id, &uids).await?;
		ctx.store.upsert_messages(&ctx.account_id, &rows)?;
		found.extend(rows);
	}
	let _ = session.logout().await;
	found.sort_by(|a, b| b.received_at.cmp(&a.received_at));
	found.truncate(limit as usize);
	let mut results = Vec::with_capacity(found.len());
	for row in found {
		if let Some(summary) = ctx.store.summary(&ctx.account_id, &row.id)? {
			results.push(summary);
		}
	}
	Ok(results)
}

/// The raw message for `id`, fetched with its own connection.
pub async fn fetch_raw(ctx: &ImapContext<'_>, id: &str) -> Result<Vec<u8>> {
	let (mailbox, uid) = split_message_id(id).ok_or_else(|| CoreError::not_found("This message no longer exists"))?;
	let path = mailbox_path(mailbox).ok_or_else(|| CoreError::not_found("This message no longer exists"))?;
	let mut session = ctx.connect().await?;
	with_timeout(session.select(path)).await?.map_err(CoreError::from)?;
	let fetched: Vec<_> = with_timeout(async {
		let stream = session.uid_fetch(uid.to_string(), "(UID BODY.PEEK[])").await?;
		stream.try_collect::<Vec<_>>().await
	})
	.await?
	.map_err(CoreError::from)?;
	let _ = session.logout().await;
	fetched
		.iter()
		.find_map(|f| f.body().map(<[u8]>::to_vec))
		.ok_or_else(|| CoreError::not_found("This message no longer exists"))
}

fn strip_brackets(id: &str) -> String {
	id.trim_matches(['<', '>']).to_string()
}

/// Replaces `cid:` references with data URIs of the parts they name, so inline
/// images render without another fetch.
fn inline_cids(html: String, message: &mail_parser::Message<'_>) -> (String, HashSet<usize>) {
	let mut html = html;
	let mut inlined = HashSet::new();
	for (index, part) in message.attachments().enumerate() {
		let Some(cid) = part.content_id() else { continue };
		let cid = strip_brackets(cid);
		let needle = format!("cid:{cid}");
		if !html.contains(&needle) {
			continue;
		}
		let bytes = part.contents();
		if bytes.len() > 2 * 1024 * 1024 {
			continue;
		}
		let mime = part.content_type().map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("octet-stream"))).unwrap_or_else(|| "application/octet-stream".into());
		use base64::Engine;
		let uri = format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes));
		html = html.replace(&needle, &uri);
		inlined.insert(index);
	}
	(html, inlined)
}

pub async fn load_message(ctx: &ImapContext<'_>, id: &str) -> Result<MessageDetail> {
	let raw = fetch_raw(ctx, id).await?;
	let message = MessageParser::default().parse(&raw).ok_or_else(|| CoreError::server("Couldn't read this message"))?;
	let body = message
		.body_html(0)
		.map(|h| h.to_string())
		.or_else(|| message.body_text(0).map(|t| sanitize::text_to_html(&t)))
		.unwrap_or_default();
	let (body, inlined) = inline_cids(body, &message);
	let html = sanitize::sanitize_html(&body);
	let attachments: Vec<Attachment> = message
		.attachments()
		.enumerate()
		.filter(|(index, _)| !inlined.contains(index))
		.map(|(index, part)| Attachment {
			blob_id: format!("{id}#{index}"),
			name: part.attachment_name().map(str::to_string),
			mime_type: part
				.content_type()
				.map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("octet-stream")))
				.unwrap_or_else(|| "application/octet-stream".into()),
			size: part.contents().len() as u64,
		})
		.collect();
	let stored = StoredBody {
		has_remote_content: sanitize::has_remote_content(&html),
		html,
		to: address_list(message.to()),
		cc: address_list(message.cc()),
		reply_to: address_list(message.reply_to()),
		attachments,
		message_id: message.message_id().map(strip_brackets),
		references: message.references().as_text_list().map(|l| l.iter().map(|s| strip_brackets(s)).collect()).unwrap_or_default(),
	};
	ctx.store.save_body(&ctx.account_id, id, &stored)?;
	ctx.store.detail(&ctx.account_id, id)?.ok_or_else(|| CoreError::not_found("This message no longer exists"))
}

/// Bytes of an attachment named by a `<message id>#<index>` blob id.
pub async fn download_attachment(ctx: &ImapContext<'_>, blob_id: &str) -> Result<Vec<u8>> {
	let (id, index) = blob_id.rsplit_once('#').ok_or_else(|| CoreError::not_found("This attachment is no longer available"))?;
	let index: usize = index.parse().map_err(|_| CoreError::not_found("This attachment is no longer available"))?;
	let raw = fetch_raw(ctx, id).await?;
	let message = MessageParser::default().parse(&raw).ok_or_else(|| CoreError::server("Couldn't read this message"))?;
	let bytes = message.attachments().nth(index).map(|part| part.contents().to_vec());
	bytes.ok_or_else(|| CoreError::not_found("This attachment is no longer available"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn roles_come_from_special_use_then_names() {
		assert_eq!(role_for("INBOX", &[]), Some("inbox"));
		assert_eq!(role_for("[Gmail]/Sent Mail", &[NameAttribute::Sent]), Some("sent"));
		assert_eq!(role_for("Sent Items", &[]), Some("sent"));
		assert_eq!(role_for("INBOX.Trash", &[]), Some("trash"));
		assert_eq!(role_for("Projects", &[]), None);
	}

	#[test]
	fn newest_range_counts_back_from_the_end() {
		assert_eq!(newest_range(0, 0, 50), None);
		assert_eq!(newest_range(30, 0, 50), Some((1, 30)));
		assert_eq!(newest_range(20000, 0, 50), Some((19951, 20000)));
		assert_eq!(newest_range(20000, 50, 50), Some((19901, 19950)));
		assert_eq!(newest_range(60, 50, 50), Some((1, 10)));
		assert_eq!(newest_range(50, 50, 50), None);
	}

	#[test]
	fn long_header_blocks_are_detected_as_cut_off() {
		// Google's notification mail puts ~7 KB of ARC/DKIM headers ahead of From and Subject.
		let mut raw = String::new();
		for i in 0..40 {
			raw.push_str(&format!("X-Filler-{i}: {}\r\n", "a".repeat(170)));
		}
		raw.push_str("From: Google <no-reply@google.com>\r\nSubject: Review your settings\r\nContent-Type: text/plain\r\n\r\nHello\r\n");
		let bytes = raw.as_bytes();
		assert!(bytes.len() > SUMMARY_BYTES);
		let cut = &bytes[..SUMMARY_BYTES];
		assert!(!headers_complete(cut));
		assert_eq!(parse_summary("m/INBOX", 1, &[], 0, 0, cut).subject, "");
		assert!(headers_complete(bytes));
		let row = parse_summary("m/INBOX", 1, &[], 0, 0, bytes);
		assert_eq!((row.from_email.as_str(), row.subject.as_str()), ("no-reply@google.com", "Review your settings"));
		assert_eq!(row.preview, "Hello");
	}

	#[test]
	fn ids_round_trip() {
		let mailbox = mailbox_id("INBOX.Work: 2025");
		let id = message_id(&mailbox, 42);
		assert_eq!(split_message_id(&id), Some((mailbox.as_str(), 42)));
		assert_eq!(mailbox_path(&mailbox), Some("INBOX.Work: 2025"));
	}

	#[test]
	fn summary_reads_headers_and_preview() {
		let raw = b"From: Ann Example <ann@example.com>\r\nTo: bob@example.com, Cy <cy@example.com>\r\nSubject: Quarterly numbers\r\nDate: Thu, 02 Jan 2026 03:04:05 +0000\r\nMessage-ID: <m1@example.com>\r\nContent-Type: text/plain\r\n\r\nHello   Bob,\r\nthe numbers are in.\r\n";
		let row = parse_summary("m/INBOX", 7, &[Flag::Seen], 0, 120, raw);
		assert_eq!(row.id, "m/INBOX:7");
		assert_eq!(row.from_name, "Ann Example");
		assert_eq!(row.from_email, "ann@example.com");
		assert_eq!(row.subject, "Quarterly numbers");
		assert_eq!(row.preview, "Hello Bob, the numbers are in.");
		assert_eq!(row.to_display, "bob, Cy");
		assert_eq!(row.received_at, 1767323045);
		assert!(row.seen && !row.flagged && !row.has_attachment);
	}
}
