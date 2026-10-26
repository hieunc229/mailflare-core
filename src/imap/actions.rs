//! Replays the action queue over IMAP and SMTP.
//!
//! Flags, moves and deletes converge to the same state when repeated. A send is
//! different: SMTP gives no way to ask whether a message already went out, so
//! the action records "submission attempted" before it connects and clears the
//! mark only when the server cleanly refused. A replay that finds the mark still
//! set (the app died mid-send) stops and asks the user rather than risk sending twice.

use std::collections::BTreeMap;
use std::path::Path;

use crate::actions::{is_transient, DestroyAction, FlushReport, KeywordAction, MoveAction, Outcome, OutgoingAction, MAX_ATTEMPTS, outbox_dir};
use crate::error::{CoreError, Result};
use crate::imap::sync::{self, mailbox_path, split_message_id, ImapContext};
use crate::imap::{with_timeout, ImapSession};
use crate::smtp;
use crate::store::PendingAction;

/// Providers that file sent mail themselves; appending another copy would duplicate it.
fn files_sent_mail(host: &str) -> bool {
	let host = host.to_ascii_lowercase();
	host.ends_with("gmail.com") || host.ends_with("office365.com") || host.ends_with("outlook.com") || host.ends_with("hotmail.com")
}

fn uid_set(uids: &[u32]) -> String {
	uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
}

/// Message ids grouped by their mailbox, as UID lists.
fn group_by_mailbox<'a>(ids: impl Iterator<Item = &'a String>) -> BTreeMap<String, Vec<u32>> {
	let mut groups: BTreeMap<String, Vec<u32>> = BTreeMap::new();
	for id in ids {
		if let Some((mailbox, uid)) = split_message_id(id) {
			groups.entry(mailbox.to_string()).or_default().push(uid);
		}
	}
	groups
}

async fn select(session: &mut ImapSession, mailbox: &str) -> Result<bool> {
	let Some(path) = mailbox_path(mailbox) else { return Ok(false) };
	Ok(with_timeout(session.select(path)).await?.is_ok())
}

async fn drain<T>(stream: impl futures::Stream<Item = std::result::Result<T, async_imap::error::Error>>) -> Result<()> {
	use futures::TryStreamExt;
	futures::pin_mut!(stream);
	while stream.try_next().await?.is_some() {}
	Ok(())
}

async fn store_flags(session: &mut ImapSession, uids: &[u32], flag: &str, on: bool) -> Result<()> {
	let sign = if on { "+" } else { "-" };
	let query = format!("{sign}FLAGS.SILENT ({flag})");
	with_timeout(async {
		let stream = session.uid_store(uid_set(uids), &query).await?;
		drain(stream).await
	})
	.await?
}

async fn keywords(ctx: &ImapContext<'_>, session: &mut ImapSession, action: &PendingAction) -> Result<Outcome> {
	let Ok(payload) = serde_json::from_str::<KeywordAction>(&action.payload) else { return Ok(Outcome::Done) };
	let flag = match payload.keyword.as_str() {
		"$seen" => "\\Seen",
		"$flagged" => "\\Flagged",
		"$draft" => "\\Draft",
		"$answered" => "\\Answered",
		_ => return Ok(Outcome::Done),
	};
	let _ = ctx;
	for (mailbox, uids) in group_by_mailbox(payload.ids.iter()) {
		// A folder that no longer exists means the message is gone too.
		if !select(session, &mailbox).await? {
			continue;
		}
		store_flags(session, &uids, flag, payload.value).await?;
	}
	Ok(Outcome::Done)
}

async fn expunge(session: &mut ImapSession, uids: &[u32]) -> Result<()> {
	store_flags(session, uids, "\\Deleted", true).await?;
	// UID EXPUNGE removes only these; plain EXPUNGE would take every \Deleted message.
	let uidplus = with_timeout(session.capabilities()).await?.map(|c| c.has_str("UIDPLUS")).unwrap_or(false);
	if uidplus {
		with_timeout(async {
			let stream = session.uid_expunge(uid_set(uids)).await?;
			drain(stream).await
		})
		.await?
	} else {
		with_timeout(async {
			let stream = session.expunge().await?;
			drain(stream).await
		})
		.await?
	}
}

async fn moves(ctx: &ImapContext<'_>, session: &mut ImapSession, action: &PendingAction) -> Result<Outcome> {
	let Ok(payload) = serde_json::from_str::<MoveAction>(&action.payload) else { return Ok(Outcome::Done) };
	let _ = ctx;
	let can_move = with_timeout(session.capabilities()).await?.map(|c| c.has_str("MOVE")).unwrap_or(false);
	// (source mailbox, target mailbox) → uids
	let mut groups: BTreeMap<(String, String), Vec<u32>> = BTreeMap::new();
	for (id, target) in &payload.moves {
		if let Some((mailbox, uid)) = split_message_id(id) {
			groups.entry((mailbox.to_string(), target.clone())).or_default().push(uid);
		}
	}
	let mut failures = Vec::new();
	for ((source, target), uids) in groups {
		let Some(target_path) = mailbox_path(&target) else { continue };
		if !select(session, &source).await? {
			continue;
		}
		let set = uid_set(&uids);
		let result = if can_move {
			with_timeout(session.uid_mv(&set, target_path)).await?.map_err(CoreError::from)
		} else {
			match with_timeout(session.uid_copy(&set, target_path)).await? {
				Ok(()) => expunge(session, &uids).await,
				Err(error) => Err(error.into()),
			}
		};
		if let Err(error) = result {
			if is_transient(&error) {
				return Err(error);
			}
			failures.push(error.to_string());
		}
	}
	Ok(if failures.is_empty() { Outcome::Done } else { Outcome::Failed(failures.join(", ")) })
}

async fn destroy(ctx: &ImapContext<'_>, session: &mut ImapSession, action: &PendingAction) -> Result<Outcome> {
	let Ok(payload) = serde_json::from_str::<DestroyAction>(&action.payload) else { return Ok(Outcome::Done) };
	let _ = ctx;
	for (mailbox, uids) in group_by_mailbox(payload.ids.iter()) {
		if !select(session, &mailbox).await? {
			continue;
		}
		expunge(session, &uids).await?;
	}
	Ok(Outcome::Done)
}

/// The mailbox holding `role`, as `(id, path)`.
fn role_mailbox(ctx: &ImapContext<'_>, role: &str) -> Result<Option<(String, String)>> {
	Ok(ctx
		.store
		.mailboxes(&ctx.account_id)?
		.into_iter()
		.find(|m| m.role.as_deref() == Some(role))
		.and_then(|m| mailbox_path(&m.id).map(|p| (m.id.clone(), p.to_string()))))
}

async fn append(session: &mut ImapSession, path: &str, flags: &str, bytes: &[u8]) -> Result<()> {
	with_timeout(session.append(path, Some(flags), None, bytes)).await?.map_err(CoreError::from)
}

async fn send_or_save(
	ctx: &ImapContext<'_>,
	session: &mut ImapSession,
	action: &PendingAction,
	report: &mut FlushReport,
) -> Result<Outcome> {
	let Ok(mut payload) = serde_json::from_str::<OutgoingAction>(&action.payload) else { return Ok(Outcome::Done) };
	if payload.submit_attempted {
		return Ok(Outcome::Failed(
			"The app stopped while sending this message. It may have been sent: check Sent, then discard this or retry.".into(),
		));
	}
	let identity = ctx
		.store
		.identities(&ctx.account_id)?
		.into_iter()
		.find(|i| i.id == payload.message.identity_id)
		.ok_or_else(|| CoreError::invalid("The address this was written from is gone"))?;

	// Attachments: files the app handed over, or parts of messages being forwarded.
	let mut attachments = Vec::new();
	for attachment in &payload.message.attachments {
		let bytes = if let Some(path) = &attachment.file_path {
			std::fs::read(path).map_err(|e| CoreError::Storage { message: format!("Couldn't read {}: {e}", attachment.name) })?
		} else if let Some(blob) = &attachment.blob_id {
			sync::download_attachment(ctx, blob).await?
		} else {
			continue;
		};
		attachments.push((attachment.name.clone(), attachment.mime_type.clone(), bytes));
	}
	let message = smtp::build_message(&identity, &payload.message, attachments)?;
	let raw = message.formatted();

	if !payload.send {
		let Some((_, drafts)) = role_mailbox(ctx, "drafts")? else {
			return Ok(Outcome::Failed("This account has no Drafts folder.".into()));
		};
		append(session, &drafts, "(\\Draft \\Seen)", &raw).await?;
		delete_replaced(session, &payload).await?;
		report.needs_sync = true;
		return Ok(Outcome::Done);
	}

	payload.submit_attempted = true;
	ctx.store.update_action_payload(action.seq, &serde_json::to_string(&payload)?)?;
	match smtp::send(&ctx.config, &ctx.auth, message).await {
		Ok(()) => {}
		Err(error) => {
			// The server answered: nothing went out, so a retry is safe.
			payload.submit_attempted = false;
			ctx.store.update_action_payload(action.seq, &serde_json::to_string(&payload)?)?;
			return Err(error);
		}
	}
	report.sent.push(payload.message.subject.clone());
	report.needs_sync = true;
	// Best effort from here on: the message is already out.
	if !files_sent_mail(&ctx.config.outgoing.host) {
		if let Ok(Some((_, sent))) = role_mailbox(ctx, "sent") {
			let _ = append(session, &sent, "(\\Seen)", &raw).await;
		}
	}
	let _ = delete_replaced(session, &payload).await;
	Ok(Outcome::Done)
}

/// Removes the draft a saved or sent message replaces.
async fn delete_replaced(session: &mut ImapSession, payload: &OutgoingAction) -> Result<()> {
	let Some(old) = payload.message.replaces_draft_id.as_deref() else { return Ok(()) };
	if let Some((mailbox, uid)) = split_message_id(old) {
		if select(session, mailbox).await? {
			expunge(session, &[uid]).await?;
		}
	}
	Ok(())
}

pub async fn flush(ctx: &ImapContext<'_>, data_dir: &Path) -> Result<FlushReport> {
	let mut report = FlushReport::default();
	let pending: Vec<PendingAction> =
		ctx.store.pending_actions(&ctx.account_id)?.into_iter().filter(|a| a.attempts < MAX_ATTEMPTS).collect();
	if pending.is_empty() {
		return Ok(report);
	}
	let mut session = ctx.connect().await?;
	for action in pending {
		let outgoing = matches!(action.kind.as_str(), "send" | "draft");
		let result = match action.kind.as_str() {
			"keywords" => keywords(ctx, &mut session, &action).await,
			"move" => moves(ctx, &mut session, &action).await,
			"destroy" => destroy(ctx, &mut session, &action).await,
			"send" | "draft" => send_or_save(ctx, &mut session, &action, &mut report).await,
			_ => Ok(Outcome::Failed("Unknown action".into())),
		};
		match result {
			Ok(Outcome::Done) => {
				ctx.store.complete_action(action.seq)?;
				report.flushed += 1;
				if outgoing {
					report.outbox_changed = true;
					report.needs_sync = true;
					let _ = std::fs::remove_dir_all(outbox_dir(data_dir, &action.client_id));
				}
			}
			Ok(Outcome::Failed(message)) => {
				ctx.store.fail_action(action.seq, &message)?;
				report.outbox_changed |= outgoing;
			}
			Err(error) if is_transient(&error) => {
				let _ = session.logout().await;
				return Err(error);
			}
			Err(error) => {
				ctx.store.fail_action(action.seq, &error.to_string())?;
				report.outbox_changed |= outgoing;
			}
		}
	}
	let _ = session.logout().await;
	Ok(report)
}
