//! Replays the persistent action queue against the server.
//!
//! Every action is idempotent on replay:
//! - keyword, move and destroy patches converge to the same state;
//! - sends and draft saves record each finished step (uploaded blobs, the
//!   created draft id, "submission attempted") in the action's payload before
//!   moving on, so a replay resumes after the last step that completed. Mailflare
//!   deletes a draft once it is submitted, so a submission retried after a lost
//!   response finds no draft and is treated as sent, never as a second send.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::compose;
use crate::error::{CoreError, Result};
use crate::jmap;
use crate::store::PendingAction;
use crate::sync::Context;
use crate::types::{EmailAddress, OutboxItem, OutboxKind, OutgoingMessage};

/// Automatic retries per action; after that it waits for the user.
pub const MAX_ATTEMPTS: u32 = 5;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct KeywordAction {
	pub ids: Vec<String>,
	pub keyword: String,
	pub value: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct MoveAction {
	/// Message id → target mailbox id.
	pub moves: BTreeMap<String, String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DestroyAction {
	pub ids: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct OutgoingAction {
	pub message: OutgoingMessage,
	pub send: bool,
	/// Server blob id per attachment once uploaded.
	#[serde(default)]
	pub uploaded: Vec<Option<String>>,
	/// The server draft holding this message once created.
	#[serde(default)]
	pub draft_id: Option<String>,
	#[serde(default)]
	pub submit_attempted: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct OutboxSummary {
	pub subject: String,
	pub recipients: String,
}

impl OutboxSummary {
	pub fn of(message: &OutgoingMessage) -> Self {
		let recipients = message
			.to
			.iter()
			.chain(&message.cc)
			.chain(&message.bcc)
			.map(|a| a.name.clone().unwrap_or_else(|| a.email.clone()))
			.collect::<Vec<_>>()
			.join(", ");
		Self { subject: message.subject.clone(), recipients }
	}
}

pub fn outbox_item(action: &PendingAction) -> Option<OutboxItem> {
	let kind = match action.kind.as_str() {
		"send" => OutboxKind::Send,
		"draft" => OutboxKind::Draft,
		_ => return None,
	};
	let summary: OutboxSummary =
		serde_json::from_str(&action.summary).unwrap_or(OutboxSummary { subject: String::new(), recipients: String::new() });
	Some(OutboxItem {
		client_id: action.client_id.clone(),
		kind,
		subject: summary.subject,
		recipients: summary.recipients,
		attempts: action.attempts,
		error: action.last_error.clone(),
		stalled: action.attempts >= MAX_ATTEMPTS,
	})
}

#[derive(Default)]
pub struct FlushReport {
	pub flushed: u32,
	/// Subjects of messages that were sent.
	pub sent: Vec<String>,
	/// Something changed server-side mailboxes (sent, draft stored), so a sync is due.
	pub needs_sync: bool,
	pub outbox_changed: bool,
}

pub(crate) enum Outcome {
	Done,
	Failed(String),
}

/// Transport and auth failures stop the flush; anything else is charged to the action.
pub(crate) fn is_transient(error: &CoreError) -> bool {
	matches!(error, CoreError::Network { .. } | CoreError::Auth { .. })
}

pub fn outbox_dir(data_dir: &Path, client_id: &str) -> PathBuf {
	data_dir.join("outbox").join(client_id)
}

pub async fn flush(ctx: &Context<'_>, account_id: &str, data_dir: &Path) -> Result<FlushReport> {
	let mut report = FlushReport::default();
	for action in ctx.store.pending_actions(account_id)? {
		if action.attempts >= MAX_ATTEMPTS {
			continue;
		}
		let outgoing = matches!(action.kind.as_str(), "send" | "draft");
		let result = match action.kind.as_str() {
			"keywords" => keywords(ctx, &action).await,
			"move" => moves(ctx, &action).await,
			"destroy" => destroy(ctx, &action).await,
			"send" | "draft" => send_or_save(ctx, &action, data_dir, &mut report).await,
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
			Err(error) if is_transient(&error) => return Err(error),
			Err(error) => {
				ctx.store.fail_action(action.seq, &error.to_string())?;
				report.outbox_changed |= outgoing;
			}
		}
	}
	Ok(report)
}

/// Collects `notUpdated`/`notDestroyed` errors other than `notFound` (the
/// message is already gone, so there is nothing left to apply).
fn set_failures(result: &Value, key: &str) -> Vec<String> {
	result[key]
		.as_object()
		.map(|map| {
			map.iter()
				.filter(|(_, err)| err["type"].as_str() != Some("notFound"))
				.map(|(id, err)| {
					let kind = err["type"].as_str().unwrap_or("error");
					match err["description"].as_str() {
						Some(description) => format!("{id}: {kind} ({description})"),
						None => format!("{id}: {kind}"),
					}
				})
				.collect()
		})
		.unwrap_or_default()
}

async fn email_set(ctx: &Context<'_>, call_id: &str, args: Value) -> Result<Value> {
	let mut args = args;
	args["accountId"] = json!(ctx.endpoint.jmap_account_id);
	let responses = ctx.call(vec![("Email/set".into(), args, call_id.to_string())]).await?;
	Ok(jmap::response(&responses, call_id, "Email/set")?.clone())
}

fn outcome(failures: Vec<String>) -> Outcome {
	if failures.is_empty() {
		Outcome::Done
	} else {
		Outcome::Failed(failures.join(", "))
	}
}

async fn keywords(ctx: &Context<'_>, action: &PendingAction) -> Result<Outcome> {
	let Ok(payload) = serde_json::from_str::<KeywordAction>(&action.payload) else { return Ok(Outcome::Done) };
	let value = if payload.value { json!(true) } else { Value::Null };
	let update: serde_json::Map<String, Value> =
		payload.ids.iter().map(|id| (id.clone(), json!({ format!("keywords/{}", payload.keyword): value.clone() }))).collect();
	let result = email_set(ctx, &action.client_id, json!({ "update": update })).await?;
	Ok(outcome(set_failures(&result, "notUpdated")))
}

async fn moves(ctx: &Context<'_>, action: &PendingAction) -> Result<Outcome> {
	let Ok(payload) = serde_json::from_str::<MoveAction>(&action.payload) else { return Ok(Outcome::Done) };
	let update: serde_json::Map<String, Value> =
		payload.moves.iter().map(|(id, target)| (id.clone(), json!({ "mailboxIds": { target: true } }))).collect();
	let result = email_set(ctx, &action.client_id, json!({ "update": update })).await?;
	Ok(outcome(set_failures(&result, "notUpdated")))
}

async fn destroy(ctx: &Context<'_>, action: &PendingAction) -> Result<Outcome> {
	let Ok(payload) = serde_json::from_str::<DestroyAction>(&action.payload) else { return Ok(Outcome::Done) };
	let result = email_set(ctx, &action.client_id, json!({ "destroy": payload.ids })).await?;
	Ok(outcome(set_failures(&result, "notDestroyed")))
}

fn address_objects(list: &[EmailAddress]) -> Value {
	Value::Array(
		list.iter()
			.map(|a| match &a.name {
				Some(name) => json!({ "name": name, "email": a.email }),
				None => json!({ "email": a.email }),
			})
			.collect(),
	)
}

/// Mailflare identity ids are `<mailboxId>~<address>`.
pub fn identity_mailbox(identity_id: &str) -> &str {
	identity_id.split_once('~').map(|(mailbox, _)| mailbox).unwrap_or(identity_id)
}

async fn send_or_save(ctx: &Context<'_>, action: &PendingAction, data_dir: &Path, report: &mut FlushReport) -> Result<Outcome> {
	let Ok(mut payload) = serde_json::from_str::<OutgoingAction>(&action.payload) else {
		return Ok(Outcome::Failed("This message could not be read back from the outbox".into()));
	};
	let save = |payload: &OutgoingAction| -> Result<()> {
		ctx.store.update_action_payload(action.seq, &serde_json::to_string(payload)?)
	};

	// 1. Uploads. Each finished upload is recorded before the next starts.
	payload.uploaded.resize(payload.message.attachments.len(), None);
	if payload.draft_id.is_none() {
		for index in 0..payload.message.attachments.len() {
			if payload.uploaded[index].is_some() {
				continue;
			}
			let attachment = payload.message.attachments[index].clone();
			let bytes = match (&attachment.file_path, &attachment.blob_id) {
				(Some(path), _) => std::fs::read(path)
					.map_err(|e| CoreError::Storage { message: format!("{} is no longer available: {e}", attachment.name) })?,
				(None, Some(blob_id)) => ctx.download(blob_id, &attachment.name, &attachment.mime_type).await?,
				(None, None) => continue,
			};
			let blob_id = ctx.upload(bytes, &attachment.mime_type, &attachment.name).await?;
			payload.uploaded[index] = Some(blob_id);
			save(&payload)?;
		}
	}

	// 2. The draft.
	if payload.draft_id.is_none() {
		let message = &payload.message;
		let identity = ctx
			.store
			.identities(&ctx.account_id)?
			.into_iter()
			.find(|identity| identity.id == message.identity_id)
			.ok_or_else(|| CoreError::invalid("The sending address is no longer available"))?;
		let mailbox = identity_mailbox(&identity.id);
		let drafts = ctx
			.store
			.sibling_with_role(&ctx.account_id, mailbox, "drafts")?
			.unwrap_or_else(|| format!("{mailbox}~drafts"));
		let html = compose::document_body(&message.html);
		let text = compose::html_to_text(&message.html);
		let attachments: Vec<Value> = message
			.attachments
			.iter()
			.zip(&payload.uploaded)
			.filter_map(|(attachment, blob)| {
				blob.as_ref().map(|blob_id| {
					json!({ "blobId": blob_id, "name": attachment.name, "type": attachment.mime_type, "disposition": "attachment" })
				})
			})
			.collect();
		let from = if identity.name.is_empty() {
			json!([{ "email": identity.email }])
		} else {
			json!([{ "name": identity.name, "email": identity.email }])
		};
		let mut create = json!({
			"mailboxIds": { drafts: true },
			"keywords": { "$draft": true, "$seen": true },
			"from": from,
			"to": address_objects(&message.to),
			"cc": address_objects(&message.cc),
			"bcc": address_objects(&message.bcc),
			"subject": message.subject,
			"textBody": [{ "partId": "t", "type": "text/plain" }],
			"htmlBody": [{ "partId": "h", "type": "text/html" }],
			"bodyValues": { "t": { "value": text }, "h": { "value": html } },
			"attachments": attachments,
		});
		if let Some(reply_to) = &message.in_reply_to {
			create["inReplyTo"] = json!([reply_to]);
		}
		if !message.references.is_empty() {
			create["references"] = json!(message.references);
		}
		let result = email_set(ctx, &action.client_id, json!({ "create": { "d": create } })).await?;
		let Some(id) = result["created"]["d"]["id"].as_str() else {
			let error = &result["notCreated"]["d"];
			let description = error["description"].as_str().or(error["type"].as_str()).unwrap_or("The server refused the message");
			return Ok(Outcome::Failed(description.to_string()));
		};
		payload.draft_id = Some(id.to_string());
		save(&payload)?;
		// The draft now owns the attachment bytes.
		if !payload.send {
			let _ = std::fs::remove_dir_all(outbox_dir(data_dir, &action.client_id));
		}
	}

	// 3. Submission.
	if payload.send {
		let draft_id = payload.draft_id.clone().unwrap_or_default();
		let retried = payload.submit_attempted;
		payload.submit_attempted = true;
		save(&payload)?;
		let call_id = format!("{}-s", action.client_id);
		let responses = ctx
			.call(vec![(
				"EmailSubmission/set".into(),
				json!({
					"accountId": ctx.endpoint.jmap_account_id,
					"create": { "s": { "identityId": payload.message.identity_id, "emailId": draft_id } },
				}),
				call_id.clone(),
			)])
			.await?;
		let result = jmap::response(&responses, &call_id, "EmailSubmission/set")?;
		if result["created"]["s"].is_null() {
			let error = &result["notCreated"]["s"];
			let not_a_draft = error["type"].as_str() == Some("invalidProperties")
				&& error["properties"].as_array().is_some_and(|p| p.iter().any(|v| v == "emailId"));
			// Retried after a lost response: the draft is gone because it was sent.
			if !(retried && not_a_draft) {
				let description = error["description"].as_str().or(error["type"].as_str()).unwrap_or("Sending failed");
				return Ok(Outcome::Failed(description.to_string()));
			}
		}
		report.sent.push(payload.message.subject.clone());
	}

	// 4. The draft this one replaces (an edited draft, or the draft just sent from).
	if let Some(old) = payload.message.replaces_draft_id.clone() {
		if Some(&old) != payload.draft_id.as_ref() {
			let _ = email_set(ctx, &format!("{}-r", action.client_id), json!({ "destroy": [old] })).await;
		}
	}
	Ok(Outcome::Done)
}
