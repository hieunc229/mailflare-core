//! Window-based sync. Mailflare answers every `*/changes` with
//! `cannotCalculateChanges`, so each sync re-queries the newest `WINDOW`
//! messages per mailbox and diffs ids locally. Older mail is paged in on
//! demand with `fetch_older`.

use serde_json::{json, Value};

use crate::error::{CoreError, Result};
use crate::jmap::{self, Credentials};
use crate::sanitize;
use crate::store::{AccountEndpoint, StoredBody, StoredMessage, Store};
use crate::types::{Attachment, EmailAddress, Folder, Mailbox, MessageDetail};

/// Newest messages kept in sync per mailbox. Mailflare caps `maxObjectsInGet` at 200.
pub const WINDOW: u32 = 200;
/// Messages per `fetch_older` page.
pub const PAGE: u32 = 100;
/// Two calls per mailbox; Mailflare allows 32 calls per request.
const MAILBOXES_PER_REQUEST: usize = 15;

const SUMMARY_PROPERTIES: [&str; 10] =
	["id", "threadId", "mailboxIds", "keywords", "from", "subject", "preview", "receivedAt", "hasAttachment", "size"];

pub struct Context<'a> {
	pub store: &'a Store,
	pub http: &'a reqwest::Client,
	pub endpoint: AccountEndpoint,
	pub credentials: Credentials,
}

impl Context<'_> {
	async fn call(&self, calls: Vec<(String, Value, String)>) -> Result<Vec<jmap::Invocation>> {
		jmap::request(self.http, &self.endpoint.api_url, &self.credentials, calls).await
	}

	fn account(&self) -> &str {
		&self.endpoint.jmap_account_id
	}
}

fn parse_date(value: &Value) -> i64 {
	value
		.as_str()
		.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
		.map(|d| d.timestamp())
		.unwrap_or(0)
}

fn parse_addresses(value: &Value) -> Vec<EmailAddress> {
	value
		.as_array()
		.map(|list| {
			list.iter()
				.filter_map(|item| {
					let email = item["email"].as_str().unwrap_or_default().to_string();
					let name = item["name"].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
					(!email.is_empty() || name.is_some()).then_some(EmailAddress { name, email })
				})
				.collect()
		})
		.unwrap_or_default()
}

fn keyword(email: &Value, name: &str) -> bool {
	email["keywords"][name].as_bool().unwrap_or(false)
}

/// A summary row from an Email object. `preferred_mailbox` wins when the
/// message is in it; otherwise the first of its `mailboxIds`.
pub fn parse_summary(email: &Value, preferred_mailbox: Option<&str>) -> Option<StoredMessage> {
	let id = email["id"].as_str()?.to_string();
	let mailbox_ids: Vec<&str> =
		email["mailboxIds"].as_object().map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
	let mailbox_id = match preferred_mailbox {
		Some(preferred) if mailbox_ids.contains(&preferred) || mailbox_ids.is_empty() => preferred.to_string(),
		_ => mailbox_ids.first()?.to_string(),
	};
	let from = parse_addresses(&email["from"]);
	let sender = from.first();
	Some(StoredMessage {
		thread_id: email["threadId"].as_str().unwrap_or(&id).to_string(),
		mailbox_id,
		from_name: sender.and_then(|a| a.name.clone()).unwrap_or_default(),
		from_email: sender.map(|a| a.email.clone()).unwrap_or_default(),
		subject: email["subject"].as_str().unwrap_or_default().to_string(),
		preview: email["preview"].as_str().unwrap_or_default().to_string(),
		received_at: parse_date(&email["receivedAt"]),
		seen: keyword(email, "$seen"),
		flagged: keyword(email, "$flagged"),
		has_attachment: email["hasAttachment"].as_bool().unwrap_or(false),
		size: email["size"].as_i64().unwrap_or(0),
		id,
	})
}

fn parse_mailbox(account_id: &str, value: &Value) -> Option<Mailbox> {
	Some(Mailbox {
		id: value["id"].as_str()?.to_string(),
		account_id: account_id.to_string(),
		name: value["name"].as_str().unwrap_or_default().to_string(),
		parent_id: value["parentId"].as_str().map(str::to_string),
		role: value["role"].as_str().map(str::to_string),
		sort_order: value["sortOrder"].as_u64().unwrap_or(0) as u32,
		total_emails: value["totalEmails"].as_u64().unwrap_or(0) as u32,
		unread_emails: value["unreadEmails"].as_u64().unwrap_or(0) as u32,
	})
}

fn query_and_get(ctx: &Context<'_>, tag: &str, filter: Value, position: u32, limit: u32) -> Vec<(String, Value, String)> {
	let query_id = format!("q{tag}");
	vec![
		(
			"Email/query".into(),
			json!({
				"accountId": ctx.account(),
				"filter": filter,
				"sort": [{ "property": "receivedAt", "isAscending": false }],
				"position": position,
				"limit": limit,
				"calculateTotal": true,
			}),
			query_id.clone(),
		),
		(
			"Email/get".into(),
			json!({
				"accountId": ctx.account(),
				"#ids": { "resultOf": query_id, "name": "Email/query", "path": "/ids" },
				"properties": SUMMARY_PROPERTIES,
			}),
			format!("g{tag}"),
		),
	]
}

struct Page {
	ids: Vec<String>,
	total: Option<u64>,
	rows: Vec<StoredMessage>,
}

fn read_page(responses: &[jmap::Invocation], tag: &str, mailbox: Option<&str>) -> Result<Page> {
	let query = jmap::response(responses, &format!("q{tag}"), "Email/query")?;
	let get = jmap::response(responses, &format!("g{tag}"), "Email/get")?;
	let ids = query["ids"].as_array().map(|ids| ids.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
	let rows = get["list"].as_array().map(|list| list.iter().filter_map(|email| parse_summary(email, mailbox)).collect()).unwrap_or_default();
	Ok(Page { ids, total: query["total"].as_u64(), rows })
}

pub async fn sync_mailboxes(ctx: &Context<'_>, account_id: &str) -> Result<Vec<Mailbox>> {
	let responses = ctx.call(vec![("Mailbox/get".into(), json!({ "accountId": ctx.account(), "ids": null }), "m".into())]).await?;
	let list = jmap::response(&responses, "m", "Mailbox/get")?;
	let mailboxes: Vec<Mailbox> =
		list["list"].as_array().map(|items| items.iter().filter_map(|item| parse_mailbox(account_id, item)).collect()).unwrap_or_default();
	ctx.store.replace_mailboxes(account_id, &mailboxes)?;
	Ok(mailboxes)
}

/// Mailboxes that hold messages directly. Mailflare's top-level mailbox per
/// address aggregates its children, so syncing it would double-file mail.
pub fn leaf_mailboxes(mailboxes: &[Mailbox]) -> Vec<&Mailbox> {
	mailboxes.iter().filter(|m| m.role.is_some() || m.parent_id.is_some()).collect()
}

pub async fn sync_messages(ctx: &Context<'_>, account_id: &str, mailboxes: &[Mailbox]) -> Result<()> {
	let leaves = leaf_mailboxes(mailboxes);
	for chunk in leaves.chunks(MAILBOXES_PER_REQUEST) {
		let mut calls = Vec::new();
		for (index, mailbox) in chunk.iter().enumerate() {
			calls.extend(query_and_get(ctx, &index.to_string(), json!({ "inMailbox": mailbox.id }), 0, WINDOW));
		}
		let responses = ctx.call(calls).await?;
		for (index, mailbox) in chunk.iter().enumerate() {
			let page = read_page(&responses, &index.to_string(), Some(&mailbox.id))?;
			ctx.store.upsert_messages(account_id, &page.rows)?;
			let complete = (page.ids.len() as u32) < WINDOW || page.total.is_some_and(|t| t as usize <= page.ids.len());
			let since = if complete { None } else { page.rows.iter().map(|r| r.received_at).min() };
			ctx.store.prune_mailbox(account_id, &mailbox.id, &page.ids, since)?;
		}
	}
	// Starred mail outside the windows above, so the Starred view is complete-ish.
	let responses = ctx.call(query_and_get(ctx, "s", json!({ "hasKeyword": "$flagged" }), 0, WINDOW)).await?;
	let page = read_page(&responses, "s", None)?;
	ctx.store.upsert_messages(account_id, &page.rows)?;
	Ok(())
}

/// Pages older mail into the store. Returns how many rows arrived.
pub async fn fetch_older(ctx: &Context<'_>, account_id: &str, folder: &Folder) -> Result<u32> {
	let mut calls = Vec::new();
	let targets: Vec<Option<String>> = match folder {
		Folder::Starred => vec![None],
		_ => ctx.store.mailbox_ids_for(account_id, folder)?.into_iter().map(Some).collect(),
	};
	for (index, mailbox) in targets.iter().enumerate() {
		let (filter, position) = match mailbox {
			Some(id) => (json!({ "inMailbox": id }), ctx.store.local_count_in_mailbox(account_id, id)?),
			None => (json!({ "hasKeyword": "$flagged" }), ctx.store.count(account_id, folder, false)?),
		};
		calls.extend(query_and_get(ctx, &index.to_string(), filter, position, PAGE));
	}
	if calls.is_empty() {
		return Ok(0);
	}
	let responses = ctx.call(calls).await?;
	let mut fetched = 0;
	for (index, mailbox) in targets.iter().enumerate() {
		let page = read_page(&responses, &index.to_string(), mailbox.as_deref())?;
		fetched += page.rows.len() as u32;
		ctx.store.upsert_messages(account_id, &page.rows)?;
	}
	Ok(fetched)
}

fn body_html(email: &Value, parts_key: &str) -> Option<String> {
	let parts = email[parts_key].as_array()?;
	let values = &email["bodyValues"];
	let mut html = String::new();
	for part in parts {
		let Some(part_id) = part["partId"].as_str() else { continue };
		let Some(value) = values[part_id]["value"].as_str() else { continue };
		match part["type"].as_str().unwrap_or_default() {
			"text/html" => html.push_str(value),
			"text/plain" => html.push_str(&sanitize::text_to_html(value)),
			_ => {}
		}
	}
	(!html.trim().is_empty()).then_some(html)
}

pub async fn load_message(ctx: &Context<'_>, account_id: &str, message_id: &str) -> Result<MessageDetail> {
	let mut properties: Vec<&str> = SUMMARY_PROPERTIES.to_vec();
	properties.extend(["to", "cc", "replyTo", "htmlBody", "textBody", "attachments", "bodyValues"]);
	let responses = ctx
		.call(vec![(
			"Email/get".into(),
			json!({
				"accountId": ctx.account(),
				"ids": [message_id],
				"properties": properties,
				"fetchHTMLBodyValues": true,
				"fetchTextBodyValues": true,
			}),
			"b".into(),
		)])
		.await?;
	let get = jmap::response(&responses, "b", "Email/get")?;
	let email = get["list"].as_array().and_then(|list| list.first()).ok_or_else(|| CoreError::not_found("This message no longer exists"))?;
	let current = ctx.store.summary(account_id, message_id)?;
	let summary = parse_summary(email, current.as_ref().map(|s| s.mailbox_id.as_str())).ok_or_else(|| CoreError::server("Malformed message"))?;
	ctx.store.upsert_messages(account_id, &[summary])?;

	let raw = body_html(email, "htmlBody").or_else(|| body_html(email, "textBody")).unwrap_or_default();
	let html = sanitize::sanitize_html(&raw);
	let attachments = email["attachments"]
		.as_array()
		.map(|parts| {
			parts
				.iter()
				.filter_map(|part| {
					Some(Attachment {
						blob_id: part["blobId"].as_str()?.to_string(),
						name: part["name"].as_str().map(str::to_string),
						mime_type: part["type"].as_str().unwrap_or("application/octet-stream").to_string(),
						size: part["size"].as_u64().unwrap_or(0),
					})
				})
				.collect()
		})
		.unwrap_or_default();
	let body = StoredBody {
		has_remote_content: sanitize::has_remote_content(&html),
		html,
		to: parse_addresses(&email["to"]),
		cc: parse_addresses(&email["cc"]),
		reply_to: parse_addresses(&email["replyTo"]),
		attachments,
	};
	ctx.store.save_body(account_id, message_id, &body)?;
	ctx.store.detail(account_id, message_id)?.ok_or_else(|| CoreError::not_found("This message no longer exists"))
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct KeywordAction {
	pub ids: Vec<String>,
	pub keyword: String,
	pub value: bool,
}

/// Replays queued actions in order. Keyword patches are idempotent, so a
/// replay after a lost response is harmless. Stops at the first transport
/// error and leaves the rest queued.
pub async fn flush_actions(ctx: &Context<'_>, account_id: &str) -> Result<u32> {
	let mut flushed = 0;
	for action in ctx.store.pending_actions(account_id)? {
		if action.kind != "keywords" {
			ctx.store.fail_action(action.seq, "Unknown action")?;
			continue;
		}
		let Ok(payload) = serde_json::from_str::<KeywordAction>(&action.payload) else {
			ctx.store.complete_action(action.seq)?;
			continue;
		};
		let patch_value = if payload.value { json!(true) } else { Value::Null };
		let update: serde_json::Map<String, Value> = payload
			.ids
			.iter()
			.map(|id| (id.clone(), json!({ format!("keywords/{}", payload.keyword): patch_value.clone() })))
			.collect();
		let responses =
			ctx.call(vec![("Email/set".into(), json!({ "accountId": ctx.account(), "update": update }), action.client_id.clone())]).await?;
		match jmap::response(&responses, &action.client_id, "Email/set") {
			Ok(result) => {
				// notFound means the message is gone; nothing left to apply.
				let failed: Vec<String> = result["notUpdated"]
					.as_object()
					.map(|map| {
						map.iter()
							.filter(|(_, err)| err["type"].as_str() != Some("notFound"))
							.map(|(id, err)| format!("{id}: {}", err["type"].as_str().unwrap_or("error")))
							.collect()
					})
					.unwrap_or_default();
				if failed.is_empty() {
					ctx.store.complete_action(action.seq)?;
					flushed += 1;
				} else {
					ctx.store.fail_action(action.seq, &failed.join(", "))?;
				}
			}
			Err(error) => ctx.store.fail_action(action.seq, &error.to_string())?,
		}
	}
	Ok(flushed)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn summary_prefers_queried_mailbox() {
		let email = json!({
			"id": "m1", "threadId": "t1", "mailboxIds": { "a~inbox": true },
			"keywords": { "$seen": true }, "from": [{ "name": "Ann", "email": "ann@x.com" }],
			"subject": "Hi", "preview": "Hello", "receivedAt": "2026-01-02T03:04:05Z", "hasAttachment": false, "size": 10
		});
		let row = parse_summary(&email, Some("a~inbox")).unwrap();
		assert_eq!(row.mailbox_id, "a~inbox");
		assert!(row.seen && !row.flagged);
		assert_eq!(row.from_name, "Ann");
		assert_eq!(row.received_at, 1767323045);
		let moved = parse_summary(&email, Some("a~trash")).unwrap();
		assert_eq!(moved.mailbox_id, "a~inbox");
	}
}
