//! Creating, renaming and deleting folders (Gmail calls them labels) on the server.
//!
//! These run online and one at a time: a folder only exists once the server says so, and the
//! mailbox list is re-read afterwards, so the local store never holds a folder the server refused.
//! What each backend can do differs: JMAP (Mailflare) keeps flat folders under an address and
//! moves a deleted folder's mail to Trash; IMAP servers create, rename and delete any folder
//! that is not a system one, and delete the mail inside it (Gmail only removes the label).

use futures::TryStreamExt;
use serde_json::{json, Value};

use crate::error::{CoreError, Result};
use crate::imap::sync::{mailbox_id, mailbox_path, ImapContext, ADDRESS_ID};
use crate::imap::{with_timeout, ImapSession};
use crate::jmap;
use crate::sync::Context;
use crate::types::Mailbox;

/// What an account lets a person do with folders, and how to word it.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FolderSupport {
	pub can_create: bool,
	pub can_rename: bool,
	pub can_delete: bool,
	/// "folder", or "label" on Gmail.
	pub noun: String,
	/// What deleting does to the mail inside, for the confirmation.
	pub delete_note: String,
}

pub fn support(is_imap: bool, incoming_host: &str) -> FolderSupport {
	if !is_imap {
		return FolderSupport {
			can_create: true,
			can_rename: true,
			can_delete: true,
			noun: "folder".into(),
			delete_note: "Messages in it move to Trash.".into(),
		};
	}
	let gmail = incoming_host.trim().eq_ignore_ascii_case("imap.gmail.com");
	FolderSupport {
		can_create: true,
		can_rename: true,
		can_delete: true,
		noun: if gmail { "label" } else { "folder" }.into(),
		delete_note: if gmail {
			"Messages keep their other labels and stay in All Mail.".into()
		} else {
			"The messages in it are deleted too.".into()
		},
	}
}

fn clean_name(name: &str) -> Result<String> {
	let name = name.trim();
	if name.is_empty() {
		return Err(CoreError::invalid("Enter a name."));
	}
	if name.chars().count() > 80 {
		return Err(CoreError::invalid("That name is too long."));
	}
	if name.chars().any(char::is_control) {
		return Err(CoreError::invalid("That name has characters a mail server won't accept."));
	}
	Ok(name.to_string())
}

// MARK: JMAP

fn jmap_failure(result: &Value, section: &str, key: &str) -> Option<CoreError> {
	let failure = result.get(section)?.get(key)?;
	let kind = failure["type"].as_str().unwrap_or("serverFail");
	let description = failure["description"].as_str().unwrap_or_default();
	let message = match kind {
		"mailboxHasEmail" => "The folder still has messages in it.".to_string(),
		"forbidden" if description.is_empty() => "The server doesn't allow that change.".to_string(),
		"notFound" => "That folder no longer exists.".to_string(),
		_ if !description.is_empty() => description.to_string(),
		_ => format!("The server refused the change ({kind})."),
	};
	Some(CoreError::server(message))
}

async fn jmap_set(ctx: &Context<'_>, args: Value) -> Result<Value> {
	let mut args = args;
	args["accountId"] = json!(ctx.account());
	let responses = ctx.call(vec![("Mailbox/set".into(), args, "s".into())]).await?;
	Ok(jmap::response(&responses, "s", "Mailbox/set")?.clone())
}

pub async fn jmap_create(ctx: &Context<'_>, parent_id: Option<&str>, name: &str) -> Result<()> {
	let name = clean_name(name)?;
	// Mailflare keeps folders directly under an address, its one top-level mailbox without a role.
	// A server without one (a generic JMAP server) takes folders at the top.
	let parent = match parent_id {
		Some(id) => Some(id.to_string()),
		None => {
			let all = ctx.store.mailboxes(&ctx.account_id)?;
			all.iter().find(|m| is_address(m, &all)).map(|m| m.id.clone())
		}
	};
	let mut mailbox = json!({ "name": name });
	if let Some(parent) = parent {
		mailbox["parentId"] = json!(parent);
	}
	let result = jmap_set(ctx, json!({ "create": { "new": mailbox } })).await?;
	match jmap_failure(&result, "notCreated", "new") {
		Some(error) => Err(error),
		None => Ok(()),
	}
}

pub async fn jmap_rename(ctx: &Context<'_>, id: &str, name: &str) -> Result<()> {
	let name = clean_name(name)?;
	let result = jmap_set(ctx, json!({ "update": { id: { "name": name } } })).await?;
	match jmap_failure(&result, "notUpdated", id) {
		Some(error) => Err(error),
		None => Ok(()),
	}
}

pub async fn jmap_delete(ctx: &Context<'_>, id: &str) -> Result<()> {
	let result = jmap_set(ctx, json!({ "destroy": [id], "onDestroyRemoveEmails": true })).await?;
	match jmap_failure(&result, "notDestroyed", id) {
		Some(error) => Err(error),
		None => Ok(()),
	}
}

// MARK: IMAP

/// The hierarchy delimiter the server uses ("/" or "."), if folders can nest at all.
async fn delimiter(session: &mut ImapSession) -> Result<Option<String>> {
	let names: Vec<_> = with_timeout(async {
		let stream = session.list(Some(""), Some("")).await?;
		stream.try_collect::<Vec<_>>().await
	})
	.await?
	.map_err(CoreError::from)?;
	Ok(names.first().and_then(|n| n.delimiter()).filter(|d| !d.is_empty()).map(str::to_string))
}

fn check_leaf(name: &str, delimiter: Option<&str>) -> Result<String> {
	let name = clean_name(name)?;
	if let Some(delimiter) = delimiter {
		if name.contains(delimiter) {
			return Err(CoreError::invalid(format!("The name can't contain \"{delimiter}\".")));
		}
	}
	Ok(name)
}

pub async fn imap_create(ctx: &ImapContext<'_>, parent_id: Option<&str>, name: &str) -> Result<()> {
	let mut session = ctx.connect().await?;
	let result = async {
		let delimiter = delimiter(&mut session).await?;
		let leaf = check_leaf(name, delimiter.as_deref())?;
		let path = match parent_id.filter(|id| *id != ADDRESS_ID).and_then(mailbox_path) {
			Some(parent) => format!("{parent}{}{leaf}", delimiter.as_deref().unwrap_or("/")),
			None => leaf,
		};
		with_timeout(session.create(&path)).await?.map_err(CoreError::from)?;
		// Folders a person just made should show up in their mail program too.
		let _ = with_timeout(session.subscribe(&path)).await;
		Ok(())
	}
	.await;
	let _ = session.logout().await;
	result
}

/// Renames the folder in place: same parent, new last segment. Returns the new mailbox id.
pub async fn imap_rename(ctx: &ImapContext<'_>, id: &str, name: &str) -> Result<String> {
	let old = mailbox_path(id).ok_or_else(|| CoreError::invalid("That folder can't be renamed."))?;
	let mut session = ctx.connect().await?;
	let result = async {
		let delimiter = delimiter(&mut session).await?;
		let leaf = check_leaf(name, delimiter.as_deref())?;
		let new = match delimiter.as_deref().and_then(|d| old.rfind(d).map(|at| (at, d.len()))) {
			Some((at, width)) => format!("{}{leaf}", &old[..at + width]),
			None => leaf,
		};
		if new != old {
			with_timeout(session.rename(old, &new)).await?.map_err(CoreError::from)?;
		}
		Ok(mailbox_id(&new))
	}
	.await;
	let _ = session.logout().await;
	result
}

pub async fn imap_delete(ctx: &ImapContext<'_>, id: &str) -> Result<()> {
	let path = mailbox_path(id).ok_or_else(|| CoreError::invalid("That folder can't be deleted."))?;
	let mut session = ctx.connect().await?;
	let result = async {
		let _ = with_timeout(session.unsubscribe(path)).await;
		with_timeout(session.delete(path)).await?.map_err(CoreError::from)
	}
	.await;
	let _ = session.logout().await;
	result
}

/// An account's own top-level mailbox: no parent, no role, and the other mailboxes hang from it.
fn is_address(mailbox: &Mailbox, all: &[Mailbox]) -> bool {
	mailbox.parent_id.is_none() && mailbox.role.is_none() && all.iter().any(|m| m.parent_id.as_deref() == Some(mailbox.id.as_str()))
}

/// A folder a person made: not a system folder and not the account's own top-level mailbox.
pub fn is_user_folder(mailbox: &Mailbox) -> bool {
	mailbox.role.is_none() && mailbox.parent_id.is_some()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn names_are_trimmed_and_checked() {
		assert_eq!(clean_name("  Receipts ").unwrap(), "Receipts");
		assert!(clean_name("   ").is_err());
		assert!(clean_name(&"x".repeat(81)).is_err());
		assert!(clean_name("a\nb").is_err());
		assert!(check_leaf("a/b", Some("/")).is_err());
		assert!(check_leaf("a/b", Some(".")).is_ok());
	}

	#[test]
	fn gmail_calls_them_labels() {
		assert_eq!(support(true, "imap.gmail.com").noun, "label");
		assert_eq!(support(true, "outlook.office365.com").noun, "folder");
		assert_eq!(support(false, "").noun, "folder");
	}

	#[test]
	fn jmap_failures_are_worded() {
		let result = json!({ "notDestroyed": { "x": { "type": "mailboxHasEmail" } } });
		assert!(jmap_failure(&result, "notDestroyed", "x").unwrap().to_string().contains("still has messages"));
		assert!(jmap_failure(&result, "notDestroyed", "y").is_none());
	}
}
