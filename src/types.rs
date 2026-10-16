//! Records and enums shared with the UI. Rows are deliberately flat and small:
//! the UI pages through them and never holds a whole mailbox.

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct Account {
	pub id: String,
	pub email: String,
	pub display_name: String,
	pub server_url: String,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct Mailbox {
	pub id: String,
	pub account_id: String,
	pub name: String,
	pub parent_id: Option<String>,
	/// RFC 8621 role (`inbox`, `sent`, `drafts`, `archive`, `junk`, `trash`), if any.
	pub role: Option<String>,
	pub sort_order: u32,
	pub total_emails: u32,
	pub unread_emails: u32,
}

/// What a message list shows. `Role` spans every mailbox with that role in the
/// account (a Mailflare user with several addresses has one Inbox per address).
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum Folder {
	Role { role: String },
	Mailbox { id: String },
	Starred,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MessageSummary {
	pub id: String,
	pub thread_id: String,
	pub mailbox_id: String,
	pub from_name: String,
	pub from_email: String,
	pub subject: String,
	pub preview: String,
	/// Unix seconds.
	pub received_at: i64,
	pub seen: bool,
	pub flagged: bool,
	pub has_attachment: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct EmailAddress {
	pub name: Option<String>,
	pub email: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct Attachment {
	pub blob_id: String,
	pub name: Option<String>,
	pub mime_type: String,
	pub size: u64,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MessageDetail {
	pub summary: MessageSummary,
	pub to: Vec<EmailAddress>,
	pub cc: Vec<EmailAddress>,
	pub reply_to: Vec<EmailAddress>,
	/// Sanitized HTML: no scripts, handlers or forms. Remote URLs are kept but
	/// must be blocked by the renderer unless the user allows them.
	pub html: String,
	pub has_remote_content: bool,
	pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum CoreEvent {
	MailboxesChanged { account_id: String },
	MessagesChanged { account_id: String },
	SyncStarted { account_id: String },
	SyncFinished { account_id: String, error: Option<String> },
}
