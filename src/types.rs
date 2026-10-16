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
	/// Recipients for display ("Maya Chen, bob"), shown in Sent and Drafts.
	pub to_display: String,
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
	/// Message-ID without angle brackets, for replies.
	pub message_id: Option<String>,
	pub references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum CoreEvent {
	MailboxesChanged { account_id: String },
	OutboxChanged { account_id: String },
	/// A queued send reached the server.
	MessageSent { account_id: String, subject: String },
	MessagesChanged { account_id: String },
	SyncStarted { account_id: String },
	SyncFinished { account_id: String, error: Option<String> },
}

/// An address the account may send from.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct Identity {
	pub id: String,
	pub name: String,
	pub email: String,
}

/// An attachment of an outgoing message: a local file the app hands over
/// (copied into the core's outbox, so the original may be deleted), or a
/// server blob to carry over when forwarding.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct OutgoingAttachment {
	pub file_path: Option<String>,
	pub blob_id: Option<String>,
	pub name: String,
	pub mime_type: String,
	pub size: u64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct OutgoingMessage {
	pub identity_id: String,
	pub to: Vec<EmailAddress>,
	pub cc: Vec<EmailAddress>,
	pub bcc: Vec<EmailAddress>,
	pub subject: String,
	/// The body as HTML; the plain-text part is derived from it.
	pub html: String,
	pub in_reply_to: Option<String>,
	pub references: Vec<String>,
	pub attachments: Vec<OutgoingAttachment>,
	/// A server draft this message replaces; it is deleted once this one is stored.
	pub replaces_draft_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, uniffi::Enum)]
pub enum ReplyKind {
	Reply,
	ReplyAll,
	Forward,
}

/// A prefilled composer for a reply, reply-all, forward or opened draft.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ComposeTemplate {
	pub identity_id: Option<String>,
	pub to: Vec<EmailAddress>,
	pub cc: Vec<EmailAddress>,
	pub bcc: Vec<EmailAddress>,
	pub subject: String,
	/// The editable part of the body (empty for replies and forwards).
	pub body_html: String,
	/// Quoted original, appended below the editable body when sending.
	pub quoted_html: String,
	pub in_reply_to: Option<String>,
	pub references: Vec<String>,
	pub attachments: Vec<OutgoingAttachment>,
	pub replaces_draft_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum MoveTarget {
	/// The mailbox with this role next to each message's current one.
	Role { role: String },
	Mailbox { id: String },
}

#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum OutboxKind {
	Send,
	Draft,
}

/// A queued send or draft save, for the Outbox view.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct OutboxItem {
	pub client_id: String,
	pub kind: OutboxKind,
	pub subject: String,
	pub recipients: String,
	pub attempts: u32,
	pub error: Option<String>,
	/// True once automatic retries stopped; the user can retry or discard it.
	pub stalled: bool,
}

/// The result of a password sign-in: done, or a second factor is needed.
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum PasswordSignIn {
	SignedIn { account: Account },
	/// Ask for a TOTP or recovery code, then call `complete_mfa` with these values.
	MfaRequired { challenge_token: String, server_url: String },
}

#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum PushEnvironment {
	Production,
	Sandbox,
}

/// An APNs registration. `public_key` is the device's P-256 key (raw
/// uncompressed point, base64) that previews are encrypted to.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct PushRegistration {
	pub token: String,
	pub environment: PushEnvironment,
	pub topic: String,
	pub public_key: Option<String>,
	pub previews: bool,
}
