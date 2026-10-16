//! Composer support: reply/forward templates, quoting and the text/plain
//! alternative derived from the HTML body.

use crate::sanitize;
use crate::types::{ComposeTemplate, EmailAddress, Identity, MessageDetail, OutgoingAttachment, ReplyKind};

const QUOTE_CLASS: &str = "mailflare-quote";

fn escape(text: &str) -> String {
	text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn display(address: &EmailAddress) -> String {
	match &address.name {
		Some(name) => format!("{name} <{}>", address.email),
		None => address.email.clone(),
	}
}

fn same_address(a: &str, b: &str) -> bool {
	a.trim().eq_ignore_ascii_case(b.trim())
}

/// Adds `prefix` ("Re:" / "Fwd:") unless the subject already starts with it.
pub fn prefixed_subject(prefix: &str, subject: &str) -> String {
	let trimmed = subject.trim();
	let lower = trimmed.to_ascii_lowercase();
	let known: &[&str] = if prefix == "Re:" { &["re:"] } else { &["fwd:", "fw:"] };
	if known.iter().any(|p| lower.starts_with(p)) {
		trimmed.to_string()
	} else if trimmed.is_empty() {
		prefix.to_string()
	} else {
		format!("{prefix} {trimmed}")
	}
}

fn local_date(unix_seconds: i64) -> String {
	use chrono::TimeZone;
	match chrono::Local.timestamp_opt(unix_seconds, 0).single() {
		Some(date) => date.format("%a, %b %-d, %Y at %-I:%M %p").to_string(),
		None => String::new(),
	}
}

fn without(list: Vec<EmailAddress>, excluded: &[String]) -> Vec<EmailAddress> {
	let mut seen: Vec<String> = excluded.to_vec();
	list.into_iter()
		.filter(|a| {
			let key = a.email.to_ascii_lowercase();
			if seen.iter().any(|s| same_address(s, &key)) {
				return false;
			}
			seen.push(key);
			true
		})
		.collect()
}

/// The identity a reply should come from: the address the message was sent
/// to, else the address owning the message's mailbox, else the first one.
pub fn reply_identity(message: &MessageDetail, identities: &[Identity]) -> Option<String> {
	let recipients: Vec<&EmailAddress> = message.to.iter().chain(&message.cc).collect();
	if let Some(identity) = identities.iter().find(|i| recipients.iter().any(|r| same_address(&r.email, &i.email))) {
		return Some(identity.id.clone());
	}
	let mailbox = message.summary.mailbox_id.split('~').next().unwrap_or_default();
	identities
		.iter()
		.find(|i| crate::actions::identity_mailbox(&i.id) == mailbox)
		.or(identities.first())
		.map(|i| i.id.clone())
}

pub fn template(message: &MessageDetail, kind: ReplyKind, identities: &[Identity]) -> ComposeTemplate {
	let summary = &message.summary;
	let sender = EmailAddress {
		name: (!summary.from_name.is_empty()).then(|| summary.from_name.clone()),
		email: summary.from_email.clone(),
	};
	let identity_id = reply_identity(message, identities);
	let own: Vec<String> = identities.iter().map(|i| i.email.to_ascii_lowercase()).collect();
	let mut references = message.references.clone();
	if let Some(id) = &message.message_id {
		if !references.contains(id) {
			references.push(id.clone());
		}
	}
	let date = local_date(summary.received_at);

	match kind {
		ReplyKind::Reply | ReplyKind::ReplyAll => {
			let primary = if message.reply_to.is_empty() { vec![sender.clone()] } else { message.reply_to.clone() };
			// Replying to your own sent message goes to its recipients.
			let from_self = own.iter().any(|o| same_address(o, &summary.from_email));
			let mut to = if from_self { message.to.clone() } else { primary };
			let mut cc = Vec::new();
			if kind == ReplyKind::ReplyAll {
				to.extend(message.to.iter().cloned());
				cc = message.cc.clone();
			}
			let to = without(to, &own);
			let excluded: Vec<String> = own.iter().cloned().chain(to.iter().map(|a| a.email.to_ascii_lowercase())).collect();
			let cc = without(cc, &excluded);
			let header = format!("On {date}, {} wrote:", escape(&display(&sender)));
			ComposeTemplate {
				identity_id,
				to,
				cc,
				bcc: vec![],
				subject: prefixed_subject("Re:", &summary.subject),
				body_html: String::new(),
				quoted_html: format!(
					"<div class=\"{QUOTE_CLASS}\"><p>{header}</p><blockquote style=\"margin:0 0 0 0.8ex;border-left:1px solid #ccc;padding-left:1ex\">{}</blockquote></div>",
					message.html
				),
				in_reply_to: message.message_id.clone(),
				references,
				attachments: vec![],
				replaces_draft_id: None,
			}
		}
		ReplyKind::Forward => {
			let mut lines = vec![
				"---------- Forwarded message ---------".to_string(),
				format!("From: {}", escape(&display(&sender))),
				format!("Date: {date}"),
				format!("Subject: {}", escape(&summary.subject)),
			];
			if !message.to.is_empty() {
				lines.push(format!("To: {}", escape(&message.to.iter().map(display).collect::<Vec<_>>().join(", "))));
			}
			if !message.cc.is_empty() {
				lines.push(format!("Cc: {}", escape(&message.cc.iter().map(display).collect::<Vec<_>>().join(", "))));
			}
			ComposeTemplate {
				identity_id,
				to: vec![],
				cc: vec![],
				bcc: vec![],
				subject: prefixed_subject("Fwd:", &summary.subject),
				body_html: String::new(),
				quoted_html: format!("<div class=\"{QUOTE_CLASS}\"><p>{}</p>{}</div>", lines.join("<br>"), message.html),
				in_reply_to: None,
				references: vec![],
				attachments: message
					.attachments
					.iter()
					.map(|a| OutgoingAttachment {
						file_path: None,
						blob_id: Some(a.blob_id.clone()),
						name: a.name.clone().unwrap_or_else(|| "attachment".into()),
						mime_type: a.mime_type.clone(),
						size: a.size,
					})
					.collect(),
				replaces_draft_id: None,
			}
		}
	}
}

/// A stored draft reopened in the composer.
pub fn draft_template(message: &MessageDetail, identities: &[Identity]) -> ComposeTemplate {
	ComposeTemplate {
		// A draft comes from its sender, not its recipients.
		identity_id: identities
			.iter()
			.find(|i| same_address(&i.email, &message.summary.from_email))
			.map(|i| i.id.clone())
			.or_else(|| reply_identity(message, identities)),
		to: message.to.clone(),
		cc: message.cc.clone(),
		bcc: vec![],
		subject: message.summary.subject.clone(),
		body_html: message.html.clone(),
		quoted_html: String::new(),
		in_reply_to: None,
		references: message.references.clone(),
		attachments: message
			.attachments
			.iter()
			.map(|a| OutgoingAttachment {
				file_path: None,
				blob_id: Some(a.blob_id.clone()),
				name: a.name.clone().unwrap_or_else(|| "attachment".into()),
				mime_type: a.mime_type.clone(),
				size: a.size,
			})
			.collect(),
		replaces_draft_id: Some(message.summary.id.clone()),
	}
}

/// The HTML part as sent: sanitized, so nothing the editor let through
/// (pasted scripts, handlers) reaches recipients.
pub fn document_body(html: &str) -> String {
	sanitize::sanitize_html(html)
}

/// A readable text/plain alternative for an HTML body.
pub fn html_to_text(html: &str) -> String {
	let mut out = String::with_capacity(html.len());
	let mut chars = html.chars().peekable();
	let mut skip_content: Option<String> = None;
	while let Some(c) = chars.next() {
		if c != '<' {
			if skip_content.is_none() {
				out.push(c);
			}
			continue;
		}
		let mut tag = String::new();
		for t in chars.by_ref() {
			if t == '>' {
				break;
			}
			tag.push(t);
		}
		let lower = tag.trim().to_ascii_lowercase();
		let closing = lower.starts_with('/');
		let name: String = lower.trim_start_matches('/').chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
		if let Some(skipped) = &skip_content {
			if closing && &name == skipped {
				skip_content = None;
			}
			continue;
		}
		match name.as_str() {
			"style" | "script" | "head" | "title" if !closing => skip_content = Some(name),
			"br" => out.push('\n'),
			"p" | "div" | "tr" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "table" | "ul" | "ol" => {
				if !out.ends_with('\n') && !out.is_empty() {
					out.push('\n');
				}
				if name == "li" && !closing {
					out.push_str("• ");
				}
			}
			"blockquote" if !out.ends_with('\n') && !out.is_empty() => out.push('\n'),
			"td" | "th" if closing => out.push('\t'),
			_ => {}
		}
	}
	let decoded = decode_entities(&out);
	// Collapse runs of blank lines.
	let mut result = String::new();
	let mut blank = 0;
	for line in decoded.lines() {
		let line = line.trim_end();
		if line.trim().is_empty() {
			blank += 1;
			if blank > 1 {
				continue;
			}
		} else {
			blank = 0;
		}
		result.push_str(line.trim_start_matches([' ', '\t']));
		result.push('\n');
	}
	result.trim().to_string()
}

fn decode_entities(text: &str) -> String {
	let mut out = String::with_capacity(text.len());
	let mut rest = text;
	while let Some(index) = rest.find('&') {
		out.push_str(&rest[..index]);
		rest = &rest[index..];
		let Some(end) = rest.find(';').filter(|&e| e <= 10) else {
			out.push('&');
			rest = &rest[1..];
			continue;
		};
		let entity = &rest[1..end];
		let decoded = match entity {
			"amp" => Some('&'),
			"lt" => Some('<'),
			"gt" => Some('>'),
			"quot" => Some('"'),
			"apos" | "#39" => Some('\''),
			"nbsp" => Some(' '),
			_ if entity.starts_with("#x") || entity.starts_with("#X") => u32::from_str_radix(&entity[2..], 16).ok().and_then(char::from_u32),
			_ if entity.starts_with('#') => entity[1..].parse().ok().and_then(char::from_u32),
			_ => None,
		};
		match decoded {
			Some(c) => {
				out.push(c);
				rest = &rest[end + 1..];
			}
			None => {
				out.push('&');
				rest = &rest[1..];
			}
		}
	}
	out.push_str(rest);
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::types::{Attachment, MessageSummary};

	fn detail() -> MessageDetail {
		MessageDetail {
			summary: MessageSummary {
				id: "m1".into(),
				thread_id: "t1".into(),
				mailbox_id: "mbx~inbox".into(),
				from_name: "Ann".into(),
				from_email: "ann@x.com".into(),
				to_display: String::new(),
				subject: "Plans".into(),
				preview: String::new(),
				received_at: 1_767_323_045,
				seen: true,
				flagged: false,
				has_attachment: true,
			},
			to: vec![EmailAddress { name: None, email: "me@y.com".into() }, EmailAddress { name: None, email: "bob@x.com".into() }],
			cc: vec![EmailAddress { name: None, email: "cat@x.com".into() }, EmailAddress { name: None, email: "ME@y.com".into() }],
			reply_to: vec![],
			html: "<p>Hi</p>".into(),
			has_remote_content: false,
			attachments: vec![Attachment { blob_id: "att~1".into(), name: Some("a.pdf".into()), mime_type: "application/pdf".into(), size: 3 }],
			message_id: Some("abc@x.com".into()),
			references: vec!["root@x.com".into()],
		}
	}

	fn identities() -> Vec<Identity> {
		vec![
			Identity { id: "other~other@y.com".into(), name: String::new(), email: "other@y.com".into() },
			Identity { id: "mbx~me@y.com".into(), name: "Me".into(), email: "me@y.com".into() },
		]
	}

	#[test]
	fn reply_targets_sender_from_matching_identity() {
		let t = template(&detail(), ReplyKind::Reply, &identities());
		assert_eq!(t.identity_id.as_deref(), Some("mbx~me@y.com"));
		assert_eq!(t.to.iter().map(|a| a.email.as_str()).collect::<Vec<_>>(), ["ann@x.com"]);
		assert_eq!(t.subject, "Re: Plans");
		assert_eq!(t.in_reply_to.as_deref(), Some("abc@x.com"));
		assert_eq!(t.references, ["root@x.com", "abc@x.com"]);
	}

	#[test]
	fn reply_all_drops_own_addresses_and_duplicates() {
		let t = template(&detail(), ReplyKind::ReplyAll, &identities());
		assert_eq!(t.to.iter().map(|a| a.email.as_str()).collect::<Vec<_>>(), ["ann@x.com", "bob@x.com"]);
		assert_eq!(t.cc.iter().map(|a| a.email.as_str()).collect::<Vec<_>>(), ["cat@x.com"]);
	}

	#[test]
	fn forward_carries_attachments() {
		let t = template(&detail(), ReplyKind::Forward, &identities());
		assert_eq!(t.subject, "Fwd: Plans");
		assert_eq!(t.attachments[0].blob_id.as_deref(), Some("att~1"));
		assert!(t.to.is_empty());
		assert_eq!(prefixed_subject("Fwd:", "FW: x"), "FW: x");
	}

	#[test]
	fn text_alternative() {
		let text = html_to_text("<style>p{}</style><p>Hello&nbsp;<b>world</b></p><p>a &amp; b<br>c</p><ul><li>one</li></ul>");
		assert_eq!(text, "Hello world\na & b\nc\n• one");
	}
}
