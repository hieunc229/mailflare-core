//! HTML sanitization for message bodies. The output keeps layout (tables,
//! inline styles, `<style>` blocks) but drops scripts, event handlers, forms
//! and frames. Remote URLs survive; the renderer blocks them.

use std::collections::HashSet;
use std::sync::OnceLock;

fn cleaner() -> &'static ammonia::Builder<'static> {
	static CLEANER: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
	CLEANER.get_or_init(|| {
		let mut builder = ammonia::Builder::default();
		builder
			.rm_clean_content_tags(["style"])
			.add_tags(["style", "center", "font", "span", "div", "img", "hr", "br", "u", "s", "small", "big", "caption", "col", "colgroup"])
			.add_generic_attributes([
				"style", "class", "align", "valign", "width", "height", "bgcolor", "color", "border", "cellpadding",
				"cellspacing", "dir", "face", "size", "background",
			])
			.add_tag_attributes("img", ["src", "alt", "width", "height"])
			.url_schemes(HashSet::from(["http", "https", "mailto", "tel", "cid", "data"]))
			.link_rel(Some("noopener noreferrer"))
			.strip_comments(true);
		builder
	})
}

pub fn sanitize_html(html: &str) -> String {
	cleaner().clean(html).to_string()
}

pub fn text_to_html(text: &str) -> String {
	let escaped = text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
	format!("<div style=\"white-space: pre-wrap; word-wrap: break-word\">{escaped}</div>")
}

/// Whether rendering would load anything over the network.
pub fn has_remote_content(html: &str) -> bool {
	let lower = html.to_ascii_lowercase();
	["src=\"http", "src='http", "src=http", "url(http", "url('http", "url(\"http", "background=\"http", "@import"]
		.iter()
		.any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn strips_scripts_and_handlers() {
		let out = sanitize_html("<div onclick=\"x()\" style=\"color:red\">Hi<script>alert(1)</script></div>");
		assert!(!out.contains("script"));
		assert!(!out.contains("onclick"));
		assert!(out.contains("color:red"));
	}

	#[test]
	fn keeps_style_blocks() {
		let out = sanitize_html("<style>p{color:red}</style><p>x</p>");
		assert!(out.contains("p{color:red}"));
	}

	#[test]
	fn detects_remote_images() {
		assert!(has_remote_content(&sanitize_html("<img src=\"https://t.example/p.gif\">")));
		assert!(!has_remote_content(&sanitize_html("<p>plain</p>")));
	}
}
