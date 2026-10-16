# mailflare-core

Shared Rust core for the Mailflare mobile apps: JMAP client, window-based sync,
SQLite store (WAL + FTS5), persistent action queue and HTML sanitization,
exposed to Swift and Kotlin through UniFFI.

## Layout

| Path | Contents |
|---|---|
| `src/lib.rs` | `MailCore` (the FFI object), `CredentialStore` and `CoreListener` foreign traits |
| `src/store.rs` | SQLite schema, paged queries, window pruning, action queue |
| `src/jmap.rs` | Session discovery and batched JMAP requests |
| `src/sync.rs` | Mailbox, identity and message window sync, `fetch_older` paging, body loading, server search, blob transfer |
| `src/actions.rs` | Replays the persistent queue: keywords, moves, deletes, draft saves and sends |
| `src/compose.rs` | Reply, reply-all, forward and draft templates; text/plain alternative |
| `src/sanitize.rs` | ammonia-based sanitizer; remote URLs are kept and blocked by the renderer |
| `swift/Sources/MailflareCore` | Generated Swift bindings (committed) |
| `Package.swift` | Swift package the iOS app depends on (`../mailflare-core`) |

## Build

```bash
cargo test                      # unit tests, no network
scripts/build-ios.sh            # XCFramework (device + simulator) and Swift bindings
scripts/build-ios.sh --debug    # faster, unoptimized
```

`build/` is not committed; run the script after cloning and after any change to
the exported API.

End-to-end checks against a running server (for example `npm run dev` in `../mailflare`):

```bash
MAILFLARE_EMAIL=you@example.com MAILFLARE_KEY=ep_… MAILFLARE_SERVER=http://localhost:3000 cargo run --example smoke
MAILFLARE_EMAIL=you@example.com MAILFLARE_KEY=ep_… MAILFLARE_SERVER=http://localhost:3000 cargo run --example actions
```

`actions` saves a draft with an attachment, downloads it back, sends it to the
account's own address, archives and restores an inbox message, and trashes then
deletes the sent copy.

## Behaviour notes

- Mailflare answers `*/changes` with `cannotCalculateChanges`, so `sync` re-queries the newest 200 messages per leaf mailbox and diffs ids inside that window. `fetch_older` pages in 100 more from the server.
- Mailflare's top-level mailbox per address aggregates its children; only role and folder mailboxes are synced so mail is not filed twice. `Folder::Role` lists span every address of the account.
- Every write (`set_seen`, `set_flagged`, `move_messages`, `delete_messages`, `save_draft`, `send`) applies locally and enqueues an action in one transaction; the queue is replayed before every sync and survives restarts. A sync never overwrites a row with a queued change, and never resurrects a row deleted locally.
- Sends and draft saves run in recorded steps (uploads, the draft, the submission) so a replay resumes after the last finished step. Mailflare deletes a draft once it is submitted, so a submission retried after a lost response is recognised as already sent. Actions that keep failing stop after 5 attempts and wait in `outbox()` for `retry_outbox_item` or `discard_outbox_item`.
- Mailflare's `Email/set` only creates drafts and only accepts uploaded blobs as attachments, so forwarding downloads the original attachments and uploads them again.
- `delete_messages` moves to Trash; from Trash or Drafts it deletes permanently (Mailflare's `destroy` semantics).
- Plain `http://` is accepted only for loopback hosts.
