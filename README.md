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
| `src/sync.rs` | Mailbox + message window sync, `fetch_older` paging, body loading, action replay |
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

End-to-end check against a running server (for example `npm run dev` in `../mailflare`):

```bash
MAILFLARE_EMAIL=you@example.com MAILFLARE_KEY=ep_… MAILFLARE_SERVER=http://localhost:3000 cargo run --example smoke
```

## Behaviour notes

- Mailflare answers `*/changes` with `cannotCalculateChanges`, so `sync` re-queries the newest 200 messages per leaf mailbox and diffs ids inside that window. `fetch_older` pages in 100 more from the server.
- Mailflare's top-level mailbox per address aggregates its children; only role and folder mailboxes are synced so mail is not filed twice. `Folder::Role` lists span every address of the account.
- Keyword changes (`set_seen`, `set_flagged`) apply locally and enqueue an action in one transaction; the queue is replayed before every sync and survives restarts. A sync never overwrites a row with a queued keyword change.
- Plain `http://` is accepted only for loopback hosts.
