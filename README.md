# pincushion

pincushion is a local Rust CLI for checking a curated package watchlist, comparing new artifact contents against the previous seen version, and writing local JSON/Markdown reports for review.

## Current command

```bash
cargo run -- check --config /path/to/watchlist.yaml
```

## Local verification

```bash
cargo fmt
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
```

## Documentation boundary

This README intentionally stays high-level. Local operator notes, planning, and in-progress design details belong under `.local/` and are kept out of the public project documentation.
