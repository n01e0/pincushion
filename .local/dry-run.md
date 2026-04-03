# local dry-run

Use this as the operator-side dry-run checklist. Keep it under `.local/` so the public README stays high-level.

## sample watchlist

The sample watchlist for local testing lives at `.local/sample-watchlist.yaml`.

## dry-run steps

```bash
cargo run -- check --config .local/sample-watchlist.yaml
```

## clean verification pass

```bash
cargo fmt
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
```

## what to look for
- First run should initialize `.pincushion/seen.json` and stop at baseline-only output.
- Later runs should summarize changed / unchanged / newly tracked packages.
- Reports should be written under `.pincushion/reports/` when package updates are processed.
- Nonzero exit codes should only appear for suspicious results or partial failures.
