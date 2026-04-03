# first monitored package set

Chosen initial set for the first real local baseline:

- npm: `react`
- npm: `chalk`
- rubygems: `rails`
- pypi: `requests`

`crates:clap` was left out of the first set for now because the current crates.io lookup returned `403 Forbidden` during local baseline work, so this initial baseline keeps the first monitored set green and repeatable.

## baseline command

```bash
cargo run -- check --config .local/first-monitored/watchlist.yaml
```

## expected result

- First run should create `.local/first-monitored/.pincushion/seen.json`.
- The run should end in baseline-only mode with the selected package versions recorded.
