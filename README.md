# pincushion

A local Rust CLI that monitors package registries for version changes, compares artifact contents between versions, detects supply-chain risk signals, and produces JSON/Markdown reports for human review.

[日本語版 README](README_ja.md)

## Supported ecosystems

| Ecosystem | Registry |
|-----------|----------|
| npm | registry.npmjs.org |
| RubyGems | rubygems.org |
| PyPI | pypi.org |
| crates.io | crates.io |

## Installation

```bash
cargo build --release
```

The binary is produced at `target/release/pincushion`.

## Usage

```
pincushion check --config <path>
pincushion --help
```

### Watchlist config

Create a YAML file listing packages to monitor and an optional review backend:

```yaml
npm:
  - react
  - axios
rubygems:
  - rails
pypi:
  - requests
crates:
  - clap
review:
  provider: none        # none | codex | claude-code
```

All ecosystem sections are optional, but at least one package must be listed. Unknown fields are rejected.

### Running a check

```bash
pincushion check --config watchlist.yaml
```

On the **first run**, pincushion records the current versions as a baseline and exits. No analysis is performed.

On **subsequent runs**, pincushion compares the latest registry versions against the saved baseline and, for each version change:

1. Downloads the old and new artifacts from the registry
2. Unpacks them (tar.gz or zip) with path-traversal protection and size limits
3. Inventories all files with SHA-256 digests
4. Diffs the two inventories to find added, removed, and modified files
5. Scans for supply-chain risk signals
6. Optionally sends the diff context to a review backend (Codex or Claude Code) for automated triage
7. Writes a JSON report and a Markdown report to `.pincushion/reports/`

### Detected signals

pincushion looks for the following risk indicators across ecosystem-specific manifests and file contents:

- `install-script-added` / `install-script-changed` — new or modified install/postinstall hooks
- `gem-extension-added` / `gem-executables-changed` — native extension or executable changes in gems
- `dependency-added` / `dependency-removed` / `dependency-source-changed` — dependency list mutations
- `entrypoint-changed` — main/module entrypoint was moved or rewritten
- `binary-added` / `executable-added` — new binary blobs or executable files
- `build-script-changed` — changes to build.rs (crates) or equivalent
- `obfuscated-js-added` — minified/obfuscated JavaScript without a clear source
- `suspicious-python-loader-added` — dynamic code loading patterns (exec, eval, importlib tricks)
- `large-encoded-blob-added` — base64 or hex-encoded payloads above threshold
- `network-process-env-access-added` — new references to network calls, child_process, or environment variable access

### Review backends

The `review.provider` config controls automated review:

| Provider | Description |
|----------|-------------|
| `none` | No automated review. Reports are marked `needs-review` for manual triage. |
| `codex` | Sends diff context to `codex exec` and parses a structured JSON verdict. |
| `claude-code` | Sends diff context to `claude --print` and parses a structured JSON verdict. |

When a review backend fails, pincushion uses a **fail-closed** policy: the package is marked `suspicious` with high confidence to ensure human review.

### Report output

Reports are written to `.pincushion/reports/<ecosystem>/<package>/<old>-<new>.{json,md}`.

JSON reports contain structured fields for automation:

```json
{
  "status": "ok",
  "ecosystem": "npm",
  "package": "react",
  "old_version": "19.0.0",
  "new_version": "19.1.0",
  "summary": { "files_added": 4, "signals": ["install-script-added", ...] },
  "verdict": "suspicious",
  "confidence": "high",
  "reasons": ["install script and dependency changes require review"],
  "focus_files": ["package.json", "scripts/postinstall.js"]
}
```

Markdown reports are human-readable and include manifest diffs and annotated code excerpts from flagged files.

### State directory

pincushion creates a `.pincushion/` directory next to the watchlist config:

```
.pincushion/
├── seen.json       # version baseline (ecosystem:package → version)
├── artifacts/      # downloaded package archives
├── unpacked/       # extracted file trees
└── reports/        # generated JSON and Markdown reports
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All packages resolved, no suspicious findings |
| 10 | Suspicious packages detected |
| 20 | Partial failure (some registry lookups failed) |

### Download safety

Artifact downloads enforce:

- HTTPS-only connections
- Host allowlist (registry domains only)
- Redirect limit (default: 5)
- Timeout (default: 30s)
- Maximum download size (default: 50 MB)

Archive unpacking enforces:

- Maximum file count (default: 10,000)
- Maximum total size (default: 512 MB)
- Maximum single file size (default: 64 MB)
- Absolute path and path-traversal rejection

## Development

```bash
cargo fmt                                     # format
cargo check                                   # type check
cargo test                                    # run all tests
cargo test <test_name>                        # run a single test
cargo clippy --all-targets -- -D warnings     # lint
```
