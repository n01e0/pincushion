# pincushion

A local Rust CLI for monitoring package registries for version changes.

Today, `pincushion check` resolves latest versions, records baseline/change state, and reports which packages changed. The artifact fetch/unpack/diff/review/report pipeline exists in library modules, but it is not fully wired into `check` yet.

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

On **subsequent runs today**, pincushion:

1. Resolves the latest version for each configured package
2. Compares those versions against the saved baseline
3. Prints changed / unchanged / newly tracked packages
4. Updates `.pincushion/seen.json`

The current implementation gap is only considered closed when `pincushion check` itself runs **fetch -> unpack -> diff** for changed packages across **npm, RubyGems, PyPI, and crates.io**. Having those pieces only in standalone modules or tests does not count.

Target full pipeline once that gap is closed:

1. Download the old and new artifacts from the registry
2. Unpack them (tar.gz or zip) with path-traversal protection and size limits
3. Inventory all files with SHA-256 digests
4. Diff the two inventories to find added, removed, and modified files
5. Scan for supply-chain risk signals
6. Optionally send the diff context to a review backend (Codex or Claude Code) for automated triage
7. Write a JSON report and a Markdown report to `.pincushion/reports/`

### Detected signals

These are the signals the full diff pipeline is meant to surface once the artifact path is wired into `check`.

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

Once the artifact diff path is connected to `check`, the `review.provider` config will control automated review:

| Provider | Description |
|----------|-------------|
| `none` | No automated review. Reports are marked `needs-review` for manual triage. |
| `codex` | Sends diff context to `codex exec` and parses a structured JSON verdict. |
| `claude-code` | Sends diff context to `claude --print` and parses a structured JSON verdict. |

When a review backend fails, pincushion uses a **fail-closed** policy: the package is marked `suspicious` with high confidence to ensure human review.

### Report output

Once the artifact diff path is connected to `check`, reports will be written to `.pincushion/reports/<ecosystem>/<package>/<old>-<new>.{json,md}`.

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

pincushion creates a `.pincushion/` directory next to the watchlist config. Today, `seen.json` is the actively used file; the other directories are the intended layout for the artifact pipeline once it is wired into `check`:

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
| 0 | Successful run with no partial lookup failures |
| 10 | Reserved for suspicious packages once the diff pipeline is wired into `check` |
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
