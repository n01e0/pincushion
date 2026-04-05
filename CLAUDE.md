# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is pincushion

パッケージウォッチリストに基づいてレジストリの最新バージョンを取得し、前回との差分を比較するローカルRust CLI。

現状の `check` 実行経路は latest version lookup + baseline/change detection + `seen.json` 更新まで。artifact download / unpack / diff / signal / review / report のモジュールはあるが、まだ `check` から end-to-end ではつながっていない。

## Build & Test Commands

```bash
cargo check                          # 型チェック
cargo test                           # 全テスト実行
cargo test <test_name>               # 単一テスト実行
cargo fmt                            # フォーマット
cargo clippy --all-targets -- -D warnings  # lint
```

## Architecture

### Pipeline flow

`check --config <watchlist.yaml>` が唯一のサブコマンド。

**現状の `check` 実行経路** は次の 1-3:

1. **config** (`config.rs`) — YAML watchlist をパース。`npm`, `rubygems`, `pypi`, `crates` のパッケージリストと `review.provider` (none/codex/claude-code) を持つ
2. **registry** (`registry/`) — 各エコシステムのレジストリAPIから最新バージョンを取得。`Registry` trait で `latest_version`, `download_artifact`, `unpack` を定義。具象実装は `npm.rs`, `rubygems.rs`, `pypi.rs`, `crates.rs`
3. **state** (`state.rs`) — `StateLayout` が `.pincushion/` 配下の状態ディレクトリを管理。`seen.json` で前回のバージョンを記録し、`ChangeDetection` で変更/未変更/新規追跡を判定。初回実行はbaseline-onlyモード

**未接続だが存在する target pipeline 部品** は 4-10:

4. **fetch** (`fetch.rs`) — `DownloadPolicy` (HTTPS強制、ホスト制限、リダイレクト上限) に従ってアーティファクトをダウンロード
5. **unpack** (`unpack.rs`) — tar.gz/zip を `UnpackLimits` (ファイル数・サイズ上限) に従って展開。パストラバーサル防止あり
6. **inventory** (`inventory.rs`) — 展開済みファイルのエントリリスト (パス、サイズ、SHA256ダイジェスト) を生成
7. **diff** (`diff.rs`) — 旧バージョンと新バージョンの `InventorySummary` を比較し、追加/削除/変更パスと疑わしい箇所の抜粋を生成
8. **signals** (`signals.rs`) — エコシステム固有のリスクシグナル検出 (install script追加、依存変更、バイナリ追加、難読化JS、エンコード済みblob等)
9. **review** (`review.rs`) — `ReviewBackend` が codex/claude-code CLI を子プロセスとして呼び出し、JSON形式の verdict を取得。失敗時は fail-closed (suspicious扱い)
10. **report** (`report.rs`) — JSON と Markdown の2形式でレポートを `.pincushion/reports/` に書き出す

実装ギャップの完了条件は、`check` 自体から 4 ecosystem 全部で fetch -> unpack -> diff が通ること。個別モジュールやfixture test だけでは完了扱いにしない。

### Key abstractions

- `Registry` trait — エコシステムごとのレジストリ操作を抽象化。テストでは `FakeRegistry` で差し替え
- `RegistryPipeline` / `RegistryAdapters` — 全エコシステムのレジストリを束ねて一括 lookup
- `artifact_pipeline` — changed package を shared に `download_artifact -> unpack -> inventory -> diff` へ流す staging layer。`ArtifactWorkspace` と `RegistryPipeline::process_version_changes(...)` を提供する
- `Reviewer` trait + `CodexCommandRunner` / `ClaudeCodeCommandRunner` trait — レビューバックエンドとプロセス実行を分離し、テストでfakeに差し替え可能
- `execute_check_with_lookup` — メインのチェックロジック。`lookup_latest_versions` をクロージャで受け取りテスト時にfake lookupを注入

### Implementation note for fetch/unpack/diff tasks

`artifact_pipeline.rs` は E1-1 の shared path で、現時点では CLI の `check` 実行経路にはまだ接続していない。`download_artifact` / `unpack` の ecosystem 実装が揃う前に `check` へ無理につなぐと runtime regression になりやすいので、段階タスクではまず shared pipeline と focused test を伸ばし、`check` wiring は後続タスクで行う。

### State directory layout

watchlist.yaml と同じディレクトリに `.pincushion/` が作られる:
- `seen.json` — 前回の `{ecosystem}:{package}` → version マッピング
- `artifacts/` — ダウンロードしたアーティファクト
- `unpacked/` — 展開済みファイル
- `reports/` — 生成されたJSON/Markdownレポート

### Exit codes

- 0: partial lookup failure のない正常終了
- 10: diff パイプラインが `check` に接続された後の suspicious package 用に予約
- 20: 一部のパッケージ lookup に失敗 (partial failure)

## Testing patterns

- テストフィクスチャは `tests/fixtures/` に配置。`config/`, `registry/`, `state/`, `e2e/` のサブディレクトリで分類
- ゴールデンファイルは `tests/golden/` (reports, review-input)
- 各モジュールは `#[cfg(test)] mod tests` でユニットテストを持つ
- `TestFixture` / `TestDir` パターンでテンポラリディレクトリを作成し、`Drop` で自動クリーンアップ
- 外部依存のテストは trait を通じた fake 実装で差し替え (FakeRegistry, FakeCodexRunner 等)
