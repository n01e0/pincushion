# pincushion

パッケージレジストリのバージョン変更を監視し、アーティファクトの中身をバージョン間で比較して、サプライチェーンリスクのシグナルを検出し、レビュー用のJSON/Markdownレポートを生成するローカルRust CLIツール。

[English README](README.md)

## 対応エコシステム

| エコシステム | レジストリ |
|-------------|-----------|
| npm | registry.npmjs.org |
| RubyGems | rubygems.org |
| PyPI | pypi.org |
| crates.io | crates.io |

## インストール

```bash
cargo build --release
```

バイナリは `target/release/pincushion` に生成されます。

## 使い方

```
pincushion check --config <path>
pincushion --help
```

### ウォッチリスト設定

監視するパッケージと、任意のレビューバックエンドをYAMLファイルで定義します:

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

各エコシステムセクションは省略可能ですが、最低1つのパッケージが必要です。未知のフィールドはエラーになります。

### チェックの実行

```bash
pincushion check --config watchlist.yaml
```

**初回実行**では、現在のバージョンをベースラインとして記録して終了します。分析は行われません。

**2回目以降**は、レジストリの最新バージョンを保存済みのベースラインと比較し、バージョン変更があったパッケージごとに以下を実行します:

1. レジストリから新旧のアーティファクトをダウンロード
2. tar.gz/zip を展開（パストラバーサル防止・サイズ制限付き）
3. 全ファイルのSHA-256ダイジェストを含むインベントリを生成
4. 新旧インベントリを比較し、追加・削除・変更されたファイルを特定
5. サプライチェーンリスクシグナルをスキャン
6. レビューバックエンド（Codex/Claude Code）による自動トリアージ（任意）
7. `.pincushion/reports/` にJSONレポートとMarkdownレポートを出力

### 検出シグナル

pincushionは、エコシステム固有のマニフェストやファイル内容から以下のリスク指標を検出します:

- `install-script-added` / `install-script-changed` — install/postinstallフックの追加・変更
- `gem-extension-added` / `gem-executables-changed` — gemのネイティブ拡張・実行ファイルの変更
- `dependency-added` / `dependency-removed` / `dependency-source-changed` — 依存関係の変更
- `entrypoint-changed` — main/moduleエントリポイントの移動・書き換え
- `binary-added` / `executable-added` — バイナリファイルや実行ファイルの追加
- `build-script-changed` — build.rs（crates）等のビルドスクリプトの変更
- `obfuscated-js-added` — ソース不明な難読化/minify済みJavaScript
- `suspicious-python-loader-added` — 動的コードローディングパターン（exec, eval, importlibの悪用等）
- `large-encoded-blob-added` — 閾値を超えるbase64/hexエンコード済みペイロード
- `network-process-env-access-added` — ネットワーク呼び出し、child_process、環境変数アクセスの新規追加

### レビューバックエンド

`review.provider` で自動レビューを制御します:

| プロバイダ | 説明 |
|-----------|------|
| `none` | 自動レビューなし。レポートは `needs-review` として手動トリアージ対象になります。 |
| `codex` | diff情報を `codex exec` に送信し、構造化JSONのverdictを取得します。 |
| `claude-code` | diff情報を `claude --print` に送信し、構造化JSONのverdictを取得します。 |

レビューバックエンドが失敗した場合、pincushionは **fail-closed** ポリシーを適用します。該当パッケージは高信頼度で `suspicious` とマークされ、人間によるレビューが担保されます。

### レポート出力

レポートは `.pincushion/reports/<ecosystem>/<package>/<old>-<new>.{json,md}` に出力されます。

JSONレポートは自動化用の構造化フィールドを含みます:

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

Markdownレポートは人間が読める形式で、マニフェストのdiffやフラグされたファイルの注釈付きコード抜粋を含みます。

### 状態ディレクトリ

pincushionはウォッチリスト設定と同じディレクトリに `.pincushion/` を作成します:

```
.pincushion/
├── seen.json       # バージョンベースライン (ecosystem:package → version)
├── artifacts/      # ダウンロードしたパッケージアーカイブ
├── unpacked/       # 展開済みファイルツリー
└── reports/        # 生成されたJSON/Markdownレポート
```

### 終了コード

| コード | 意味 |
|-------|------|
| 0 | 全パッケージ解決済み、疑わしい発見なし |
| 10 | 疑わしいパッケージを検出 |
| 20 | 部分的な失敗（一部のレジストリ問い合わせが失敗） |

### ダウンロード安全性

アーティファクトのダウンロード時には以下を強制します:

- HTTPS接続のみ
- ホストの許可リスト（レジストリドメインのみ）
- リダイレクト上限（デフォルト: 5回）
- タイムアウト（デフォルト: 30秒）
- 最大ダウンロードサイズ（デフォルト: 50 MB）

アーカイブの展開時には以下を強制します:

- 最大ファイル数（デフォルト: 10,000）
- 最大合計サイズ（デフォルト: 512 MB）
- 最大単一ファイルサイズ（デフォルト: 64 MB）
- 絶対パスおよびパストラバーサルの拒否

## 開発

```bash
cargo fmt                                     # フォーマット
cargo check                                   # 型チェック
cargo test                                    # 全テスト実行
cargo test <test_name>                        # 単一テスト実行
cargo clippy --all-targets -- -D warnings     # lint
```
