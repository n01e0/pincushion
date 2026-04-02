use crate::diff::SuspiciousExcerpt;
use crate::signals::Signal;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReviewVerdict {
    Benign,
    Suspicious,
    #[default]
    NeedsReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Confidence {
    #[default]
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReviewSummary {
    pub files_added: usize,
    pub files_removed: usize,
    pub files_changed: usize,
    pub signals: Vec<Signal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReviewInput {
    pub ecosystem: String,
    pub package: String,
    pub old_version: String,
    pub new_version: String,
    pub summary: ReviewSummary,
    pub manifest_diff: Option<String>,
    pub interesting_files: Vec<SuspiciousExcerpt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReviewOutput {
    pub verdict: ReviewVerdict,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
    pub focus_files: Vec<String>,
}
