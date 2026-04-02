use crate::diff::DiffSummary;
use crate::review::ReviewVerdict;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonReport {
    pub status: String,
    pub verdict: ReviewVerdict,
    pub summary: DiffSummary,
}

impl Default for JsonReport {
    fn default() -> Self {
        Self {
            status: String::from("pending"),
            verdict: ReviewVerdict::NeedsReview,
            summary: DiffSummary::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MarkdownReport {
    pub title: String,
    pub body: String,
}
