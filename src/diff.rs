#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiffSummary {
    pub files_added: usize,
    pub files_removed: usize,
    pub files_changed: usize,
    pub changed_paths: Vec<String>,
}
