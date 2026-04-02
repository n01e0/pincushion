#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchlistConfig {
    pub npm: Vec<String>,
    pub rubygems: Vec<String>,
    pub pypi: Vec<String>,
    pub crates: Vec<String>,
    pub review: ReviewConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReviewConfig {
    pub provider: ReviewProvider,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReviewProvider {
    #[default]
    None,
    Codex,
    ClaudeCode,
}
