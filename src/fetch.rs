use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadPolicy {
    pub https_only: bool,
    pub max_redirects: usize,
    pub timeout: Duration,
    pub max_bytes: u64,
}

impl Default for DownloadPolicy {
    fn default() -> Self {
        Self {
            https_only: true,
            max_redirects: 5,
            timeout: Duration::from_secs(30),
            max_bytes: 50 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResponse {
    pub final_url: String,
    pub bytes_written: u64,
}
