use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::LOCATION;
use reqwest::{StatusCode, Url};

use crate::registry::{DownloadedArtifact, PackageVersion};
use crate::state::StateLayout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadPolicy {
    pub https_only: bool,
    pub allowed_hosts: Vec<String>,
    pub max_redirects: usize,
    pub timeout: Duration,
    pub max_bytes: u64,
}

impl Default for DownloadPolicy {
    fn default() -> Self {
        Self {
            https_only: true,
            allowed_hosts: Vec::new(),
            max_redirects: 5,
            timeout: Duration::from_secs(30),
            max_bytes: 50 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub url: String,
    pub artifact_metadata: Option<ArtifactMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMetadata {
    pub filename: String,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResponse {
    pub final_url: String,
    pub bytes_written: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedArtifact {
    pub artifact: DownloadedArtifact,
    pub cache_hit: bool,
}

impl ArtifactMetadata {
    fn validate(&self) -> Result<(), FetchError> {
        let filename = self.filename.trim();
        if filename.is_empty() {
            return Err(FetchError::InvalidArtifactMetadata {
                reason: "artifact filename must not be empty".to_string(),
            });
        }

        if filename.contains('/') || filename.contains('\\') || filename == "." || filename == ".."
        {
            return Err(FetchError::InvalidArtifactMetadata {
                reason: format!("artifact filename `{filename}` must be a plain file name"),
            });
        }

        if let Some(size_bytes) = self.size_bytes {
            if size_bytes == 0 {
                return Err(FetchError::InvalidArtifactMetadata {
                    reason: "artifact size must be greater than zero when provided".to_string(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactCache {
    root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SafeDownloader {
    policy: DownloadPolicy,
    client: Client,
}

impl ArtifactCache {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn from_state_layout(state_layout: &StateLayout) -> Self {
        Self::new(state_layout.artifacts_dir())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path_for(
        &self,
        package_version: &PackageVersion,
        metadata: &ArtifactMetadata,
    ) -> Result<PathBuf, FetchError> {
        metadata.validate()?;
        Ok(self
            .root
            .join(package_version.ecosystem.as_str())
            .join(sanitize_cache_path_component(&package_version.package))
            .join(sanitize_cache_path_component(&package_version.version))
            .join(&metadata.filename))
    }

    pub fn fetch(
        &self,
        downloader: &SafeDownloader,
        package_version: &PackageVersion,
        request: &FetchRequest,
    ) -> Result<CachedArtifact, FetchError> {
        let metadata = request.artifact_metadata.as_ref().ok_or_else(|| {
            FetchError::MissingArtifactMetadata {
                url: request.url.clone(),
            }
        })?;
        let cache_path = self.path_for(package_version, metadata)?;
        downloader.validate_destination_path(&cache_path)?;

        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent).map_err(|source| FetchError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        if let Ok(existing_metadata) = fs::metadata(&cache_path) {
            let size_matches = metadata
                .size_bytes
                .is_none_or(|expected_size| existing_metadata.len() == expected_size);
            if size_matches {
                return Ok(CachedArtifact {
                    artifact: DownloadedArtifact {
                        source_url: Some(request.url.clone()),
                        path: cache_path,
                    },
                    cache_hit: true,
                });
            }

            let _ = fs::remove_file(&cache_path);
        }

        let temporary_path = cache_path.with_extension("partial");
        let response = match downloader.fetch_to_path(request, &temporary_path) {
            Ok(response) => response,
            Err(error) => {
                let _ = fs::remove_file(&temporary_path);
                return Err(error);
            }
        };

        if let Err(source) = fs::rename(&temporary_path, &cache_path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(FetchError::Io {
                path: cache_path.clone(),
                source,
            });
        }

        Ok(CachedArtifact {
            artifact: DownloadedArtifact {
                source_url: Some(response.final_url),
                path: cache_path,
            },
            cache_hit: false,
        })
    }
}

impl SafeDownloader {
    pub fn new(policy: DownloadPolicy) -> Result<Self, FetchError> {
        let client = Client::builder()
            .timeout(policy.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(FetchError::ClientBuild)?;

        Ok(Self { policy, client })
    }

    pub fn policy(&self) -> &DownloadPolicy {
        &self.policy
    }

    pub fn fetch_to_path(
        &self,
        request: &FetchRequest,
        destination: impl AsRef<Path>,
    ) -> Result<FetchResponse, FetchError> {
        let destination = destination.as_ref();
        self.validate_destination_path(destination)?;
        if let Some(metadata) = request.artifact_metadata.as_ref() {
            metadata.validate()?;
        }

        let mut current_url =
            Url::parse(&request.url).map_err(|source| FetchError::InvalidUrl {
                url: request.url.clone(),
                source: source.to_string(),
            })?;
        self.validate_url(&current_url)?;

        let mut redirects_followed = 0usize;
        loop {
            let mut response = self
                .client
                .get(current_url.clone())
                .send()
                .map_err(|source| self.map_request_error(&current_url, source))?;

            if response.status().is_redirection() {
                if redirects_followed >= self.policy.max_redirects {
                    return Err(FetchError::RedirectLimitExceeded {
                        url: current_url.to_string(),
                        limit: self.policy.max_redirects,
                    });
                }

                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| FetchError::MissingRedirectLocation {
                        url: current_url.to_string(),
                        status: response.status(),
                    })?
                    .to_str()
                    .map_err(|source| FetchError::InvalidRedirectLocation {
                        url: current_url.to_string(),
                        source,
                    })?;

                let next_url = current_url.join(location).map_err(|source| {
                    FetchError::InvalidRedirectTarget {
                        from: current_url.to_string(),
                        location: location.to_string(),
                        source: source.to_string(),
                    }
                })?;
                self.validate_url(&next_url)?;
                current_url = next_url;
                redirects_followed += 1;
                continue;
            }

            if !response.status().is_success() {
                return Err(FetchError::UnexpectedStatus {
                    url: current_url.to_string(),
                    status: response.status(),
                });
            }

            if let Some(content_length) = response.content_length() {
                if content_length > self.policy.max_bytes {
                    return Err(FetchError::SizeLimitExceeded {
                        url: current_url.to_string(),
                        limit: self.policy.max_bytes,
                        attempted: content_length,
                    });
                }
            }

            if let Some(metadata) = request.artifact_metadata.as_ref() {
                self.validate_final_url_against_artifact_metadata(&current_url, metadata)?;
                self.validate_content_length_against_artifact_metadata(
                    &current_url,
                    response.content_length(),
                    metadata,
                )?;
            }

            let fetch_response = self.write_response_body(&mut response, destination)?;
            if let Some(metadata) = request.artifact_metadata.as_ref() {
                self.validate_downloaded_size_against_artifact_metadata(
                    &current_url,
                    fetch_response,
                    metadata,
                    destination,
                )?;
            }

            return Ok(FetchResponse {
                final_url: current_url.to_string(),
                bytes_written: fetch_response,
            });
        }
    }

    fn validate_url(&self, url: &Url) -> Result<(), FetchError> {
        match url.scheme() {
            "https" => {}
            "http" if !self.policy.https_only => {}
            scheme => {
                return Err(FetchError::UnsupportedScheme {
                    url: url.to_string(),
                    scheme: scheme.to_string(),
                    https_only: self.policy.https_only,
                })
            }
        }

        if !self.policy.allowed_hosts.is_empty() {
            let host = url.host_str().ok_or_else(|| FetchError::MissingHost {
                url: url.to_string(),
            })?;
            let host_allowed = self
                .policy
                .allowed_hosts
                .iter()
                .any(|allowed_host| allowed_host.eq_ignore_ascii_case(host));
            if !host_allowed {
                return Err(FetchError::HostNotAllowed {
                    url: url.to_string(),
                    host: host.to_string(),
                    allowed_hosts: self.policy.allowed_hosts.clone(),
                });
            }
        }

        Ok(())
    }

    fn validate_destination_path(&self, destination: &Path) -> Result<(), FetchError> {
        let mut current = Some(destination);

        while let Some(path) = current {
            match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(FetchError::SymlinkPathRejected {
                        path: path.to_path_buf(),
                    });
                }
                Ok(_) => {}
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(FetchError::Io {
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }

            current = path.parent();
        }

        Ok(())
    }

    fn validate_final_url_against_artifact_metadata(
        &self,
        url: &Url,
        metadata: &ArtifactMetadata,
    ) -> Result<(), FetchError> {
        let actual_filename = url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .filter(|segment| !segment.is_empty())
            .ok_or_else(|| FetchError::ArtifactFilenameMismatch {
                url: url.to_string(),
                expected_filename: metadata.filename.clone(),
                actual_filename: None,
            })?;

        if actual_filename != metadata.filename {
            return Err(FetchError::ArtifactFilenameMismatch {
                url: url.to_string(),
                expected_filename: metadata.filename.clone(),
                actual_filename: Some(actual_filename.to_string()),
            });
        }

        Ok(())
    }

    fn validate_content_length_against_artifact_metadata(
        &self,
        url: &Url,
        content_length: Option<u64>,
        metadata: &ArtifactMetadata,
    ) -> Result<(), FetchError> {
        if let (Some(expected), Some(actual)) = (metadata.size_bytes, content_length) {
            if expected != actual {
                return Err(FetchError::ArtifactSizeMismatch {
                    url: url.to_string(),
                    expected_size: expected,
                    actual_size: actual,
                });
            }
        }

        Ok(())
    }

    fn validate_downloaded_size_against_artifact_metadata(
        &self,
        url: &Url,
        bytes_written: u64,
        metadata: &ArtifactMetadata,
        destination: &Path,
    ) -> Result<(), FetchError> {
        if let Some(expected) = metadata.size_bytes {
            if expected != bytes_written {
                let _ = fs::remove_file(destination);
                return Err(FetchError::ArtifactSizeMismatch {
                    url: url.to_string(),
                    expected_size: expected,
                    actual_size: bytes_written,
                });
            }
        }

        Ok(())
    }

    fn write_response_body(
        &self,
        response: &mut reqwest::blocking::Response,
        destination: &Path,
    ) -> Result<u64, FetchError> {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| FetchError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let mut file = File::create(destination).map_err(|source| FetchError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
        let mut buffer = [0_u8; 8192];
        let mut bytes_written = 0_u64;

        loop {
            let read = response
                .read(&mut buffer)
                .map_err(|source| FetchError::BodyRead {
                    url: response.url().to_string(),
                    source,
                })?;
            if read == 0 {
                return Ok(bytes_written);
            }

            bytes_written = bytes_written.saturating_add(read as u64);
            if bytes_written > self.policy.max_bytes {
                let _ = fs::remove_file(destination);
                return Err(FetchError::SizeLimitExceeded {
                    url: response.url().to_string(),
                    limit: self.policy.max_bytes,
                    attempted: bytes_written,
                });
            }

            io::Write::write_all(&mut file, &buffer[..read]).map_err(|source| FetchError::Io {
                path: destination.to_path_buf(),
                source,
            })?;
        }
    }

    fn map_request_error(&self, url: &Url, source: reqwest::Error) -> FetchError {
        if source.is_timeout() {
            FetchError::Timeout {
                url: url.to_string(),
                timeout: self.policy.timeout,
            }
        } else {
            FetchError::Request {
                url: url.to_string(),
                source,
            }
        }
    }
}

fn sanitize_cache_path_component(component: &str) -> String {
    let mut sanitized = String::with_capacity(component.len());

    for byte in component.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                sanitized.push(byte as char);
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

#[derive(Debug)]
pub enum FetchError {
    ClientBuild(reqwest::Error),
    InvalidUrl {
        url: String,
        source: String,
    },
    UnsupportedScheme {
        url: String,
        scheme: String,
        https_only: bool,
    },
    MissingHost {
        url: String,
    },
    HostNotAllowed {
        url: String,
        host: String,
        allowed_hosts: Vec<String>,
    },
    InvalidArtifactMetadata {
        reason: String,
    },
    SymlinkPathRejected {
        path: PathBuf,
    },
    MissingArtifactMetadata {
        url: String,
    },
    ArtifactFilenameMismatch {
        url: String,
        expected_filename: String,
        actual_filename: Option<String>,
    },
    ArtifactSizeMismatch {
        url: String,
        expected_size: u64,
        actual_size: u64,
    },
    RedirectLimitExceeded {
        url: String,
        limit: usize,
    },
    MissingRedirectLocation {
        url: String,
        status: StatusCode,
    },
    InvalidRedirectLocation {
        url: String,
        source: reqwest::header::ToStrError,
    },
    InvalidRedirectTarget {
        from: String,
        location: String,
        source: String,
    },
    UnexpectedStatus {
        url: String,
        status: StatusCode,
    },
    Timeout {
        url: String,
        timeout: Duration,
    },
    SizeLimitExceeded {
        url: String,
        limit: u64,
        attempted: u64,
    },
    Request {
        url: String,
        source: reqwest::Error,
    },
    BodyRead {
        url: String,
        source: io::Error,
    },
    Io {
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientBuild(source) => write!(f, "failed to build downloader client: {source}"),
            Self::InvalidUrl { url, source } => {
                write!(f, "invalid download url `{url}`: {source}")
            }
            Self::UnsupportedScheme {
                url,
                scheme,
                https_only,
            } => {
                if *https_only {
                    write!(f, "download url `{url}` uses unsupported scheme `{scheme}`; HTTPS is required")
                } else {
                    write!(f, "download url `{url}` uses unsupported scheme `{scheme}`")
                }
            }
            Self::MissingHost { url } => {
                write!(f, "download url `{url}` does not include a host")
            }
            Self::HostNotAllowed {
                url,
                host,
                allowed_hosts,
            } => write!(
                f,
                "download url `{url}` uses host `{host}` which is not in the allowlist [{}]",
                allowed_hosts.join(", ")
            ),
            Self::InvalidArtifactMetadata { reason } => {
                write!(f, "invalid artifact metadata: {reason}")
            }
            Self::SymlinkPathRejected { path } => {
                write!(f, "refusing to use symlink path {}", path.display())
            }
            Self::MissingArtifactMetadata { url } => {
                write!(f, "download request for `{url}` is missing artifact metadata")
            }
            Self::ArtifactFilenameMismatch {
                url,
                expected_filename,
                actual_filename,
            } => {
                if let Some(actual_filename) = actual_filename {
                    write!(
                        f,
                        "download url `{url}` resolved to filename `{actual_filename}` but expected `{expected_filename}`"
                    )
                } else {
                    write!(
                        f,
                        "download url `{url}` does not resolve to a filename matching `{expected_filename}`"
                    )
                }
            }
            Self::ArtifactSizeMismatch {
                url,
                expected_size,
                actual_size,
            } => write!(
                f,
                "download for `{url}` does not match expected artifact size ({actual_size} != {expected_size} bytes)"
            ),
            Self::RedirectLimitExceeded { url, limit } => {
                write!(
                    f,
                    "download redirect limit exceeded for `{url}` (limit: {limit})"
                )
            }
            Self::MissingRedirectLocation { url, status } => write!(
                f,
                "redirect response for `{url}` is missing Location header (status: {status})"
            ),
            Self::InvalidRedirectLocation { url, source } => write!(
                f,
                "redirect response for `{url}` has invalid Location header: {source}"
            ),
            Self::InvalidRedirectTarget {
                from,
                location,
                source,
            } => write!(
                f,
                "redirect from `{from}` has invalid target `{location}`: {source}"
            ),
            Self::UnexpectedStatus { url, status } => {
                write!(
                    f,
                    "download request for `{url}` failed with status {status}"
                )
            }
            Self::Timeout { url, timeout } => {
                write!(
                    f,
                    "download request for `{url}` timed out after {timeout:?}"
                )
            }
            Self::SizeLimitExceeded {
                url,
                limit,
                attempted,
            } => write!(
                f,
                "download for `{url}` exceeded size limit ({attempted} > {limit} bytes)"
            ),
            Self::Request { url, source } => {
                write!(f, "download request for `{url}` failed: {source}")
            }
            Self::BodyRead { url, source } => {
                write!(f, "failed to read response body for `{url}`: {source}")
            }
            Self::Io { path, source } => {
                write!(f, "filesystem error for {}: {source}", path.display())
            }
        }
    }
}

impl Error for FetchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ClientBuild(source) => Some(source),
            Self::InvalidRedirectLocation { source, .. } => Some(source),
            Self::Request { source, .. } => Some(source),
            Self::BodyRead { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::InvalidUrl { .. }
            | Self::UnsupportedScheme { .. }
            | Self::MissingHost { .. }
            | Self::HostNotAllowed { .. }
            | Self::InvalidArtifactMetadata { .. }
            | Self::SymlinkPathRejected { .. }
            | Self::MissingArtifactMetadata { .. }
            | Self::ArtifactFilenameMismatch { .. }
            | Self::ArtifactSizeMismatch { .. }
            | Self::RedirectLimitExceeded { .. }
            | Self::MissingRedirectLocation { .. }
            | Self::InvalidRedirectTarget { .. }
            | Self::UnexpectedStatus { .. }
            | Self::Timeout { .. }
            | Self::SizeLimitExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use crate::registry::Ecosystem;

    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    #[test]
    fn rejects_non_https_urls_by_default() {
        let downloader =
            SafeDownloader::new(DownloadPolicy::default()).expect("client should build");
        let destination = TestDir::new("non-https").path().join("artifact.bin");
        let error = downloader
            .fetch_to_path(
                &request("http://example.test/artifact.tgz".to_string()),
                &destination,
            )
            .expect_err("http url should be rejected");

        assert_eq!(
            error.to_string(),
            "download url `http://example.test/artifact.tgz` uses unsupported scheme `http`; HTTPS is required"
        );
    }

    #[test]
    fn rejects_hosts_outside_allowlist() {
        let mut policy = test_policy();
        policy.allowed_hosts = vec!["example.test".to_string()];
        let downloader = SafeDownloader::new(policy).expect("client should build");
        let destination = TestDir::new("host-allowlist").path().join("artifact.bin");
        let disallowed_url = "http://127.0.0.1:43210/artifact.bin".to_string();

        let error = downloader
            .fetch_to_path(&request(disallowed_url.clone()), &destination)
            .expect_err("host outside allowlist should fail");

        assert_eq!(
            error.to_string(),
            format!(
                "download url `{disallowed_url}` uses host `127.0.0.1` which is not in the allowlist [example.test]"
            )
        );
        assert!(!destination.exists());
    }

    #[test]
    fn downloads_body_within_limits() {
        let server = TestServer::start(vec![TestResponse::ok("hello world")]);
        let downloader = SafeDownloader::new(test_policy()).expect("client should build");
        let destination = TestDir::new("success").path().join("artifact.bin");

        let response = downloader
            .fetch_to_path(
                &request(format!("{}/artifact.bin", server.base_url())),
                &destination,
            )
            .expect("download should succeed");

        assert_eq!(
            response.final_url,
            format!("{}/artifact.bin", server.base_url())
        );
        assert_eq!(response.bytes_written, 11);
        assert_eq!(
            fs::read_to_string(destination).expect("file should exist"),
            "hello world"
        );
        assert_eq!(server.paths(), vec!["/artifact.bin"]);
    }

    #[test]
    fn rejects_invalid_artifact_metadata_before_download() {
        let downloader = SafeDownloader::new(test_policy()).expect("client should build");
        let destination = TestDir::new("invalid-metadata").path().join("artifact.bin");
        let error = downloader
            .fetch_to_path(
                &request_with_artifact_metadata(
                    "http://example.test/artifact.bin".to_string(),
                    "nested/path.bin",
                    Some(12),
                ),
                &destination,
            )
            .expect_err("invalid artifact metadata should fail");

        assert_eq!(
            error.to_string(),
            "invalid artifact metadata: artifact filename `nested/path.bin` must be a plain file name"
        );
    }

    #[test]
    fn rejects_filename_mismatches_against_artifact_metadata() {
        let server = TestServer::start(vec![TestResponse::ok("hello world")]);
        let downloader = SafeDownloader::new(test_policy()).expect("client should build");
        let destination = TestDir::new("filename-mismatch")
            .path()
            .join("artifact.bin");

        let error = downloader
            .fetch_to_path(
                &request_with_artifact_metadata(
                    format!("{}/artifact.bin", server.base_url()),
                    "expected.bin",
                    Some(11),
                ),
                &destination,
            )
            .expect_err("filename mismatch should fail");

        let final_url = format!("{}/artifact.bin", server.base_url());
        assert_eq!(
            error.to_string(),
            format!(
                "download url `{final_url}` resolved to filename `artifact.bin` but expected `expected.bin`"
            )
        );
        assert!(!destination.exists());
    }

    #[test]
    fn rejects_size_mismatches_against_artifact_metadata() {
        let server = TestServer::start(vec![TestResponse::ok("hello world")]);
        let downloader = SafeDownloader::new(test_policy()).expect("client should build");
        let destination = TestDir::new("metadata-size-mismatch")
            .path()
            .join("artifact.bin");

        let error = downloader
            .fetch_to_path(
                &request_with_artifact_metadata(
                    format!("{}/artifact.bin", server.base_url()),
                    "artifact.bin",
                    Some(12),
                ),
                &destination,
            )
            .expect_err("artifact size mismatch should fail");

        let final_url = format!("{}/artifact.bin", server.base_url());
        assert_eq!(
            error.to_string(),
            format!(
                "download for `{final_url}` does not match expected artifact size (11 != 12 bytes)"
            )
        );
        assert!(!destination.exists());
    }

    #[test]
    fn follows_redirects_within_limit() {
        let server = TestServer::start(vec![
            TestResponse::redirect("/step-1"),
            TestResponse::redirect("/final.bin"),
            TestResponse::ok("payload"),
        ]);
        let mut policy = test_policy();
        policy.max_redirects = 2;
        let downloader = SafeDownloader::new(policy).expect("client should build");
        let destination = TestDir::new("redirect-success").path().join("artifact.bin");

        let response = downloader
            .fetch_to_path(
                &request(format!("{}/start", server.base_url())),
                &destination,
            )
            .expect("redirected download should succeed");

        assert_eq!(
            response.final_url,
            format!("{}/final.bin", server.base_url())
        );
        assert_eq!(
            fs::read_to_string(destination).expect("file should exist"),
            "payload"
        );
        assert_eq!(server.paths(), vec!["/start", "/step-1", "/final.bin"]);
    }

    #[test]
    fn rejects_redirects_beyond_limit() {
        let server = TestServer::start(vec![
            TestResponse::redirect("/step-1"),
            TestResponse::redirect("/final.bin"),
        ]);
        let mut policy = test_policy();
        policy.max_redirects = 1;
        let downloader = SafeDownloader::new(policy).expect("client should build");
        let destination = TestDir::new("redirect-limit").path().join("artifact.bin");

        let error = downloader
            .fetch_to_path(
                &request(format!("{}/start", server.base_url())),
                &destination,
            )
            .expect_err("redirect limit should fail");

        let expected_url = format!("{}/step-1", server.base_url());
        assert_eq!(
            error.to_string(),
            format!("download redirect limit exceeded for `{expected_url}` (limit: 1)")
        );
        assert!(!destination.exists());
    }

    #[test]
    fn rejects_bodies_larger_than_limit() {
        let server = TestServer::start(vec![TestResponse::ok("0123456789")]);
        let mut policy = test_policy();
        policy.max_bytes = 4;
        let downloader = SafeDownloader::new(policy).expect("client should build");
        let destination = TestDir::new("size-limit").path().join("artifact.bin");

        let error = downloader
            .fetch_to_path(
                &request(format!("{}/artifact.bin", server.base_url())),
                &destination,
            )
            .expect_err("size limit should fail");

        let expected_url = format!("{}/artifact.bin", server.base_url());
        assert_eq!(
            error.to_string(),
            format!("download for `{expected_url}` exceeded size limit (10 > 4 bytes)")
        );
        assert!(!destination.exists());
    }

    #[test]
    fn rejects_streamed_bodies_larger_than_limit_without_content_length() {
        let server = TestServer::start(vec![TestResponse::ok_without_content_length("0123456789")]);
        let mut policy = test_policy();
        policy.max_bytes = 4;
        let downloader = SafeDownloader::new(policy).expect("client should build");
        let destination = TestDir::new("stream-size-limit")
            .path()
            .join("artifact.bin");

        let error = downloader
            .fetch_to_path(
                &request(format!("{}/artifact.bin", server.base_url())),
                &destination,
            )
            .expect_err("streamed size limit should fail");

        let expected_url = format!("{}/artifact.bin", server.base_url());
        assert_eq!(
            error.to_string(),
            format!("download for `{expected_url}` exceeded size limit (10 > 4 bytes)")
        );
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_download_destinations() {
        let server = TestServer::start(vec![TestResponse::ok("hello")]);
        let downloader = SafeDownloader::new(test_policy()).expect("client should build");
        let temp = TestDir::new("symlink-destination");
        let real_target = temp.path().join("real-target.bin");
        let destination = temp.path().join("artifact.bin");
        fs::write(&real_target, "keep me").expect("real target should be written");
        symlink(&real_target, &destination).expect("symlink should be created");

        let error = downloader
            .fetch_to_path(
                &request(format!("{}/artifact.bin", server.base_url())),
                &destination,
            )
            .expect_err("symlink destination should fail");

        assert_eq!(
            error.to_string(),
            format!("refusing to use symlink path {}", destination.display())
        );
        assert_eq!(
            fs::read_to_string(&real_target).expect("real target should remain untouched"),
            "keep me"
        );
    }

    #[test]
    fn rejects_requests_that_timeout() {
        let server = TestServer::start(vec![TestResponse::delayed_ok(
            Duration::from_millis(150),
            "late response",
        )]);
        let mut policy = test_policy();
        policy.timeout = Duration::from_millis(50);
        let downloader = SafeDownloader::new(policy.clone()).expect("client should build");
        let destination = TestDir::new("timeout").path().join("artifact.bin");

        let error = downloader
            .fetch_to_path(
                &request(format!("{}/artifact.bin", server.base_url())),
                &destination,
            )
            .expect_err("timeout should fail");

        let expected_url = format!("{}/artifact.bin", server.base_url());
        assert_eq!(
            error.to_string(),
            format!(
                "download request for `{expected_url}` timed out after {:?}",
                policy.timeout
            )
        );
    }

    #[test]
    fn computes_cache_paths_inside_state_layout() {
        let repo_root = TestDir::new("cache-layout");
        let state_layout =
            StateLayout::from_repo_root(repo_root.path()).expect("state layout should build");
        let cache = ArtifactCache::from_state_layout(&state_layout);
        let package_version = package_version(Ecosystem::Npm, "@types/node", "24.0.0");
        let metadata = ArtifactMetadata {
            filename: "node.tgz".to_string(),
            size_bytes: Some(42),
        };

        let path = cache
            .path_for(&package_version, &metadata)
            .expect("cache path should build");

        assert_eq!(
            path,
            state_layout
                .artifacts_dir()
                .join("npm")
                .join("~40types~2Fnode")
                .join("24.0.0")
                .join("node.tgz")
        );
    }

    #[test]
    fn serves_repeated_downloads_from_cache() {
        let repo_root = TestDir::new("cache-hit");
        let state_layout =
            StateLayout::from_repo_root(repo_root.path()).expect("state layout should build");
        let cache = ArtifactCache::from_state_layout(&state_layout);
        let server = TestServer::start(vec![TestResponse::ok("hello")]);
        let downloader = SafeDownloader::new(test_policy()).expect("client should build");
        let package_version = package_version(Ecosystem::Npm, "chalk", "5.4.0");
        let request = request_with_artifact_metadata(
            format!("{}/chalk-5.4.0.tgz", server.base_url()),
            "chalk-5.4.0.tgz",
            Some(5),
        );

        let first = cache
            .fetch(&downloader, &package_version, &request)
            .expect("first fetch should succeed");
        let second = cache
            .fetch(&downloader, &package_version, &request)
            .expect("second fetch should hit cache");

        assert!(!first.cache_hit);
        assert!(second.cache_hit);
        assert_eq!(first.artifact.path, second.artifact.path);
        assert_eq!(
            fs::read_to_string(&second.artifact.path).expect("cached file should exist"),
            "hello"
        );
        assert_eq!(server.paths(), vec!["/chalk-5.4.0.tgz"]);
    }

    #[test]
    fn redownloads_stale_cached_artifacts() {
        let repo_root = TestDir::new("cache-stale");
        let state_layout =
            StateLayout::from_repo_root(repo_root.path()).expect("state layout should build");
        let cache = ArtifactCache::from_state_layout(&state_layout);
        let downloader = SafeDownloader::new(test_policy()).expect("client should build");
        let package_version = package_version(Ecosystem::Pypi, "requests", "2.32.3");
        let metadata = ArtifactMetadata {
            filename: "requests-2.32.3.tar.gz".to_string(),
            size_bytes: Some(12),
        };
        let stale_path = cache
            .path_for(&package_version, &metadata)
            .expect("cache path should build");
        fs::create_dir_all(
            stale_path
                .parent()
                .expect("cache path should have a parent"),
        )
        .expect("cache directories should be created");
        fs::write(&stale_path, b"stale").expect("stale cache entry should be written");

        let server = TestServer::start(vec![TestResponse::ok("fresh-bytes!")]);
        let request = request_with_artifact_metadata(
            format!("{}/requests-2.32.3.tar.gz", server.base_url()),
            "requests-2.32.3.tar.gz",
            Some(12),
        );

        let fetched = cache
            .fetch(&downloader, &package_version, &request)
            .expect("stale artifact should be refreshed");

        assert!(!fetched.cache_hit);
        assert_eq!(
            fs::read_to_string(&fetched.artifact.path).expect("refreshed cache file should exist"),
            "fresh-bytes!"
        );
        assert_eq!(server.paths(), vec!["/requests-2.32.3.tar.gz"]);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cache_entries() {
        let repo_root = TestDir::new("cache-symlink");
        let state_layout =
            StateLayout::from_repo_root(repo_root.path()).expect("state layout should build");
        let cache = ArtifactCache::from_state_layout(&state_layout);
        let downloader = SafeDownloader::new(test_policy()).expect("client should build");
        let package_version = package_version(Ecosystem::Npm, "chalk", "5.4.0");
        let metadata = ArtifactMetadata {
            filename: "chalk-5.4.0.tgz".to_string(),
            size_bytes: Some(5),
        };
        let cache_path = cache
            .path_for(&package_version, &metadata)
            .expect("cache path should build");
        let real_target = repo_root.path().join("outside.bin");
        fs::write(&real_target, "hello").expect("real target should be written");
        fs::create_dir_all(cache_path.parent().expect("cache path should have parent"))
            .expect("cache directories should be created");
        symlink(&real_target, &cache_path).expect("cache symlink should be created");

        let request = request_with_artifact_metadata(
            "http://example.test/chalk-5.4.0.tgz".to_string(),
            "chalk-5.4.0.tgz",
            Some(5),
        );
        let error = cache
            .fetch(&downloader, &package_version, &request)
            .expect_err("symlink cache entry should be rejected");

        assert_eq!(
            error.to_string(),
            format!("refusing to use symlink path {}", cache_path.display())
        );
        assert_eq!(
            fs::read_to_string(&real_target).expect("real target should remain untouched"),
            "hello"
        );
    }

    fn test_policy() -> DownloadPolicy {
        DownloadPolicy {
            https_only: false,
            allowed_hosts: Vec::new(),
            max_redirects: 5,
            timeout: Duration::from_secs(1),
            max_bytes: 1024,
        }
    }

    fn request(url: String) -> FetchRequest {
        FetchRequest {
            url,
            artifact_metadata: None,
        }
    }

    fn request_with_artifact_metadata(
        url: String,
        filename: &str,
        size_bytes: Option<u64>,
    ) -> FetchRequest {
        FetchRequest {
            url,
            artifact_metadata: Some(ArtifactMetadata {
                filename: filename.to_string(),
                size_bytes,
            }),
        }
    }

    fn package_version(ecosystem: Ecosystem, package: &str, version: &str) -> PackageVersion {
        PackageVersion {
            ecosystem,
            package: package.to_string(),
            version: version.to_string(),
        }
    }

    #[derive(Debug, Clone)]
    struct TestResponse {
        status: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        delay: Duration,
        include_content_length: bool,
    }

    impl TestResponse {
        fn ok(body: &str) -> Self {
            Self {
                status: "200 OK",
                headers: vec![(
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string(),
                )],
                body: body.as_bytes().to_vec(),
                delay: Duration::ZERO,
                include_content_length: true,
            }
        }

        fn ok_without_content_length(body: &str) -> Self {
            let mut response = Self::ok(body);
            response.include_content_length = false;
            response
        }

        fn delayed_ok(delay: Duration, body: &str) -> Self {
            let mut response = Self::ok(body);
            response.delay = delay;
            response
        }

        fn redirect(location: &str) -> Self {
            Self {
                status: "302 Found",
                headers: vec![("Location".to_string(), location.to_string())],
                body: Vec::new(),
                delay: Duration::ZERO,
                include_content_length: true,
            }
        }
    }

    struct TestServer {
        base_url: String,
        paths: Arc<Mutex<Vec<String>>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestServer {
        fn start(responses: Vec<TestResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test server should bind");
            let address = listener.local_addr().expect("local addr should resolve");
            let base_url = format!("http://{}", address);
            let paths = Arc::new(Mutex::new(Vec::new()));
            let paths_for_thread = Arc::clone(&paths);
            let thread = thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) = listener.accept().expect("request should arrive");
                    let mut buffer = [0_u8; 4096];
                    let read = std::io::Read::read(&mut stream, &mut buffer)
                        .expect("request should be readable");
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("")
                        .to_string();
                    paths_for_thread
                        .lock()
                        .expect("paths lock should succeed")
                        .push(path);

                    if !response.delay.is_zero() {
                        thread::sleep(response.delay);
                    }

                    let mut headers = response.headers;
                    if response.include_content_length
                        && !headers
                            .iter()
                            .any(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
                    {
                        headers.push((
                            "Content-Length".to_string(),
                            response.body.len().to_string(),
                        ));
                    }
                    headers.push(("Connection".to_string(), "close".to_string()));

                    let mut response_text = format!("HTTP/1.1 {}\r\n", response.status);
                    for (name, value) in headers {
                        response_text.push_str(&format!("{name}: {value}\r\n"));
                    }
                    response_text.push_str("\r\n");

                    stream
                        .write_all(response_text.as_bytes())
                        .expect("headers should be written");
                    stream
                        .write_all(&response.body)
                        .expect("body should be written");
                }
            });

            Self {
                base_url,
                paths,
                thread: Some(thread),
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn paths(mut self) -> Vec<String> {
            if let Some(thread) = self.thread.take() {
                thread.join().expect("server thread should finish");
            }
            self.paths
                .lock()
                .expect("paths lock should succeed")
                .clone()
        }
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = format!(
                "{}-{}",
                label,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time should move forward")
                    .as_nanos()
            );
            let path = std::env::temp_dir().join(format!("pincushion-fetch-{unique}"));
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
