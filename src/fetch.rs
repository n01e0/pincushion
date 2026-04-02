use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::LOCATION;
use reqwest::{StatusCode, Url};

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

#[derive(Debug, Clone)]
pub struct SafeDownloader {
    policy: DownloadPolicy,
    client: Client,
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

            let fetch_response = self.write_response_body(&mut response, destination)?;
            return Ok(FetchResponse {
                final_url: current_url.to_string(),
                bytes_written: fetch_response,
            });
        }
    }

    fn validate_url(&self, url: &Url) -> Result<(), FetchError> {
        match url.scheme() {
            "https" => Ok(()),
            "http" if !self.policy.https_only => Ok(()),
            scheme => Err(FetchError::UnsupportedScheme {
                url: url.to_string(),
                scheme: scheme.to_string(),
                https_only: self.policy.https_only,
            }),
        }
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

    use super::*;

    #[test]
    fn rejects_non_https_urls_by_default() {
        let downloader =
            SafeDownloader::new(DownloadPolicy::default()).expect("client should build");
        let destination = TestDir::new("non-https").path().join("artifact.bin");
        let error = downloader
            .fetch_to_path(
                &FetchRequest {
                    url: "http://example.test/artifact.tgz".to_string(),
                },
                &destination,
            )
            .expect_err("http url should be rejected");

        assert_eq!(
            error.to_string(),
            "download url `http://example.test/artifact.tgz` uses unsupported scheme `http`; HTTPS is required"
        );
    }

    #[test]
    fn downloads_body_within_limits() {
        let server = TestServer::start(vec![TestResponse::ok("hello world")]);
        let downloader = SafeDownloader::new(test_policy()).expect("client should build");
        let destination = TestDir::new("success").path().join("artifact.bin");

        let response = downloader
            .fetch_to_path(
                &FetchRequest {
                    url: format!("{}/artifact.bin", server.base_url()),
                },
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
                &FetchRequest {
                    url: format!("{}/start", server.base_url()),
                },
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
                &FetchRequest {
                    url: format!("{}/start", server.base_url()),
                },
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
                &FetchRequest {
                    url: format!("{}/artifact.bin", server.base_url()),
                },
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
                &FetchRequest {
                    url: format!("{}/artifact.bin", server.base_url()),
                },
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

    fn test_policy() -> DownloadPolicy {
        DownloadPolicy {
            https_only: false,
            max_redirects: 5,
            timeout: Duration::from_secs(1),
            max_bytes: 1024,
        }
    }

    #[derive(Debug, Clone)]
    struct TestResponse {
        status: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        delay: Duration,
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
            }
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
                    headers.push((
                        "Content-Length".to_string(),
                        response.body.len().to_string(),
                    ));
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
