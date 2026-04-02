use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::{
    DownloadedArtifact, Ecosystem, PackageVersion, Registry, RegistryError, RegistryResult,
};

const DEFAULT_METADATA_BASE_URL: &str = "https://crates.io/api/v1/crates";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CratesRegistry {
    metadata_base_url: String,
}

impl CratesRegistry {
    pub fn new() -> Self {
        Self {
            metadata_base_url: DEFAULT_METADATA_BASE_URL.to_string(),
        }
    }

    fn with_metadata_base_url(metadata_base_url: impl Into<String>) -> Self {
        Self {
            metadata_base_url: metadata_base_url.into().trim_end_matches('/').to_string(),
        }
    }

    fn metadata_url(&self, package: &str) -> String {
        format!("{}/{}", self.metadata_base_url, package)
    }

    fn parse_latest_version(
        &self,
        package: &str,
        metadata: CratesPackageMetadata,
    ) -> RegistryResult<PackageVersion> {
        let latest = metadata
            .krate
            .max_stable_version
            .or(metadata.krate.newest_version)
            .filter(|version| !version.trim().is_empty())
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "crates.io response for `{package}` is missing max_stable_version/newest_version"
                ))
            })?;

        Ok(PackageVersion {
            ecosystem: self.ecosystem(),
            package: package.to_string(),
            version: latest,
        })
    }
}

impl Default for CratesRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry for CratesRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Crates
    }

    fn latest_version(&self, package: &str) -> RegistryResult<PackageVersion> {
        let response = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|source| {
                RegistryError::new(format!("failed to build crates.io client: {source}"))
            })?
            .get(self.metadata_url(package))
            .send()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to fetch crates.io metadata for `{package}`: {source}"
                ))
            })?
            .error_for_status()
            .map_err(|source| {
                RegistryError::new(format!(
                    "crates.io metadata request for `{package}` failed: {source}"
                ))
            })?;

        let metadata = response.json::<CratesPackageMetadata>().map_err(|source| {
            RegistryError::new(format!(
                "failed to parse crates.io metadata for `{package}`: {source}"
            ))
        })?;

        self.parse_latest_version(package, metadata)
    }

    fn download_artifact(
        &self,
        _package: &PackageVersion,
        _destination: &Path,
    ) -> RegistryResult<DownloadedArtifact> {
        Err(RegistryError::placeholder(
            self.ecosystem(),
            "download_artifact",
        ))
    }

    fn unpack(&self, _artifact: &Path, _destination: &Path) -> RegistryResult<()> {
        Err(RegistryError::placeholder(self.ecosystem(), "unpack"))
    }
}

#[derive(Debug, Deserialize)]
struct CratesPackageMetadata {
    #[serde(rename = "crate")]
    krate: CratesPackage,
}

#[derive(Debug, Deserialize)]
struct CratesPackage {
    max_stable_version: Option<String>,
    newest_version: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use super::*;

    #[test]
    fn builds_metadata_url_for_crate() {
        let registry = CratesRegistry::new();

        assert_eq!(
            registry.metadata_url("clap"),
            "https://crates.io/api/v1/crates/clap"
        );
    }

    #[test]
    fn parses_latest_version_from_crates_metadata() {
        let registry = CratesRegistry::new();
        let package = registry
            .parse_latest_version(
                "clap",
                CratesPackageMetadata {
                    krate: CratesPackage {
                        max_stable_version: Some("4.5.31".to_string()),
                        newest_version: Some("4.6.0-beta.1".to_string()),
                    },
                },
            )
            .expect("latest version should parse");

        assert_eq!(package.package_key(), "crates:clap");
        assert_eq!(package.version, "4.5.31");
    }

    #[test]
    fn parses_latest_version_from_fixture_metadata() {
        let registry = CratesRegistry::new();
        let metadata: CratesPackageMetadata = serde_json::from_str(include_str!(
            "../../tests/fixtures/registry/crates/clap.json"
        ))
        .expect("fixture metadata should parse");

        let package = registry
            .parse_latest_version("clap", metadata)
            .expect("fixture latest version should parse");

        assert_eq!(package.package_key(), "crates:clap");
        assert_eq!(package.version, "4.5.31");
    }

    #[test]
    fn falls_back_to_newest_version_when_max_stable_is_missing() {
        let registry = CratesRegistry::new();
        let package = registry
            .parse_latest_version(
                "clap",
                CratesPackageMetadata {
                    krate: CratesPackage {
                        max_stable_version: None,
                        newest_version: Some("4.5.31".to_string()),
                    },
                },
            )
            .expect("newest version should be used");

        assert_eq!(package.version, "4.5.31");
    }

    #[test]
    fn rejects_metadata_without_any_version() {
        let registry = CratesRegistry::new();
        let error = registry
            .parse_latest_version(
                "clap",
                CratesPackageMetadata {
                    krate: CratesPackage {
                        max_stable_version: None,
                        newest_version: None,
                    },
                },
            )
            .expect_err("missing versions should fail");

        assert_eq!(
            error.to_string(),
            "crates.io response for `clap` is missing max_stable_version/newest_version"
        );
    }

    #[test]
    fn fetches_latest_version_from_http_registry() {
        let server = TestServer::start(
            200,
            r#"{"crate":{"max_stable_version":"4.5.31","newest_version":"4.5.31"}}"#,
        );
        let registry = CratesRegistry::with_metadata_base_url(server.base_url());

        let package = registry
            .latest_version("clap")
            .expect("latest version should load");

        assert_eq!(package.package, "clap");
        assert_eq!(package.version, "4.5.31");
        assert_eq!(package.package_key(), "crates:clap");
        assert_eq!(server.request_path(), "/clap");
    }

    struct TestServer {
        base_url: String,
        request_path: Arc<Mutex<String>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestServer {
        fn start(status_code: u16, body: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test server should bind");
            let address = listener.local_addr().expect("local addr should resolve");
            let base_url = format!("http://{}", address);

            let request_path = Arc::new(Mutex::new(String::new()));
            let request_path_for_thread = request_path.clone();

            let thread = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0_u8; 2048];
                let read = stream
                    .read(&mut buffer)
                    .expect("request should be readable");
                let request = String::from_utf8_lossy(&buffer[..read]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                *request_path_for_thread
                    .lock()
                    .expect("path lock should succeed") = path;

                let response = format!(
                    "HTTP/1.1 {status_code} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("response should be written");
            });

            Self {
                base_url,
                request_path,
                thread: Some(thread),
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn request_path(mut self) -> String {
            if let Some(thread) = self.thread.take() {
                thread.join().expect("server thread should finish");
            }
            self.request_path
                .lock()
                .expect("path lock should succeed")
                .clone()
        }
    }
}
