use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::{
    DownloadedArtifact, Ecosystem, PackageVersion, Registry, RegistryError, RegistryResult,
};

const DEFAULT_METADATA_BASE_URL: &str = "https://registry.npmjs.org";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmRegistry {
    metadata_base_url: String,
}

impl NpmRegistry {
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
        format!(
            "{}/{}",
            self.metadata_base_url,
            encode_package_for_registry_path(package)
        )
    }

    fn parse_latest_version(
        &self,
        package: &str,
        metadata: NpmPackageMetadata,
    ) -> RegistryResult<PackageVersion> {
        let latest = metadata
            .dist_tags
            .latest
            .filter(|latest| !latest.trim().is_empty())
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "npm registry response for `{package}` is missing dist-tags.latest"
                ))
            })?;

        Ok(PackageVersion {
            ecosystem: self.ecosystem(),
            package: package.to_string(),
            version: latest,
        })
    }
}

impl Default for NpmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry for NpmRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn latest_version(&self, package: &str) -> RegistryResult<PackageVersion> {
        let response = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|source| {
                RegistryError::new(format!("failed to build npm registry client: {source}"))
            })?
            .get(self.metadata_url(package))
            .send()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to fetch npm metadata for `{package}`: {source}"
                ))
            })?
            .error_for_status()
            .map_err(|source| {
                RegistryError::new(format!(
                    "npm metadata request for `{package}` failed: {source}"
                ))
            })?;

        let metadata = response.json::<NpmPackageMetadata>().map_err(|source| {
            RegistryError::new(format!(
                "failed to parse npm metadata for `{package}`: {source}"
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
struct NpmPackageMetadata {
    #[serde(rename = "dist-tags")]
    dist_tags: NpmDistTags,
}

#[derive(Debug, Deserialize)]
struct NpmDistTags {
    latest: Option<String>,
}

fn encode_package_for_registry_path(package: &str) -> String {
    package.replace('/', "%2f")
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use super::*;

    #[test]
    fn encodes_scoped_package_names_for_metadata_paths() {
        let registry = NpmRegistry::new();

        assert_eq!(
            registry.metadata_url("@types/node"),
            "https://registry.npmjs.org/@types%2fnode"
        );
        assert_eq!(
            registry.metadata_url("react"),
            "https://registry.npmjs.org/react"
        );
    }

    #[test]
    fn parses_latest_version_from_registry_metadata() {
        let registry = NpmRegistry::new();
        let package = registry
            .parse_latest_version(
                "react",
                NpmPackageMetadata {
                    dist_tags: NpmDistTags {
                        latest: Some("19.0.0".to_string()),
                    },
                },
            )
            .expect("latest version should parse");

        assert_eq!(package.package_key(), "npm:react");
        assert_eq!(package.version, "19.0.0");
    }

    #[test]
    fn parses_latest_version_from_fixture_metadata() {
        let registry = NpmRegistry::new();
        let metadata: NpmPackageMetadata =
            serde_json::from_str(include_str!("../../tests/fixtures/registry/npm/chalk.json"))
                .expect("fixture metadata should parse");

        let package = registry
            .parse_latest_version("chalk", metadata)
            .expect("fixture latest version should parse");

        assert_eq!(package.package_key(), "npm:chalk");
        assert_eq!(package.version, "5.4.0");
    }

    #[test]
    fn rejects_registry_metadata_without_latest_dist_tag() {
        let registry = NpmRegistry::new();
        let error = registry
            .parse_latest_version(
                "react",
                NpmPackageMetadata {
                    dist_tags: NpmDistTags { latest: None },
                },
            )
            .expect_err("missing latest tag should fail");

        assert_eq!(
            error.to_string(),
            "npm registry response for `react` is missing dist-tags.latest"
        );
    }

    #[test]
    fn fetches_latest_version_from_http_registry() {
        let server = TestServer::start(200, r#"{"dist-tags":{"latest":"5.4.0"}}"#);
        let registry = NpmRegistry::with_metadata_base_url(server.base_url());

        let package = registry
            .latest_version("chalk")
            .expect("latest version should load");

        assert_eq!(package.package, "chalk");
        assert_eq!(package.version, "5.4.0");
        assert_eq!(package.package_key(), "npm:chalk");
        assert_eq!(server.request_path(), "/chalk");
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
