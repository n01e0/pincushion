use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::{
    blocking_metadata_client, DownloadedArtifact, Ecosystem, PackageVersion, Registry,
    RegistryError, RegistryResult,
};

const DEFAULT_METADATA_BASE_URL: &str = "https://pypi.org/pypi";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PypiRegistry {
    metadata_base_url: String,
}

impl PypiRegistry {
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
        format!("{}/{}/json", self.metadata_base_url, package)
    }

    fn fetch_package_metadata(&self, package: &str) -> RegistryResult<PypiPackageMetadata> {
        blocking_metadata_client(Duration::from_secs(15))?
            .get(self.metadata_url(package))
            .send()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to fetch pypi metadata for `{package}`: {source}"
                ))
            })?
            .error_for_status()
            .map_err(|source| {
                RegistryError::new(format!(
                    "pypi metadata request for `{package}` failed: {source}"
                ))
            })?
            .json::<PypiPackageMetadata>()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to parse pypi metadata for `{package}`: {source}"
                ))
            })
    }

    fn parse_latest_version(
        &self,
        package: &str,
        metadata: &PypiPackageMetadata,
    ) -> RegistryResult<PackageVersion> {
        let latest = metadata
            .info
            .version
            .as_deref()
            .filter(|version| !version.trim().is_empty())
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "pypi response for `{package}` is missing info.version"
                ))
            })?;

        Ok(PackageVersion {
            ecosystem: self.ecosystem(),
            package: package.to_string(),
            version: latest.to_string(),
        })
    }

    fn select_preferred_artifact(
        &self,
        package_version: &PackageVersion,
        metadata: &PypiPackageMetadata,
    ) -> RegistryResult<PypiArtifact> {
        let release_files = metadata
            .releases
            .get(&package_version.version)
            .map(Vec::as_slice)
            .unwrap_or(metadata.urls.as_slice());

        let mut candidates = release_files
            .iter()
            .filter_map(PypiArtifact::from_distribution_file)
            .collect::<Vec<_>>();

        candidates.sort_by(|left, right| {
            left.artifact_type
                .priority()
                .cmp(&right.artifact_type.priority())
                .then_with(|| left.filename.cmp(&right.filename))
                .then_with(|| left.url.cmp(&right.url))
        });

        candidates.into_iter().next().ok_or_else(|| {
            RegistryError::new(format!(
                "pypi release `{}` has no supported sdist or wheel artifact",
                package_version.package_key().replace(':', "==")
            ))
        })
    }
}

impl Default for PypiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry for PypiRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pypi
    }

    fn latest_version(&self, package: &str) -> RegistryResult<PackageVersion> {
        let metadata = self.fetch_package_metadata(package)?;
        self.parse_latest_version(package, &metadata)
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
struct PypiPackageMetadata {
    info: PypiPackageInfo,
    #[serde(default)]
    urls: Vec<PypiDistributionFile>,
    #[serde(default)]
    releases: HashMap<String, Vec<PypiDistributionFile>>,
}

#[derive(Debug, Deserialize)]
struct PypiPackageInfo {
    version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PypiDistributionFile {
    filename: Option<String>,
    packagetype: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PypiArtifactType {
    SourceDist,
    Wheel,
}

impl PypiArtifactType {
    const fn priority(self) -> usize {
        match self {
            Self::SourceDist => 0,
            Self::Wheel => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PypiArtifact {
    filename: String,
    url: String,
    artifact_type: PypiArtifactType,
}

impl PypiArtifact {
    fn from_distribution_file(file: &PypiDistributionFile) -> Option<Self> {
        let artifact_type = match file.packagetype.as_deref()? {
            "sdist" => PypiArtifactType::SourceDist,
            "bdist_wheel" => PypiArtifactType::Wheel,
            _ => return None,
        };

        let filename = file.filename.as_deref()?.trim();
        let url = file.url.as_deref()?.trim();
        if filename.is_empty() || url.is_empty() {
            return None;
        }

        Some(Self {
            filename: filename.to_string(),
            url: url.to_string(),
            artifact_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use super::*;

    #[test]
    fn builds_metadata_url_for_project() {
        let registry = PypiRegistry::new();

        assert_eq!(
            registry.metadata_url("requests"),
            "https://pypi.org/pypi/requests/json"
        );
    }

    #[test]
    fn parses_latest_version_from_pypi_metadata() {
        let registry = PypiRegistry::new();
        let package = registry
            .parse_latest_version("requests", &metadata_with_version("2.32.3"))
            .expect("latest version should parse");

        assert_eq!(package.package_key(), "pypi:requests");
        assert_eq!(package.version, "2.32.3");
    }

    #[test]
    fn parses_latest_version_and_artifact_from_fixture_metadata() {
        let registry = PypiRegistry::new();
        let metadata: PypiPackageMetadata = serde_json::from_str(include_str!(
            "../../tests/fixtures/registry/pypi/requests.json"
        ))
        .expect("fixture metadata should parse");

        let package = registry
            .parse_latest_version("requests", &metadata)
            .expect("fixture latest version should parse");
        let artifact = registry
            .select_preferred_artifact(&package, &metadata)
            .expect("fixture artifact should be selected");

        assert_eq!(package.package_key(), "pypi:requests");
        assert_eq!(package.version, "2.32.3");
        assert_eq!(artifact.artifact_type, PypiArtifactType::SourceDist);
        assert_eq!(artifact.filename, "requests-2.32.3.tar.gz");
    }

    #[test]
    fn rejects_pypi_metadata_without_version() {
        let registry = PypiRegistry::new();
        let error = registry
            .parse_latest_version(
                "requests",
                &PypiPackageMetadata {
                    info: PypiPackageInfo { version: None },
                    urls: Vec::new(),
                    releases: HashMap::new(),
                },
            )
            .expect_err("missing version should fail");

        assert_eq!(
            error.to_string(),
            "pypi response for `requests` is missing info.version"
        );
    }

    #[test]
    fn prefers_sdist_over_wheel() {
        let registry = PypiRegistry::new();
        let package = package_version("requests", "2.32.3");
        let metadata = PypiPackageMetadata {
            info: PypiPackageInfo {
                version: Some("2.32.3".to_string()),
            },
            urls: Vec::new(),
            releases: HashMap::from([(
                "2.32.3".to_string(),
                vec![
                    wheel(
                        "requests-2.32.3-py3-none-any.whl",
                        "https://files.example/requests.whl",
                    ),
                    sdist(
                        "requests-2.32.3.tar.gz",
                        "https://files.example/requests.tar.gz",
                    ),
                ],
            )]),
        };

        let artifact = registry
            .select_preferred_artifact(&package, &metadata)
            .expect("artifact should be selected");

        assert_eq!(artifact.artifact_type, PypiArtifactType::SourceDist);
        assert_eq!(artifact.filename, "requests-2.32.3.tar.gz");
    }

    #[test]
    fn falls_back_to_wheel_when_no_sdist_exists() {
        let registry = PypiRegistry::new();
        let package = package_version("requests", "2.32.3");
        let metadata = PypiPackageMetadata {
            info: PypiPackageInfo {
                version: Some("2.32.3".to_string()),
            },
            urls: vec![wheel(
                "requests-2.32.3-py3-none-any.whl",
                "https://files.example/requests.whl",
            )],
            releases: HashMap::new(),
        };

        let artifact = registry
            .select_preferred_artifact(&package, &metadata)
            .expect("wheel should be selected");

        assert_eq!(artifact.artifact_type, PypiArtifactType::Wheel);
        assert_eq!(artifact.filename, "requests-2.32.3-py3-none-any.whl");
    }

    #[test]
    fn rejects_release_without_supported_artifacts() {
        let registry = PypiRegistry::new();
        let package = package_version("requests", "2.32.3");
        let metadata = PypiPackageMetadata {
            info: PypiPackageInfo {
                version: Some("2.32.3".to_string()),
            },
            urls: vec![PypiDistributionFile {
                filename: Some("requests-2.32.3.exe".to_string()),
                packagetype: Some("bdist_egg".to_string()),
                url: Some("https://files.example/requests.exe".to_string()),
            }],
            releases: HashMap::new(),
        };

        let error = registry
            .select_preferred_artifact(&package, &metadata)
            .expect_err("unsupported artifacts should fail");

        assert_eq!(
            error.to_string(),
            "pypi release `pypi==requests` has no supported sdist or wheel artifact"
        );
    }

    #[test]
    fn fetches_latest_version_from_http_registry() {
        let server = TestServer::start(
            200,
            r#"{"info":{"version":"2.32.3"},"urls":[{"filename":"requests-2.32.3.tar.gz","packagetype":"sdist","url":"https://files.example/requests.tar.gz"}],"releases":{"2.32.3":[{"filename":"requests-2.32.3.tar.gz","packagetype":"sdist","url":"https://files.example/requests.tar.gz"}]}}"#,
        );
        let registry = PypiRegistry::with_metadata_base_url(server.base_url());

        let package = registry
            .latest_version("requests")
            .expect("latest version should load");
        let metadata = registry
            .fetch_package_metadata("requests")
            .expect("metadata should load");
        let artifact = registry
            .select_preferred_artifact(&package, &metadata)
            .expect("artifact should be selected");

        assert_eq!(package.package, "requests");
        assert_eq!(package.version, "2.32.3");
        assert_eq!(package.package_key(), "pypi:requests");
        assert_eq!(artifact.filename, "requests-2.32.3.tar.gz");
        assert_eq!(server.request_count(), 2);
        assert_eq!(server.last_request_path(), "/requests/json");
    }

    fn metadata_with_version(version: &str) -> PypiPackageMetadata {
        PypiPackageMetadata {
            info: PypiPackageInfo {
                version: Some(version.to_string()),
            },
            urls: Vec::new(),
            releases: HashMap::new(),
        }
    }

    fn package_version(package: &str, version: &str) -> PackageVersion {
        PackageVersion {
            ecosystem: Ecosystem::Pypi,
            package: package.to_string(),
            version: version.to_string(),
        }
    }

    fn sdist(filename: &str, url: &str) -> PypiDistributionFile {
        PypiDistributionFile {
            filename: Some(filename.to_string()),
            packagetype: Some("sdist".to_string()),
            url: Some(url.to_string()),
        }
    }

    fn wheel(filename: &str, url: &str) -> PypiDistributionFile {
        PypiDistributionFile {
            filename: Some(filename.to_string()),
            packagetype: Some("bdist_wheel".to_string()),
            url: Some(url.to_string()),
        }
    }

    struct TestServer {
        base_url: String,
        request_paths: Arc<Mutex<Vec<String>>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestServer {
        fn start(status_code: u16, body: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test server should bind");
            let address = listener.local_addr().expect("local addr should resolve");
            let base_url = format!("http://{}", address);

            let request_paths = Arc::new(Mutex::new(Vec::new()));
            let request_paths_for_thread = request_paths.clone();

            let thread = thread::spawn(move || {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().expect("request should arrive");
                    let mut buffer = [0_u8; 4096];
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
                    request_paths_for_thread
                        .lock()
                        .expect("path lock should succeed")
                        .push(path);

                    let response = format!(
                        "HTTP/1.1 {status_code} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("response should be written");
                }
            });

            Self {
                base_url,
                request_paths,
                thread: Some(thread),
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn request_count(&self) -> usize {
            self.request_paths
                .lock()
                .expect("path lock should succeed")
                .len()
        }

        fn last_request_path(mut self) -> String {
            if let Some(thread) = self.thread.take() {
                thread.join().expect("server thread should finish");
            }
            self.request_paths
                .lock()
                .expect("path lock should succeed")
                .last()
                .cloned()
                .unwrap_or_default()
        }
    }
}
