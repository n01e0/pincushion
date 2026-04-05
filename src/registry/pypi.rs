use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use reqwest::Url;
use serde::Deserialize;

use crate::fetch::{ArtifactCache, ArtifactMetadata, DownloadPolicy, FetchRequest, SafeDownloader};
use crate::state::version_scoped_state_directory;
use crate::unpack::SafeUnpacker;

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

    fn download_policy_for(&self, artifact_url: &str) -> RegistryResult<DownloadPolicy> {
        let parsed = Url::parse(artifact_url).map_err(|source| {
            RegistryError::new(format!(
                "pypi artifact url `{artifact_url}` is invalid: {source}"
            ))
        })?;

        let mut policy = DownloadPolicy {
            https_only: parsed.scheme() != "http",
            ..DownloadPolicy::default()
        };

        if let Some(host) = parsed.host_str() {
            policy.allowed_hosts = vec![host.to_string()];
        }

        Ok(policy)
    }

    fn cache_from_destination(
        &self,
        package_version: &PackageVersion,
        destination: &Path,
    ) -> RegistryResult<ArtifactCache> {
        let Some(cache_root) = destination.ancestors().nth(3) else {
            return Err(RegistryError::new(format!(
                "pypi artifact destination `{}` is not under a version-scoped cache directory",
                destination.display()
            )));
        };

        let expected_destination = version_scoped_state_directory(cache_root, package_version);
        if expected_destination != destination {
            return Err(RegistryError::new(format!(
                "pypi artifact destination `{}` does not match the version-scoped cache path `{}`",
                destination.display(),
                expected_destination.display()
            )));
        }

        Ok(ArtifactCache::new(cache_root))
    }

    fn fetch_request_for(&self, artifact: &PypiArtifact) -> FetchRequest {
        FetchRequest {
            url: artifact.url.clone(),
            artifact_metadata: Some(ArtifactMetadata {
                filename: artifact.filename.clone(),
                size_bytes: artifact.size_bytes,
            }),
        }
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
        package: &PackageVersion,
        destination: &Path,
    ) -> RegistryResult<DownloadedArtifact> {
        let metadata = self.fetch_package_metadata(&package.package)?;
        let artifact = self.select_preferred_artifact(package, &metadata)?;
        let cache = self.cache_from_destination(package, destination)?;
        let downloader =
            SafeDownloader::new(self.download_policy_for(&artifact.url)?).map_err(|source| {
                RegistryError::new(format!(
                    "failed to build pypi downloader for `{}` version `{}`: {source}",
                    package.package, package.version
                ))
            })?;
        let request = self.fetch_request_for(&artifact);

        cache
            .fetch(&downloader, package, &request)
            .map(|cached| cached.artifact)
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to download pypi artifact for `{}` version `{}`: {source}",
                    package.package, package.version
                ))
            })
    }

    fn unpack(&self, artifact: &Path, destination: &Path) -> RegistryResult<()> {
        let unpacker = SafeUnpacker::default();
        let file_name = artifact
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        let result = if file_name.ends_with(".whl") {
            unpacker.unpack_wheel(artifact, destination)
        } else if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") {
            unpacker.unpack_tar_gz(artifact, destination)
        } else if file_name.ends_with(".zip") {
            unpacker.unpack_zip(artifact, destination)
        } else {
            return Err(RegistryError::new(format!(
                "unsupported pypi artifact format for {}",
                artifact.display()
            )));
        };

        result.map(|_| ()).map_err(|source| {
            RegistryError::new(format!(
                "failed to unpack pypi artifact {} into {}: {source}",
                artifact.display(),
                destination.display()
            ))
        })
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
    #[serde(default, alias = "size")]
    size_bytes: Option<u64>,
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
    size_bytes: Option<u64>,
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
            size_bytes: file.size_bytes,
            artifact_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::{Builder, Header};
    use zip::write::FileOptions;
    use zip::ZipWriter;

    use crate::state::StateLayout;

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
        assert_eq!(artifact.size_bytes, None);
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
                size_bytes: None,
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
    fn downloads_sdist_artifact_when_available() {
        let server = RequestSequenceServer::start_with_builder(|base_url| {
            vec![
                ResponseSpec::json(
                    200,
                    "/requests/json",
                    format!(
                        "{{\"info\":{{\"version\":\"2.32.3\"}},\"urls\":[],\"releases\":{{\"2.32.3\":[{{\"filename\":\"requests-2.32.3-py3-none-any.whl\",\"packagetype\":\"bdist_wheel\",\"url\":\"{base_url}/files/requests-2.32.3-py3-none-any.whl\",\"size\":11}},{{\"filename\":\"requests-2.32.3.tar.gz\",\"packagetype\":\"sdist\",\"url\":\"{base_url}/files/requests-2.32.3.tar.gz\",\"size\":13}}]}}}}"
                    ),
                ),
                ResponseSpec::get(200, "/files/requests-2.32.3.tar.gz", "sdist package"),
            ]
        });
        let registry = PypiRegistry::with_metadata_base_url(server.base_url());
        let package = package_version("requests", "2.32.3");
        let fixture = TestDir::new("pypi-download-sdist");
        let state_layout =
            StateLayout::from_repo_root(fixture.path()).expect("state layout should build");
        let destination = state_layout.artifact_cache_dir_for(&package);

        let downloaded = registry
            .download_artifact(&package, &destination)
            .expect("sdist download should succeed");

        assert_eq!(downloaded.path, destination.join("requests-2.32.3.tar.gz"));
        assert_eq!(
            fs::read_to_string(&downloaded.path).expect("artifact should be readable"),
            "sdist package"
        );
        assert_eq!(
            server.request_log(),
            vec![
                "GET /requests/json".to_string(),
                "GET /files/requests-2.32.3.tar.gz".to_string()
            ]
        );
    }

    #[test]
    fn downloads_wheel_when_no_sdist_exists() {
        let server = RequestSequenceServer::start_with_builder(|base_url| {
            vec![
                ResponseSpec::json(
                    200,
                    "/requests/json",
                    format!(
                        "{{\"info\":{{\"version\":\"2.32.3\"}},\"urls\":[{{\"filename\":\"requests-2.32.3-py3-none-any.whl\",\"packagetype\":\"bdist_wheel\",\"url\":\"{base_url}/files/requests-2.32.3-py3-none-any.whl\",\"size\":11}}],\"releases\":{{}}}}"
                    ),
                ),
                ResponseSpec::get(
                    200,
                    "/files/requests-2.32.3-py3-none-any.whl",
                    "wheel bytes",
                ),
            ]
        });
        let registry = PypiRegistry::with_metadata_base_url(server.base_url());
        let package = package_version("requests", "2.32.3");
        let fixture = TestDir::new("pypi-download-wheel");
        let state_layout =
            StateLayout::from_repo_root(fixture.path()).expect("state layout should build");
        let destination = state_layout.artifact_cache_dir_for(&package);

        let downloaded = registry
            .download_artifact(&package, &destination)
            .expect("wheel download should succeed");

        assert_eq!(
            downloaded.path,
            destination.join("requests-2.32.3-py3-none-any.whl")
        );
        assert_eq!(
            fs::read_to_string(&downloaded.path).expect("artifact should be readable"),
            "wheel bytes"
        );
        assert_eq!(
            server.request_log(),
            vec![
                "GET /requests/json".to_string(),
                "GET /files/requests-2.32.3-py3-none-any.whl".to_string()
            ]
        );
    }

    #[test]
    fn unpacks_sdist_tar_gz_artifacts_safely() {
        let registry = PypiRegistry::new();
        let fixture = TestDir::new("pypi-unpack-sdist");
        let artifact = fixture.path().join("requests-2.32.3.tar.gz");
        let destination = fixture.path().join("out");
        write_tar_gz_archive(
            &artifact,
            &[
                ArchiveFile::new("requests-2.32.3/README.md", b"hello\n"),
                ArchiveFile::new(
                    "requests-2.32.3/src/requests/__init__.py",
                    b"__version__ = '2.32.3'\n",
                ),
            ],
        )
        .expect("sdist archive should be created");

        registry
            .unpack(&artifact, &destination)
            .expect("sdist should unpack");

        assert_eq!(
            fs::read_to_string(destination.join("requests-2.32.3/README.md"))
                .expect("readme should exist"),
            "hello\n"
        );
        assert_eq!(
            fs::read_to_string(destination.join("requests-2.32.3/src/requests/__init__.py"))
                .expect("package init should exist"),
            "__version__ = '2.32.3'\n"
        );
    }

    #[test]
    fn unpacks_wheel_artifacts_safely() {
        let registry = PypiRegistry::new();
        let fixture = TestDir::new("pypi-unpack-wheel");
        let artifact = fixture.path().join("requests-2.32.3-py3-none-any.whl");
        let destination = fixture.path().join("out");
        write_zip_archive(
            &artifact,
            &[
                ArchiveFile::new("requests/__init__.py", b"__version__ = '2.32.3'\n"),
                ArchiveFile::new(
                    "requests-2.32.3.dist-info/METADATA",
                    b"Name: requests\nVersion: 2.32.3\n",
                ),
            ],
        )
        .expect("wheel archive should be created");

        registry
            .unpack(&artifact, &destination)
            .expect("wheel should unpack");

        assert_eq!(
            fs::read_to_string(destination.join("requests/__init__.py"))
                .expect("package init should exist"),
            "__version__ = '2.32.3'\n"
        );
        assert_eq!(
            fs::read_to_string(destination.join("requests-2.32.3.dist-info/METADATA"))
                .expect("metadata should exist"),
            "Name: requests\nVersion: 2.32.3\n"
        );
    }

    #[test]
    fn rejects_download_destination_outside_version_scoped_cache() {
        let registry = PypiRegistry::new();
        let package = package_version("requests", "2.32.3");
        let fixture = TestDir::new("pypi-download-destination");
        let invalid_destination = fixture.path().join("artifacts").join("requests");

        let error = registry
            .cache_from_destination(&package, &invalid_destination)
            .expect_err("invalid cache destination should fail");

        assert!(error
            .to_string()
            .contains("does not match the version-scoped cache path"));
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
            size_bytes: None,
        }
    }

    fn wheel(filename: &str, url: &str) -> PypiDistributionFile {
        PypiDistributionFile {
            filename: Some(filename.to_string()),
            packagetype: Some("bdist_wheel".to_string()),
            url: Some(url.to_string()),
            size_bytes: None,
        }
    }

    #[derive(Debug, Clone)]
    struct ResponseSpec {
        status_code: u16,
        method: String,
        path: String,
        content_type: &'static str,
        body: Vec<u8>,
    }

    impl ResponseSpec {
        fn json(status_code: u16, path: &str, body: impl AsRef<[u8]>) -> Self {
            Self {
                status_code,
                method: "GET".to_string(),
                path: path.to_string(),
                content_type: "application/json",
                body: body.as_ref().to_vec(),
            }
        }

        fn get(status_code: u16, path: &str, body: impl AsRef<[u8]>) -> Self {
            Self {
                status_code,
                method: "GET".to_string(),
                path: path.to_string(),
                content_type: "application/octet-stream",
                body: body.as_ref().to_vec(),
            }
        }
    }

    struct RequestSequenceServer {
        base_url: String,
        request_log: Arc<Mutex<Vec<String>>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl RequestSequenceServer {
        fn start_with_builder(
            build_responses: impl FnOnce(&str) -> Vec<ResponseSpec> + Send + 'static,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test server should bind");
            let address = listener.local_addr().expect("local addr should resolve");
            let base_url = format!("http://{}", address);
            let responses = build_responses(&base_url);
            Self::spawn(listener, base_url, responses)
        }

        fn spawn(listener: TcpListener, base_url: String, responses: Vec<ResponseSpec>) -> Self {
            let request_log = Arc::new(Mutex::new(Vec::new()));
            let request_log_for_thread = request_log.clone();

            let thread = thread::spawn(move || {
                for response_spec in responses {
                    let (mut stream, _) = listener.accept().expect("request should arrive");
                    let mut buffer = [0_u8; 4096];
                    let read = stream
                        .read(&mut buffer)
                        .expect("request should be readable");
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let mut request_line_parts =
                        request.lines().next().unwrap_or("").split_whitespace();
                    let method = request_line_parts.next().unwrap_or("");
                    let path = request_line_parts.next().unwrap_or("");
                    request_log_for_thread
                        .lock()
                        .expect("request log lock should succeed")
                        .push(format!("{method} {path}"));
                    assert_eq!(method, response_spec.method, "unexpected request method");
                    assert_eq!(path, response_spec.path, "unexpected request path");

                    let mut response = format!(
                        "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
                        response_spec.status_code,
                        response_spec.body.len(),
                        response_spec.content_type,
                    )
                    .into_bytes();
                    response.extend_from_slice(&response_spec.body);
                    stream
                        .write_all(&response)
                        .expect("response should be written");
                }
            });

            Self {
                base_url,
                request_log,
                thread: Some(thread),
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn request_log(mut self) -> Vec<String> {
            if let Some(thread) = self.thread.take() {
                thread.join().expect("server thread should finish");
            }
            self.request_log
                .lock()
                .expect("request log lock should succeed")
                .clone()
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

    struct ArchiveFile<'a> {
        path: &'a str,
        contents: &'a [u8],
    }

    impl<'a> ArchiveFile<'a> {
        fn new(path: &'a str, contents: &'a [u8]) -> Self {
            Self { path, contents }
        }
    }

    fn write_tar_gz_archive(path: &Path, files: &[ArchiveFile<'_>]) -> std::io::Result<()> {
        let file = fs::File::create(path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);

        for file in files {
            let mut header = Header::new_gnu();
            header.set_path(file.path)?;
            header.set_mode(0o644);
            header.set_size(file.contents.len() as u64);
            header.set_cksum();
            builder.append(&header, Cursor::new(file.contents))?;
        }

        let encoder = builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

    fn write_zip_archive(path: &Path, files: &[ArchiveFile<'_>]) -> std::io::Result<()> {
        let file = fs::File::create(path)?;
        let mut writer = ZipWriter::new(file);

        for file in files {
            writer.start_file(file.path, FileOptions::default())?;
            writer.write_all(file.contents)?;
        }

        writer.finish()?;
        Ok(())
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos();
            let path = env::temp_dir().join(format!("pincushion-pypi-{label}-{unique}"));
            fs::create_dir_all(&path).expect("test dir should be created");
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
