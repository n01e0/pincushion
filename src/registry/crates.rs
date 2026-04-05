use std::path::Path;
use std::time::Duration;

use reqwest::header::CONTENT_LENGTH;
use reqwest::Url;
use serde::Deserialize;

use crate::fetch::{ArtifactCache, ArtifactMetadata, DownloadPolicy, FetchRequest, SafeDownloader};
use crate::state::version_scoped_state_directory;
use crate::unpack::SafeUnpacker;

use super::{
    blocking_metadata_client, DownloadedArtifact, Ecosystem, PackageVersion, Registry,
    RegistryError, RegistryResult,
};

const DEFAULT_METADATA_BASE_URL: &str = "https://crates.io/api/v1/crates";
const DEFAULT_DOWNLOAD_BASE_URL: &str = "https://crates.io/api/v1/crates";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CratesRegistry {
    metadata_base_url: String,
    download_base_url: String,
}

impl CratesRegistry {
    pub fn new() -> Self {
        Self {
            metadata_base_url: DEFAULT_METADATA_BASE_URL.to_string(),
            download_base_url: DEFAULT_DOWNLOAD_BASE_URL.to_string(),
        }
    }

    fn with_metadata_base_url(metadata_base_url: impl Into<String>) -> Self {
        Self {
            metadata_base_url: metadata_base_url.into().trim_end_matches('/').to_string(),
            download_base_url: DEFAULT_DOWNLOAD_BASE_URL.to_string(),
        }
    }

    fn with_base_urls(
        metadata_base_url: impl Into<String>,
        download_base_url: impl Into<String>,
    ) -> Self {
        Self {
            metadata_base_url: metadata_base_url.into().trim_end_matches('/').to_string(),
            download_base_url: download_base_url.into().trim_end_matches('/').to_string(),
        }
    }

    fn metadata_url(&self, package: &str) -> String {
        format!("{}/{}", self.metadata_base_url, package)
    }

    fn download_url(&self, package_version: &PackageVersion) -> String {
        format!(
            "{}/{}/{}/download",
            self.download_base_url, package_version.package, package_version.version
        )
    }

    fn fetch_package_metadata(&self, package: &str) -> RegistryResult<CratesPackageMetadata> {
        blocking_metadata_client(Duration::from_secs(15))?
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
            })?
            .json::<CratesPackageMetadata>()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to parse crates.io metadata for `{package}`: {source}"
                ))
            })
    }

    fn resolve_artifact(&self, package_version: &PackageVersion) -> RegistryResult<CratesArtifact> {
        let download_url = self.download_url(package_version);
        let filename = artifact_filename_for(package_version);
        let size_bytes = self.fetch_artifact_size_bytes(&download_url)?;

        Ok(CratesArtifact {
            url: download_url,
            metadata: ArtifactMetadata {
                filename,
                size_bytes: Some(size_bytes),
            },
        })
    }

    fn fetch_artifact_size_bytes(&self, download_url: &str) -> RegistryResult<u64> {
        let response = blocking_metadata_client(Duration::from_secs(15))?
            .head(download_url)
            .send()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to fetch crates.io artifact headers for `{download_url}`: {source}"
                ))
            })?
            .error_for_status()
            .map_err(|source| {
                RegistryError::new(format!(
                    "crates.io artifact header request for `{download_url}` failed: {source}"
                ))
            })?;

        let content_length = response
            .headers()
            .get(CONTENT_LENGTH)
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "crates.io artifact header response for `{download_url}` is missing content-length"
                ))
            })?
            .to_str()
            .map_err(|source| {
                RegistryError::new(format!(
                    "crates.io artifact header response for `{download_url}` returned an invalid content-length: {source}"
                ))
            })?
            .parse::<u64>()
            .map_err(|source| {
                RegistryError::new(format!(
                    "crates.io artifact header response for `{download_url}` returned a non-numeric content-length: {source}"
                ))
            })?;

        Ok(content_length)
    }

    fn download_policy_for(&self, download_url: &str) -> RegistryResult<DownloadPolicy> {
        let parsed = Url::parse(download_url).map_err(|source| {
            RegistryError::new(format!(
                "crates.io artifact url `{download_url}` is invalid: {source}"
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
                "crates.io artifact destination `{}` is not under a version-scoped cache directory",
                destination.display()
            )));
        };

        let expected_destination = version_scoped_state_directory(cache_root, package_version);
        if expected_destination != destination {
            return Err(RegistryError::new(format!(
                "crates.io artifact destination `{}` does not match the version-scoped cache path `{}`",
                destination.display(),
                expected_destination.display()
            )));
        }

        Ok(ArtifactCache::new(cache_root))
    }

    fn fetch_request_for(&self, artifact: &CratesArtifact) -> FetchRequest {
        FetchRequest {
            url: artifact.url.clone(),
            artifact_metadata: Some(artifact.metadata.clone()),
        }
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
        let metadata = self.fetch_package_metadata(package)?;
        self.parse_latest_version(package, metadata)
    }

    fn download_artifact(
        &self,
        package: &PackageVersion,
        destination: &Path,
    ) -> RegistryResult<DownloadedArtifact> {
        let artifact = self.resolve_artifact(package)?;
        let cache = self.cache_from_destination(package, destination)?;
        let downloader =
            SafeDownloader::new(self.download_policy_for(&artifact.url)?).map_err(|source| {
                RegistryError::new(format!(
                    "failed to build crates.io downloader for `{}` version `{}`: {source}",
                    package.package, package.version
                ))
            })?;
        let request = self.fetch_request_for(&artifact);

        cache
            .fetch(&downloader, package, &request)
            .map(|cached| cached.artifact)
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to download crates.io artifact for `{}` version `{}`: {source}",
                    package.package, package.version
                ))
            })
    }

    fn unpack(&self, artifact: &Path, destination: &Path) -> RegistryResult<()> {
        SafeUnpacker::default()
            .unpack_crate(artifact, destination)
            .map(|_| ())
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to unpack crates.io artifact {} into {}: {source}",
                    artifact.display(),
                    destination.display()
                ))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CratesArtifact {
    url: String,
    metadata: ArtifactMetadata,
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

fn artifact_filename_for(package_version: &PackageVersion) -> String {
    format!(
        "{}-{}.crate",
        package_version.package, package_version.version
    )
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

    use crate::artifact_pipeline::{process_version_change, ArtifactWorkspace};
    use crate::http;
    use crate::state::{StateLayout, VersionChange};

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
    fn resolves_artifact_metadata_for_crate_download() {
        let registry = CratesRegistry::new();
        let artifact = CratesArtifact {
            url: registry.download_url(&package_version("clap", "4.5.31")),
            metadata: ArtifactMetadata {
                filename: artifact_filename_for(&package_version("clap", "4.5.31")),
                size_bytes: Some(4_321),
            },
        };

        assert_eq!(
            artifact.url,
            "https://crates.io/api/v1/crates/clap/4.5.31/download"
        );
        assert_eq!(artifact.metadata.filename, "clap-4.5.31.crate");
        assert_eq!(artifact.metadata.size_bytes, Some(4_321));
    }

    #[test]
    fn resolves_artifact_via_http_download_head_lookup() {
        let server = RequestSequenceServer::start_with_builder(|_base_url| {
            vec![ResponseSpec::head(
                200,
                "/api/v1/crates/clap/4.5.31/download",
                Some(4_321),
            )]
        });
        let registry =
            CratesRegistry::with_base_urls(server.metadata_base_url(), server.download_base_url());

        let artifact = registry
            .resolve_artifact(&package_version("clap", "4.5.31"))
            .expect("crate artifact metadata should resolve");

        assert_eq!(
            artifact.url,
            format!("{}/clap/4.5.31/download", server.download_base_url())
        );
        assert_eq!(artifact.metadata.filename, "clap-4.5.31.crate");
        assert_eq!(artifact.metadata.size_bytes, Some(4_321));
        assert_eq!(
            server.request_log(),
            vec!["HEAD /api/v1/crates/clap/4.5.31/download".to_string()]
        );
    }

    #[test]
    fn downloads_artifact_through_safe_downloader_and_cache() {
        let server = RequestSequenceServer::start_with_builder(|_base_url| {
            vec![
                ResponseSpec::head(200, "/api/v1/crates/clap/4.5.31/download", Some(18)),
                ResponseSpec::redirect(
                    "/api/v1/crates/clap/4.5.31/download",
                    "/files/clap-4.5.31.crate",
                ),
                ResponseSpec::get(200, "/files/clap-4.5.31.crate", "crate tarball body"),
                ResponseSpec::head(200, "/api/v1/crates/clap/4.5.31/download", Some(18)),
            ]
        });
        let registry =
            CratesRegistry::with_base_urls(server.metadata_base_url(), server.download_base_url());
        let package = package_version("clap", "4.5.31");
        let fixture = TestDir::new("crates-download-cache");
        let state_layout =
            StateLayout::from_repo_root(fixture.path()).expect("state layout should build");
        let destination = state_layout.artifact_cache_dir_for(&package);

        let first = registry
            .download_artifact(&package, &destination)
            .expect("first artifact download should succeed");
        let second = registry
            .download_artifact(&package, &destination)
            .expect("second artifact download should hit cache");

        assert_eq!(first.path, destination.join("clap-4.5.31.crate"));
        assert_eq!(second.path, first.path);
        assert_eq!(
            fs::read_to_string(&first.path).expect("artifact should be readable"),
            "crate tarball body"
        );
        assert_eq!(
            server.request_log(),
            vec![
                "HEAD /api/v1/crates/clap/4.5.31/download".to_string(),
                "GET /api/v1/crates/clap/4.5.31/download".to_string(),
                "GET /files/clap-4.5.31.crate".to_string(),
                "HEAD /api/v1/crates/clap/4.5.31/download".to_string(),
            ]
        );
    }

    #[test]
    fn processes_changed_crate_package_through_fetch_unpack_and_diff_summary() {
        let old_crate = crate_archive_bytes(&[
            ArchiveFile::new("crate/README.md", b"old readme\n"),
            ArchiveFile::new(
                "crate/src/lib.rs",
                b"pub fn clap() {\n    println!(\"old\");\n}\n",
            ),
        ])
        .expect("old crate should be created");
        let new_crate = crate_archive_bytes(&[
            ArchiveFile::new(
                "crate/src/lib.rs",
                b"pub fn clap() {\n    println!(\"new\");\n}\n",
            ),
            ArchiveFile::new("crate/src/derive.rs", b"pub fn derive() {}\n"),
        ])
        .expect("new crate should be created");
        let old_size = old_crate.len() as u64;
        let new_size = new_crate.len() as u64;

        let server = RequestSequenceServer::start_with_builder(move |_base_url| {
            vec![
                ResponseSpec::head(200, "/api/v1/crates/clap/4.5.30/download", Some(old_size)),
                ResponseSpec::redirect(
                    "/api/v1/crates/clap/4.5.30/download",
                    "/files/clap-4.5.30.crate",
                ),
                ResponseSpec::get(200, "/files/clap-4.5.30.crate", old_crate),
                ResponseSpec::head(200, "/api/v1/crates/clap/4.5.31/download", Some(new_size)),
                ResponseSpec::redirect(
                    "/api/v1/crates/clap/4.5.31/download",
                    "/files/clap-4.5.31.crate",
                ),
                ResponseSpec::get(200, "/files/clap-4.5.31.crate", new_crate),
            ]
        });
        let registry =
            CratesRegistry::with_base_urls(server.metadata_base_url(), server.download_base_url());
        let fixture = TestDir::new("crates-changed-package");
        let state_layout =
            StateLayout::from_repo_root(fixture.path()).expect("state layout should build");
        let workspace = ArtifactWorkspace::from_state_layout(&state_layout);

        let result = process_version_change(
            &registry,
            &version_change("clap", "4.5.30", "4.5.31"),
            &workspace,
        )
        .expect("crate changed package should process successfully");

        assert_eq!(result.previous_package.version, "4.5.30");
        assert_eq!(result.current_package.version, "4.5.31");
        assert_eq!(result.analysis.diff.files_added, 1);
        assert_eq!(result.analysis.diff.files_removed, 1);
        assert_eq!(result.analysis.diff.files_changed, 1);
        assert_eq!(
            result.analysis.diff.added_paths,
            vec!["crate/src/derive.rs"]
        );
        assert_eq!(result.analysis.diff.removed_paths, vec!["crate/README.md"]);
        assert_eq!(
            result.analysis.diff.modified_paths,
            vec!["crate/src/lib.rs"]
        );
        assert!(result.current_root.join("crate/src/derive.rs").exists());
        assert_eq!(
            fs::read_to_string(result.current_root.join("crate/src/lib.rs"))
                .expect("crate source should exist"),
            "pub fn clap() {\n    println!(\"new\");\n}\n"
        );
        assert_eq!(
            server.request_log(),
            vec![
                "HEAD /api/v1/crates/clap/4.5.30/download".to_string(),
                "GET /api/v1/crates/clap/4.5.30/download".to_string(),
                "GET /files/clap-4.5.30.crate".to_string(),
                "HEAD /api/v1/crates/clap/4.5.31/download".to_string(),
                "GET /api/v1/crates/clap/4.5.31/download".to_string(),
                "GET /files/clap-4.5.31.crate".to_string(),
            ]
        );
    }

    #[test]
    fn unpacks_crate_artifacts_safely() {
        let registry = CratesRegistry::new();
        let fixture = TestDir::new("crates-unpack");
        let artifact = fixture.path().join("clap-4.5.31.crate");
        let destination = fixture.path().join("out");
        write_crate_archive(
            &artifact,
            &[
                ArchiveFile::new("clap-4.5.31/Cargo.toml", b"[package]\nname = \"clap\"\n"),
                ArchiveFile::new("clap-4.5.31/src/lib.rs", b"pub fn clap() {}\n"),
            ],
        )
        .expect("crate archive should be created");

        registry
            .unpack(&artifact, &destination)
            .expect("crate should unpack");

        assert_eq!(
            fs::read_to_string(destination.join("clap-4.5.31/Cargo.toml"))
                .expect("cargo manifest should exist"),
            "[package]\nname = \"clap\"\n"
        );
        assert_eq!(
            fs::read_to_string(destination.join("clap-4.5.31/src/lib.rs"))
                .expect("crate source should exist"),
            "pub fn clap() {}\n"
        );
    }

    #[test]
    fn rejects_download_destination_outside_version_scoped_cache() {
        let registry = CratesRegistry::new();
        let package = package_version("clap", "4.5.31");
        let fixture = TestDir::new("crates-download-destination");
        let invalid_destination = fixture.path().join("artifacts").join("clap");

        let error = registry
            .cache_from_destination(&package, &invalid_destination)
            .expect_err("invalid cache destination should fail");

        assert!(error
            .to_string()
            .contains("does not match the version-scoped cache path"));
    }

    #[test]
    fn rejects_artifact_header_responses_without_content_length() {
        let server = RequestSequenceServer::start(vec![ResponseSpec::head(
            200,
            "/api/v1/crates/clap/4.5.31/download",
            None,
        )]);
        let registry =
            CratesRegistry::with_base_urls(server.metadata_base_url(), server.download_base_url());

        let error = registry
            .fetch_artifact_size_bytes(&format!(
                "{}/clap/4.5.31/download",
                server.download_base_url()
            ))
            .expect_err("missing content-length should fail");

        assert_eq!(
            error.to_string(),
            format!(
                "crates.io artifact header response for `{}/clap/4.5.31/download` is missing content-length",
                server.download_base_url()
            )
        );
        assert_eq!(
            server.request_log(),
            vec!["HEAD /api/v1/crates/clap/4.5.31/download".to_string()]
        );
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

    fn package_version(package: &str, version: &str) -> PackageVersion {
        PackageVersion {
            ecosystem: Ecosystem::Crates,
            package: package.to_string(),
            version: version.to_string(),
        }
    }

    fn version_change(
        package: &str,
        previous_version: &str,
        current_version: &str,
    ) -> VersionChange {
        VersionChange {
            package: package_version(package, current_version),
            previous_version: previous_version.to_string(),
        }
    }

    #[derive(Debug, Clone)]
    struct ResponseSpec {
        status_code: u16,
        method: String,
        path: String,
        content_type: &'static str,
        body: Vec<u8>,
        content_length: Option<u64>,
        extra_headers: Vec<(String, String)>,
    }

    impl ResponseSpec {
        fn get(status_code: u16, path: &str, body: impl AsRef<[u8]>) -> Self {
            Self {
                status_code,
                method: "GET".to_string(),
                path: path.to_string(),
                content_type: "application/octet-stream",
                body: body.as_ref().to_vec(),
                content_length: None,
                extra_headers: Vec::new(),
            }
        }

        fn redirect(path: &str, location: &str) -> Self {
            Self {
                status_code: 302,
                method: "GET".to_string(),
                path: path.to_string(),
                content_type: "text/plain",
                body: Vec::new(),
                content_length: Some(0),
                extra_headers: vec![("Location".to_string(), location.to_string())],
            }
        }

        fn head(status_code: u16, path: &str, content_length: Option<u64>) -> Self {
            Self {
                status_code,
                method: "HEAD".to_string(),
                path: path.to_string(),
                content_type: "application/octet-stream",
                body: Vec::new(),
                content_length,
                extra_headers: Vec::new(),
            }
        }
    }

    struct RequestSequenceServer {
        root_url: String,
        request_log: Arc<Mutex<Vec<String>>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl RequestSequenceServer {
        fn start_with_builder(
            build_responses: impl FnOnce(&str) -> Vec<ResponseSpec> + Send + 'static,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test server should bind");
            let address = listener.local_addr().expect("local addr should resolve");
            let root_url = format!("http://{}", address);
            let responses = build_responses(&root_url);
            Self::spawn(listener, root_url, responses)
        }

        fn start(responses: Vec<ResponseSpec>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test server should bind");
            let address = listener.local_addr().expect("local addr should resolve");
            let root_url = format!("http://{}", address);
            Self::spawn(listener, root_url, responses)
        }

        fn spawn(listener: TcpListener, root_url: String, responses: Vec<ResponseSpec>) -> Self {
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
                        "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nConnection: close\r\n",
                        response_spec.status_code, response_spec.content_type
                    );
                    if let Some(content_length) = response_spec.content_length {
                        response.push_str(&format!("Content-Length: {content_length}\r\n"));
                    }
                    if response_spec.method != "HEAD" && response_spec.content_length.is_none() {
                        response
                            .push_str(&format!("Content-Length: {}\r\n", response_spec.body.len()));
                    }
                    for (name, value) in &response_spec.extra_headers {
                        response.push_str(&format!("{name}: {value}\r\n"));
                    }
                    response.push_str("\r\n");
                    let mut response_bytes = response.into_bytes();
                    if response_spec.method != "HEAD" {
                        response_bytes.extend_from_slice(&response_spec.body);
                    }
                    stream
                        .write_all(&response_bytes)
                        .expect("response should be written");
                }
            });

            Self {
                root_url,
                request_log,
                thread: Some(thread),
            }
        }

        fn metadata_base_url(&self) -> String {
            format!("{}/api/v1/crates", self.root_url)
        }

        fn download_base_url(&self) -> String {
            format!("{}/api/v1/crates", self.root_url)
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

    #[test]
    fn sends_user_agent_when_fetching_crates_metadata() {
        let server = TestServer::start(
            200,
            r#"{"crate":{"max_stable_version":"4.5.31","newest_version":"4.5.31"}}"#,
        );
        let registry = CratesRegistry::with_metadata_base_url(server.base_url());

        registry
            .latest_version("clap")
            .expect("latest version should load");

        let request = server.request_raw();
        let expected = format!("user-agent: {}", http::user_agent().to_ascii_lowercase());
        assert!(
            request.to_ascii_lowercase().contains(&expected),
            "expected request to contain `{expected}`, got:\n{request}"
        );
    }

    struct TestServer {
        base_url: String,
        request_path: Arc<Mutex<String>>,
        request_raw: Arc<Mutex<String>>,
        thread: Option<thread::JoinHandle<()>>,
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

    fn write_crate_archive(path: &Path, files: &[ArchiveFile<'_>]) -> std::io::Result<()> {
        fs::write(path, crate_archive_bytes(files)?)
    }

    fn crate_archive_bytes(files: &[ArchiveFile<'_>]) -> std::io::Result<Vec<u8>> {
        let cursor = Cursor::new(Vec::new());
        let encoder = GzEncoder::new(cursor, Compression::default());
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
        let cursor = encoder.finish()?;
        Ok(cursor.into_inner())
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
            let path = env::temp_dir().join(format!("pincushion-crates-{label}-{unique}"));
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

    impl TestServer {
        fn start(status_code: u16, body: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test server should bind");
            let address = listener.local_addr().expect("local addr should resolve");
            let base_url = format!("http://{}", address);

            let request_path = Arc::new(Mutex::new(String::new()));
            let request_path_for_thread = request_path.clone();
            let request_raw = Arc::new(Mutex::new(String::new()));
            let request_raw_for_thread = request_raw.clone();

            let thread = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0_u8; 2048];
                let read = stream
                    .read(&mut buffer)
                    .expect("request should be readable");
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                *request_path_for_thread
                    .lock()
                    .expect("path lock should succeed") = path;
                *request_raw_for_thread
                    .lock()
                    .expect("raw request lock should succeed") = request.clone();

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
                request_raw,
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

        fn request_raw(mut self) -> String {
            if let Some(thread) = self.thread.take() {
                thread.join().expect("server thread should finish");
            }
            self.request_raw
                .lock()
                .expect("raw request lock should succeed")
                .clone()
        }
    }
}
