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

const DEFAULT_METADATA_BASE_URL: &str = "https://rubygems.org/api/v1/gems";
const DEFAULT_VERSION_METADATA_BASE_URL: &str = "https://rubygems.org/api/v2/rubygems";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubygemsRegistry {
    metadata_base_url: String,
    version_metadata_base_url: String,
}

impl RubygemsRegistry {
    pub fn new() -> Self {
        Self {
            metadata_base_url: DEFAULT_METADATA_BASE_URL.to_string(),
            version_metadata_base_url: DEFAULT_VERSION_METADATA_BASE_URL.to_string(),
        }
    }

    fn with_metadata_base_url(metadata_base_url: impl Into<String>) -> Self {
        Self {
            metadata_base_url: metadata_base_url.into().trim_end_matches('/').to_string(),
            version_metadata_base_url: DEFAULT_VERSION_METADATA_BASE_URL.to_string(),
        }
    }

    fn with_base_urls(
        metadata_base_url: impl Into<String>,
        version_metadata_base_url: impl Into<String>,
    ) -> Self {
        Self {
            metadata_base_url: metadata_base_url.into().trim_end_matches('/').to_string(),
            version_metadata_base_url: version_metadata_base_url
                .into()
                .trim_end_matches('/')
                .to_string(),
        }
    }

    fn metadata_url(&self, package: &str) -> String {
        format!("{}/{}.json", self.metadata_base_url, package)
    }

    fn version_metadata_url(&self, package_version: &PackageVersion) -> String {
        format!(
            "{}/{}/versions/{}.json",
            self.version_metadata_base_url, package_version.package, package_version.version
        )
    }

    fn fetch_package_metadata(&self, package: &str) -> RegistryResult<RubygemsPackageMetadata> {
        blocking_metadata_client(Duration::from_secs(15))?
            .get(self.metadata_url(package))
            .send()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to fetch rubygems metadata for `{package}`: {source}"
                ))
            })?
            .error_for_status()
            .map_err(|source| {
                RegistryError::new(format!(
                    "rubygems metadata request for `{package}` failed: {source}"
                ))
            })?
            .json::<RubygemsPackageMetadata>()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to parse rubygems metadata for `{package}`: {source}"
                ))
            })
    }

    fn fetch_version_metadata(
        &self,
        package_version: &PackageVersion,
    ) -> RegistryResult<RubygemsVersionMetadata> {
        blocking_metadata_client(Duration::from_secs(15))?
            .get(self.version_metadata_url(package_version))
            .send()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to fetch rubygems version metadata for `{}` version `{}`: {source}",
                    package_version.package, package_version.version
                ))
            })?
            .error_for_status()
            .map_err(|source| {
                RegistryError::new(format!(
                    "rubygems version metadata request for `{}` version `{}` failed: {source}",
                    package_version.package, package_version.version
                ))
            })?
            .json::<RubygemsVersionMetadata>()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to parse rubygems version metadata for `{}` version `{}`: {source}",
                    package_version.package, package_version.version
                ))
            })
    }

    fn resolve_artifact(
        &self,
        package_version: &PackageVersion,
    ) -> RegistryResult<RubygemsArtifact> {
        let metadata = self.fetch_version_metadata(package_version)?;
        self.resolve_artifact_from_metadata(package_version, &metadata)
    }

    fn resolve_artifact_from_metadata(
        &self,
        package_version: &PackageVersion,
        metadata: &RubygemsVersionMetadata,
    ) -> RegistryResult<RubygemsArtifact> {
        let gem_url = metadata
            .gem_uri
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "rubygems version metadata for `{}` version `{}` is missing gem_uri",
                    package_version.package, package_version.version
                ))
            })?;
        let filename = artifact_filename_from_url(gem_url)?;
        let size_bytes = match metadata.size_bytes {
            Some(size_bytes) => size_bytes,
            None => self.fetch_artifact_size_bytes(gem_url)?,
        };

        Ok(RubygemsArtifact {
            url: gem_url.to_string(),
            metadata: ArtifactMetadata {
                filename,
                size_bytes: Some(size_bytes),
            },
        })
    }

    fn fetch_artifact_size_bytes(&self, gem_url: &str) -> RegistryResult<u64> {
        let response = blocking_metadata_client(Duration::from_secs(15))?
            .head(gem_url)
            .send()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to fetch rubygems artifact headers for `{gem_url}`: {source}"
                ))
            })?
            .error_for_status()
            .map_err(|source| {
                RegistryError::new(format!(
                    "rubygems artifact header request for `{gem_url}` failed: {source}"
                ))
            })?;

        let content_length = response
            .headers()
            .get(CONTENT_LENGTH)
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "rubygems artifact header response for `{gem_url}` is missing content-length"
                ))
            })?
            .to_str()
            .map_err(|source| {
                RegistryError::new(format!(
                    "rubygems artifact header response for `{gem_url}` returned an invalid content-length: {source}"
                ))
            })?
            .parse::<u64>()
            .map_err(|source| {
                RegistryError::new(format!(
                    "rubygems artifact header response for `{gem_url}` returned a non-numeric content-length: {source}"
                ))
            })?;

        Ok(content_length)
    }

    fn download_policy_for(&self, gem_url: &str) -> RegistryResult<DownloadPolicy> {
        let parsed = Url::parse(gem_url).map_err(|source| {
            RegistryError::new(format!(
                "rubygems artifact url `{gem_url}` is invalid: {source}"
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
                "rubygems artifact destination `{}` is not under a version-scoped cache directory",
                destination.display()
            )));
        };

        let expected_destination = version_scoped_state_directory(cache_root, package_version);
        if expected_destination != destination {
            return Err(RegistryError::new(format!(
                "rubygems artifact destination `{}` does not match the version-scoped cache path `{}`",
                destination.display(),
                expected_destination.display()
            )));
        }

        Ok(ArtifactCache::new(cache_root))
    }

    fn fetch_request_for(&self, artifact: &RubygemsArtifact) -> FetchRequest {
        FetchRequest {
            url: artifact.url.clone(),
            artifact_metadata: Some(artifact.metadata.clone()),
        }
    }

    fn parse_latest_version(
        &self,
        package: &str,
        metadata: RubygemsPackageMetadata,
    ) -> RegistryResult<PackageVersion> {
        let latest = metadata
            .version
            .filter(|version| !version.trim().is_empty())
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "rubygems response for `{package}` is missing version"
                ))
            })?;

        Ok(PackageVersion {
            ecosystem: self.ecosystem(),
            package: package.to_string(),
            version: latest,
        })
    }
}

impl Default for RubygemsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry for RubygemsRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Rubygems
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
                    "failed to build rubygems downloader for `{}` version `{}`: {source}",
                    package.package, package.version
                ))
            })?;
        let request = self.fetch_request_for(&artifact);

        cache
            .fetch(&downloader, package, &request)
            .map(|cached| cached.artifact)
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to download rubygems artifact for `{}` version `{}`: {source}",
                    package.package, package.version
                ))
            })
    }

    fn unpack(&self, artifact: &Path, destination: &Path) -> RegistryResult<()> {
        SafeUnpacker::default()
            .unpack_gem(artifact, destination)
            .map(|_| ())
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to unpack rubygems artifact {}: {source}",
                    artifact.display()
                ))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RubygemsArtifact {
    url: String,
    metadata: ArtifactMetadata,
}

#[derive(Debug, Deserialize)]
struct RubygemsPackageMetadata {
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RubygemsVersionMetadata {
    gem_uri: Option<String>,
    #[serde(default, alias = "size")]
    size_bytes: Option<u64>,
}

fn artifact_filename_from_url(url: &str) -> RegistryResult<String> {
    let parsed = Url::parse(url).map_err(|source| {
        RegistryError::new(format!(
            "rubygems artifact url `{url}` is invalid: {source}"
        ))
    })?;
    let filename = parsed
        .path_segments()
        .and_then(|mut segments| segments.rfind(|segment| !segment.is_empty()))
        .ok_or_else(|| {
            RegistryError::new(format!(
                "rubygems artifact url `{url}` does not contain a file name"
            ))
        })?;

    Ok(filename.to_string())
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
    use crate::state::{StateLayout, VersionChange};

    use super::*;

    #[test]
    fn builds_metadata_url_for_gem() {
        let registry = RubygemsRegistry::new();

        assert_eq!(
            registry.metadata_url("rails"),
            "https://rubygems.org/api/v1/gems/rails.json"
        );
    }

    #[test]
    fn parses_latest_version_from_rubygems_metadata() {
        let registry = RubygemsRegistry::new();
        let package = registry
            .parse_latest_version(
                "rails",
                RubygemsPackageMetadata {
                    version: Some("8.0.0".to_string()),
                },
            )
            .expect("latest version should parse");

        assert_eq!(package.package_key(), "rubygems:rails");
        assert_eq!(package.version, "8.0.0");
    }

    #[test]
    fn parses_latest_version_from_fixture_metadata() {
        let registry = RubygemsRegistry::new();
        let metadata: RubygemsPackageMetadata = serde_json::from_str(include_str!(
            "../../tests/fixtures/registry/rubygems/rails.json"
        ))
        .expect("fixture metadata should parse");

        let package = registry
            .parse_latest_version("rails", metadata)
            .expect("fixture latest version should parse");

        assert_eq!(package.package_key(), "rubygems:rails");
        assert_eq!(package.version, "8.0.0");
    }

    #[test]
    fn resolves_artifact_metadata_from_version_metadata() {
        let registry = RubygemsRegistry::new();
        let package = package_version("rails", "8.0.0");
        let artifact = registry
            .resolve_artifact_from_metadata(
                &package,
                &RubygemsVersionMetadata {
                    gem_uri: Some("https://rubygems.org/gems/rails-8.0.0.gem".to_string()),
                    size_bytes: Some(42),
                },
            )
            .expect("artifact metadata should resolve");

        assert_eq!(artifact.url, "https://rubygems.org/gems/rails-8.0.0.gem");
        assert_eq!(artifact.metadata.filename, "rails-8.0.0.gem");
        assert_eq!(artifact.metadata.size_bytes, Some(42));
    }

    #[test]
    fn resolves_artifact_via_version_metadata_and_head_size_lookup() {
        let server = RequestSequenceServer::start_with_builder(|base_url| {
            vec![
                ResponseSpec::json(
                    200,
                    "/api/v2/rubygems/rails/versions/8.0.0.json",
                    format!("{{\"gem_uri\":\"{base_url}/gems/rails-8.0.0.gem\"}}"),
                ),
                ResponseSpec::head(200, "/gems/rails-8.0.0.gem", Some(42)),
            ]
        });
        let registry = RubygemsRegistry::with_base_urls(server.v1_base_url(), server.v2_base_url());

        let artifact = registry
            .resolve_artifact(&package_version("rails", "8.0.0"))
            .expect("artifact metadata should resolve");

        assert_eq!(
            artifact.url,
            format!("{}/gems/rails-8.0.0.gem", server.root_url())
        );
        assert_eq!(artifact.metadata.filename, "rails-8.0.0.gem");
        assert_eq!(artifact.metadata.size_bytes, Some(42));
        assert_eq!(
            server.request_log(),
            vec![
                "GET /api/v2/rubygems/rails/versions/8.0.0.json".to_string(),
                "HEAD /gems/rails-8.0.0.gem".to_string(),
            ]
        );
    }

    #[test]
    fn downloads_artifact_through_safe_downloader_and_cache() {
        let server = RequestSequenceServer::start_with_builder(|base_url| {
            vec![
                ResponseSpec::json(
                    200,
                    "/api/v2/rubygems/rails/versions/8.0.0.json",
                    format!("{{\"gem_uri\":\"{base_url}/gems/rails-8.0.0.gem\",\"size\":13}}"),
                ),
                ResponseSpec::get(200, "/gems/rails-8.0.0.gem", "fake gem body"),
                ResponseSpec::json(
                    200,
                    "/api/v2/rubygems/rails/versions/8.0.0.json",
                    format!("{{\"gem_uri\":\"{base_url}/gems/rails-8.0.0.gem\",\"size\":13}}"),
                ),
            ]
        });
        let registry = RubygemsRegistry::with_base_urls(server.v1_base_url(), server.v2_base_url());
        let package = package_version("rails", "8.0.0");
        let fixture = TestDir::new("rubygems-download-cache");
        let state_layout =
            StateLayout::from_repo_root(fixture.path()).expect("state layout should build");
        let destination = state_layout.artifact_cache_dir_for(&package);

        let first = registry
            .download_artifact(&package, &destination)
            .expect("first artifact download should succeed");
        let second = registry
            .download_artifact(&package, &destination)
            .expect("second artifact download should hit cache");

        assert_eq!(first.path, destination.join("rails-8.0.0.gem"));
        assert_eq!(second.path, first.path);
        assert_eq!(
            fs::read_to_string(&first.path).expect("artifact should be readable"),
            "fake gem body"
        );
        assert_eq!(
            server.request_log(),
            vec![
                "GET /api/v2/rubygems/rails/versions/8.0.0.json".to_string(),
                "GET /gems/rails-8.0.0.gem".to_string(),
                "GET /api/v2/rubygems/rails/versions/8.0.0.json".to_string(),
            ]
        );
    }

    #[test]
    fn processes_changed_rubygems_package_through_fetch_unpack_and_diff_summary() {
        let old_gem = gem_archive_bytes(&[
            ArchiveFile::new("README.md", b"old readme\n"),
            ArchiveFile::new("lib/rails.rb", b"module Rails\nend\n"),
            ArchiveFile::new("lib/rails/version.rb", b"VERSION = \"7.9.0\"\n"),
        ])
        .expect("old gem should be created");
        let new_gem = gem_archive_bytes(&[
            ArchiveFile::new("lib/rails.rb", b"module Rails\n  VERSION = true\nend\n"),
            ArchiveFile::new("lib/rails/version.rb", b"VERSION = \"8.0.0\"\n"),
            ArchiveFile::new("exe/rails", b"#!/usr/bin/env ruby\nputs :rails\n"),
        ])
        .expect("new gem should be created");
        let old_size = old_gem.len() as u64;
        let new_size = new_gem.len() as u64;

        let server = RequestSequenceServer::start_with_builder(move |base_url| {
            let old_metadata = rubygems_version_metadata_body(base_url, "7.9.0", old_size);
            let new_metadata = rubygems_version_metadata_body(base_url, "8.0.0", new_size);
            vec![
                ResponseSpec::json(
                    200,
                    "/api/v2/rubygems/rails/versions/7.9.0.json",
                    old_metadata,
                ),
                ResponseSpec::get(200, "/gems/rails-7.9.0.gem", old_gem),
                ResponseSpec::json(
                    200,
                    "/api/v2/rubygems/rails/versions/8.0.0.json",
                    new_metadata,
                ),
                ResponseSpec::get(200, "/gems/rails-8.0.0.gem", new_gem),
            ]
        });
        let registry = RubygemsRegistry::with_base_urls(server.v1_base_url(), server.v2_base_url());
        let fixture = TestDir::new("rubygems-changed-package");
        let state_layout =
            StateLayout::from_repo_root(fixture.path()).expect("state layout should build");
        let workspace = ArtifactWorkspace::from_state_layout(&state_layout);

        let result = process_version_change(
            &registry,
            &version_change("rails", "7.9.0", "8.0.0"),
            &workspace,
        )
        .expect("rubygems changed package should process successfully");

        assert_eq!(result.previous_package.version, "7.9.0");
        assert_eq!(result.current_package.version, "8.0.0");
        assert_eq!(result.diff.files_added, 2);
        assert_eq!(result.diff.files_removed, 1);
        assert_eq!(result.diff.files_changed, 2);
        assert_eq!(result.diff.added_paths, vec!["exe", "exe/rails"]);
        assert_eq!(result.diff.removed_paths, vec!["README.md"]);
        assert_eq!(
            result.diff.modified_paths,
            vec!["lib/rails/version.rb", "lib/rails.rb"]
        );
        assert!(result.current_root.join("exe/rails").exists());
        assert_eq!(
            fs::read_to_string(result.current_root.join("lib/rails/version.rb"))
                .expect("unpacked file should be readable"),
            "VERSION = \"8.0.0\"\n"
        );
        assert_eq!(
            server.request_log(),
            vec![
                "GET /api/v2/rubygems/rails/versions/7.9.0.json".to_string(),
                "GET /gems/rails-7.9.0.gem".to_string(),
                "GET /api/v2/rubygems/rails/versions/8.0.0.json".to_string(),
                "GET /gems/rails-8.0.0.gem".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_download_destination_outside_version_scoped_cache() {
        let registry = RubygemsRegistry::new();
        let package = package_version("rails", "8.0.0");
        let fixture = TestDir::new("rubygems-download-destination");
        let invalid_destination = fixture.path().join("artifacts").join("rails");

        let error = registry
            .cache_from_destination(&package, &invalid_destination)
            .expect_err("invalid cache destination should fail");

        assert!(error
            .to_string()
            .contains("does not match the version-scoped cache path"));
    }

    #[test]
    fn rejects_artifact_resolution_when_gem_uri_is_missing() {
        let registry = RubygemsRegistry::new();
        let error = registry
            .resolve_artifact_from_metadata(
                &package_version("rails", "8.0.0"),
                &RubygemsVersionMetadata {
                    gem_uri: None,
                    size_bytes: None,
                },
            )
            .expect_err("missing gem_uri should fail");

        assert_eq!(
            error.to_string(),
            "rubygems version metadata for `rails` version `8.0.0` is missing gem_uri"
        );
    }

    #[test]
    fn rejects_artifact_header_responses_without_content_length() {
        let server = RequestSequenceServer::start(vec![ResponseSpec::head(
            200,
            "/gems/rails-8.0.0.gem",
            None,
        )]);
        let registry = RubygemsRegistry::new();

        let error = registry
            .fetch_artifact_size_bytes(&format!("{}/gems/rails-8.0.0.gem", server.root_url()))
            .expect_err("missing content-length should fail");

        assert_eq!(
            error.to_string(),
            format!(
                "rubygems artifact header response for `{}/gems/rails-8.0.0.gem` is missing content-length",
                server.root_url()
            )
        );
        assert_eq!(
            server.request_log(),
            vec!["HEAD /gems/rails-8.0.0.gem".to_string()]
        );
    }

    #[test]
    fn rejects_rubygems_metadata_without_version() {
        let registry = RubygemsRegistry::new();
        let error = registry
            .parse_latest_version("rails", RubygemsPackageMetadata { version: None })
            .expect_err("missing version should fail");

        assert_eq!(
            error.to_string(),
            "rubygems response for `rails` is missing version"
        );
    }

    #[test]
    fn fetches_latest_version_from_http_registry() {
        let server = TestServer::start(200, r#"{"version":"8.0.0"}"#);
        let registry = RubygemsRegistry::with_metadata_base_url(server.base_url());

        let package = registry
            .latest_version("rails")
            .expect("latest version should load");

        assert_eq!(package.package, "rails");
        assert_eq!(package.version, "8.0.0");
        assert_eq!(package.package_key(), "rubygems:rails");
        assert_eq!(server.request_path(), "/rails.json");
    }

    fn package_version(package: &str, version: &str) -> PackageVersion {
        PackageVersion {
            ecosystem: Ecosystem::Rubygems,
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
    }

    impl ResponseSpec {
        fn json(status_code: u16, path: &str, body: impl AsRef<[u8]>) -> Self {
            Self {
                status_code,
                method: "GET".to_string(),
                path: path.to_string(),
                content_type: "application/json",
                body: body.as_ref().to_vec(),
                content_length: None,
            }
        }

        fn get(status_code: u16, path: &str, body: impl AsRef<[u8]>) -> Self {
            Self {
                status_code,
                method: "GET".to_string(),
                path: path.to_string(),
                content_type: "application/octet-stream",
                body: body.as_ref().to_vec(),
                content_length: None,
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

        fn root_url(&self) -> &str {
            &self.root_url
        }

        fn v1_base_url(&self) -> String {
            format!("{}/api/v1/gems", self.root_url)
        }

        fn v2_base_url(&self) -> String {
            format!("{}/api/v2/rubygems", self.root_url)
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

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos();
            let path = env::temp_dir().join(format!("pincushion-rubygems-{label}-{unique}"));
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

    struct ArchiveFile<'a> {
        path: &'a str,
        contents: &'a [u8],
    }

    impl<'a> ArchiveFile<'a> {
        fn new(path: &'a str, contents: &'a [u8]) -> Self {
            Self { path, contents }
        }
    }

    fn gem_archive_bytes(files: &[ArchiveFile<'_>]) -> std::io::Result<Vec<u8>> {
        let metadata_bytes = gzip_bytes(b"--- !ruby/object:Gem::Specification {}\n")?;
        let data_bytes = tar_gz_bytes(files)?;

        let cursor = Cursor::new(Vec::new());
        let mut builder = Builder::new(cursor);
        append_tar_file(&mut builder, "metadata.gz", &metadata_bytes)?;
        append_tar_file(&mut builder, "data.tar.gz", &data_bytes)?;
        builder.finish()?;

        Ok(builder.into_inner()?.into_inner())
    }

    fn gzip_bytes(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes)?;
        encoder.finish()
    }

    fn tar_gz_bytes(files: &[ArchiveFile<'_>]) -> std::io::Result<Vec<u8>> {
        let cursor = Cursor::new(Vec::new());
        let encoder = GzEncoder::new(cursor, Compression::default());
        let mut builder = Builder::new(encoder);

        for file in files {
            let mut header = Header::new_gnu();
            header.set_path(file.path)?;
            header.set_mode(0o644);
            header.set_size(file.contents.len() as u64);
            header.set_cksum();
            builder.append(&header, file.contents)?;
        }

        let encoder = builder.into_inner()?;
        let cursor = encoder.finish()?;
        Ok(cursor.into_inner())
    }

    fn append_tar_file<W: Write>(
        builder: &mut Builder<W>,
        path: &str,
        contents: &[u8],
    ) -> std::io::Result<()> {
        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder.append(&header, Cursor::new(contents))
    }

    fn rubygems_version_metadata_body(base_url: &str, version: &str, size: u64) -> String {
        serde_json::json!({
            "gem_uri": format!("{base_url}/gems/rails-{version}.gem"),
            "size": size,
        })
        .to_string()
    }
}
