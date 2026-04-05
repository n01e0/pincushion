use std::collections::HashMap;
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

    fn fetch_package_metadata(&self, package: &str) -> RegistryResult<NpmPackageMetadata> {
        blocking_metadata_client(Duration::from_secs(15))?
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
            })?
            .json::<NpmPackageMetadata>()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to parse npm metadata for `{package}`: {source}"
                ))
            })
    }

    fn resolve_artifact(&self, package_version: &PackageVersion) -> RegistryResult<NpmArtifact> {
        let metadata = self.fetch_package_metadata(&package_version.package)?;
        self.resolve_artifact_from_metadata(package_version, &metadata)
    }

    fn resolve_artifact_from_metadata(
        &self,
        package_version: &PackageVersion,
        metadata: &NpmPackageMetadata,
    ) -> RegistryResult<NpmArtifact> {
        let release = metadata
            .versions
            .get(&package_version.version)
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "npm metadata for `{}` is missing version `{}`",
                    package_version.package, package_version.version
                ))
            })?;
        let dist = release.dist.as_ref().ok_or_else(|| {
            RegistryError::new(format!(
                "npm metadata for `{}` version `{}` is missing dist metadata",
                package_version.package, package_version.version
            ))
        })?;
        let tarball_url = dist
            .tarball
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "npm metadata for `{}` version `{}` is missing dist.tarball",
                    package_version.package, package_version.version
                ))
            })?;
        let filename = artifact_filename_from_url(tarball_url)?;
        let size_bytes = match dist.size_bytes {
            Some(size_bytes) => size_bytes,
            None => self.fetch_artifact_size_bytes(tarball_url)?,
        };

        Ok(NpmArtifact {
            url: tarball_url.to_string(),
            metadata: ArtifactMetadata {
                filename,
                size_bytes: Some(size_bytes),
            },
        })
    }

    fn fetch_artifact_size_bytes(&self, tarball_url: &str) -> RegistryResult<u64> {
        let response = blocking_metadata_client(Duration::from_secs(15))?
            .head(tarball_url)
            .send()
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to fetch npm artifact headers for `{tarball_url}`: {source}"
                ))
            })?
            .error_for_status()
            .map_err(|source| {
                RegistryError::new(format!(
                    "npm artifact header request for `{tarball_url}` failed: {source}"
                ))
            })?;

        let content_length = response
            .headers()
            .get(CONTENT_LENGTH)
            .ok_or_else(|| {
                RegistryError::new(format!(
                    "npm artifact header response for `{tarball_url}` is missing content-length"
                ))
            })?
            .to_str()
            .map_err(|source| {
                RegistryError::new(format!(
                    "npm artifact header response for `{tarball_url}` returned an invalid content-length: {source}"
                ))
            })?
            .parse::<u64>()
            .map_err(|source| {
                RegistryError::new(format!(
                    "npm artifact header response for `{tarball_url}` returned a non-numeric content-length: {source}"
                ))
            })?;

        Ok(content_length)
    }

    fn download_policy_for(&self, tarball_url: &str) -> RegistryResult<DownloadPolicy> {
        let parsed = Url::parse(tarball_url).map_err(|source| {
            RegistryError::new(format!(
                "npm artifact tarball url `{tarball_url}` is invalid: {source}"
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
                "npm artifact destination `{}` is not under a version-scoped cache directory",
                destination.display()
            )));
        };

        let expected_destination = version_scoped_state_directory(cache_root, package_version);
        if expected_destination != destination {
            return Err(RegistryError::new(format!(
                "npm artifact destination `{}` does not match the version-scoped cache path `{}`",
                destination.display(),
                expected_destination.display()
            )));
        }

        Ok(ArtifactCache::new(cache_root))
    }

    fn fetch_request_for(&self, artifact: &NpmArtifact) -> FetchRequest {
        FetchRequest {
            url: artifact.url.clone(),
            artifact_metadata: Some(artifact.metadata.clone()),
        }
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
                    "failed to build npm downloader for `{}` version `{}`: {source}",
                    package.package, package.version
                ))
            })?;
        let request = self.fetch_request_for(&artifact);

        cache
            .fetch(&downloader, package, &request)
            .map(|cached| cached.artifact)
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to download npm artifact for `{}` version `{}`: {source}",
                    package.package, package.version
                ))
            })
    }

    fn unpack(&self, artifact: &Path, destination: &Path) -> RegistryResult<()> {
        SafeUnpacker::new(Default::default())
            .unpack_tar_gz(artifact, destination)
            .map(|_| ())
            .map_err(|source| {
                RegistryError::new(format!(
                    "failed to unpack npm artifact {} into {}: {source}",
                    artifact.display(),
                    destination.display()
                ))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NpmArtifact {
    url: String,
    metadata: ArtifactMetadata,
}

#[derive(Debug, Deserialize)]
struct NpmPackageMetadata {
    #[serde(rename = "dist-tags")]
    dist_tags: NpmDistTags,
    #[serde(default)]
    versions: HashMap<String, NpmVersionMetadata>,
}

#[derive(Debug, Deserialize)]
struct NpmDistTags {
    latest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NpmVersionMetadata {
    dist: Option<NpmDistMetadata>,
}

#[derive(Debug, Deserialize)]
struct NpmDistMetadata {
    tarball: Option<String>,
    #[serde(default, alias = "size")]
    size_bytes: Option<u64>,
}

fn encode_package_for_registry_path(package: &str) -> String {
    package.replace('/', "%2f")
}

fn artifact_filename_from_url(url: &str) -> RegistryResult<String> {
    let parsed = Url::parse(url).map_err(|source| {
        RegistryError::new(format!(
            "npm artifact tarball url `{url}` is invalid: {source}"
        ))
    })?;
    let filename = parsed
        .path_segments()
        .and_then(|mut segments| segments.rfind(|segment| !segment.is_empty()))
        .ok_or_else(|| {
            RegistryError::new(format!(
                "npm artifact tarball url `{url}` does not contain a file name"
            ))
        })?;

    Ok(filename.to_string())
}

#[cfg(test)]
mod tests {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tar::Builder;

    use crate::artifact_pipeline::{process_version_change, ArtifactWorkspace};
    use crate::state::{StateLayout, VersionChange};

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
                    versions: HashMap::new(),
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
    fn resolves_artifact_metadata_from_package_metadata() {
        let registry = NpmRegistry::new();
        let package = package_version("chalk", "5.4.0");
        let artifact = registry
            .resolve_artifact_from_metadata(
                &package,
                &NpmPackageMetadata {
                    dist_tags: NpmDistTags {
                        latest: Some("5.4.0".to_string()),
                    },
                    versions: HashMap::from([(
                        "5.4.0".to_string(),
                        NpmVersionMetadata {
                            dist: Some(NpmDistMetadata {
                                tarball: Some(
                                    "https://registry.npmjs.org/chalk/-/chalk-5.4.0.tgz"
                                        .to_string(),
                                ),
                                size_bytes: Some(27_391),
                            }),
                        },
                    )]),
                },
            )
            .expect("artifact metadata should resolve");

        assert_eq!(
            artifact.url,
            "https://registry.npmjs.org/chalk/-/chalk-5.4.0.tgz"
        );
        assert_eq!(artifact.metadata.filename, "chalk-5.4.0.tgz");
        assert_eq!(artifact.metadata.size_bytes, Some(27_391));
    }

    #[test]
    fn resolves_artifact_size_via_head_when_metadata_omits_size() {
        let server = RequestSequenceServer::start_with_builder(|base_url| {
            vec![
                ResponseSpec::json(
                    200,
                    "/chalk",
                    format!(
                        "{{\"dist-tags\":{{\"latest\":\"5.4.0\"}},\"versions\":{{\"5.4.0\":{{\"dist\":{{\"tarball\":\"{base_url}/chalk/-/chalk-5.4.0.tgz\"}}}}}}}}"
                    ),
                ),
                ResponseSpec::head(200, "/chalk/-/chalk-5.4.0.tgz", Some(27_391)),
            ]
        });
        let registry = NpmRegistry::with_metadata_base_url(server.base_url());

        let artifact = registry
            .resolve_artifact(&package_version("chalk", "5.4.0"))
            .expect("artifact metadata should resolve");

        assert_eq!(artifact.metadata.filename, "chalk-5.4.0.tgz");
        assert_eq!(artifact.metadata.size_bytes, Some(27_391));
        assert_eq!(
            server.request_log(),
            vec![
                "GET /chalk".to_string(),
                "HEAD /chalk/-/chalk-5.4.0.tgz".to_string(),
            ]
        );
    }

    #[test]
    fn downloads_artifact_through_safe_downloader_and_cache() {
        let server = RequestSequenceServer::start_with_builder(|base_url| {
            vec![
                ResponseSpec::json(
                    200,
                    "/chalk",
                    format!(
                        "{{\"dist-tags\":{{\"latest\":\"5.4.0\"}},\"versions\":{{\"5.4.0\":{{\"dist\":{{\"tarball\":\"{base_url}/chalk/-/chalk-5.4.0.tgz\",\"size\":13}}}}}}}}"
                    ),
                ),
                ResponseSpec::get(200, "/chalk/-/chalk-5.4.0.tgz", "fake tgz body"),
                ResponseSpec::json(
                    200,
                    "/chalk",
                    format!(
                        "{{\"dist-tags\":{{\"latest\":\"5.4.0\"}},\"versions\":{{\"5.4.0\":{{\"dist\":{{\"tarball\":\"{base_url}/chalk/-/chalk-5.4.0.tgz\",\"size\":13}}}}}}}}"
                    ),
                ),
            ]
        });
        let registry = NpmRegistry::with_metadata_base_url(server.base_url());
        let package = package_version("chalk", "5.4.0");
        let fixture = TestDir::new("npm-download-cache");
        let state_layout =
            StateLayout::from_repo_root(fixture.path()).expect("state layout should build");
        let destination = state_layout.artifact_cache_dir_for(&package);

        let first = registry
            .download_artifact(&package, &destination)
            .expect("first artifact download should succeed");
        let second = registry
            .download_artifact(&package, &destination)
            .expect("second artifact download should hit cache");

        assert_eq!(first.path, destination.join("chalk-5.4.0.tgz"));
        assert_eq!(second.path, first.path);
        assert_eq!(
            fs::read_to_string(&first.path).expect("artifact should be readable"),
            "fake tgz body"
        );
        assert_eq!(
            server.request_log(),
            vec![
                "GET /chalk".to_string(),
                "GET /chalk/-/chalk-5.4.0.tgz".to_string(),
                "GET /chalk".to_string(),
            ]
        );
    }

    #[test]
    fn unpacks_npm_tarball_with_safe_unpacker() {
        let registry = NpmRegistry::new();
        let fixture = TestDir::new("npm-unpack");
        let artifact = fixture.path().join("chalk-5.4.0.tgz");
        let destination = fixture.path().join("out");
        write_tar_gz_archive(
            &artifact,
            &[
                ArchiveFile::new("package/package.json", br#"{"name":"chalk"}"#),
                ArchiveFile::new("package/source/index.js", b"export const chalk = true;\n"),
            ],
        )
        .expect("artifact archive should be created");

        registry
            .unpack(&artifact, &destination)
            .expect("npm tarball should unpack");

        assert_eq!(
            fs::read_to_string(destination.join("package/package.json"))
                .expect("package json should exist"),
            "{\"name\":\"chalk\"}"
        );
        assert_eq!(
            fs::read_to_string(destination.join("package/source/index.js"))
                .expect("index should exist"),
            "export const chalk = true;\n"
        );
    }

    #[test]
    fn processes_changed_npm_package_through_fetch_unpack_and_diff_summary() {
        let old_tarball = tar_gz_archive_bytes(&[
            ArchiveFile::new(
                "package/package.json",
                br#"{"name":"chalk","version":"5.3.0"}"#,
            ),
            ArchiveFile::new(
                "package/source/index.js",
                b"export const version = 'old';\n",
            ),
            ArchiveFile::new("package/README.md", b"old readme\n"),
        ])
        .expect("old tarball should be created");
        let new_tarball = tar_gz_archive_bytes(&[
            ArchiveFile::new(
                "package/package.json",
                br#"{"name":"chalk","version":"5.4.0"}"#,
            ),
            ArchiveFile::new(
                "package/source/index.js",
                b"export const version = 'new';\n",
            ),
            ArchiveFile::new("package/dist/index.js", b"export const bundle = true;\n"),
        ])
        .expect("new tarball should be created");
        let old_size = old_tarball.len();
        let new_size = new_tarball.len();

        let server = RequestSequenceServer::start_with_builder(move |base_url| {
            let metadata_body =
                npm_versions_metadata_body(base_url, old_size as u64, new_size as u64);
            vec![
                ResponseSpec::json(200, "/chalk", metadata_body.clone()),
                ResponseSpec::get(200, "/chalk/-/chalk-5.3.0.tgz", old_tarball),
                ResponseSpec::json(200, "/chalk", metadata_body),
                ResponseSpec::get(200, "/chalk/-/chalk-5.4.0.tgz", new_tarball),
            ]
        });
        let registry = NpmRegistry::with_metadata_base_url(server.base_url());
        let fixture = TestDir::new("npm-changed-package");
        let state_layout =
            StateLayout::from_repo_root(fixture.path()).expect("state layout should build");
        let workspace = ArtifactWorkspace::from_state_layout(&state_layout);

        let result = process_version_change(
            &registry,
            &version_change("chalk", "5.3.0", "5.4.0"),
            &workspace,
        )
        .expect("npm changed package should process successfully");

        assert_eq!(result.previous_package.version, "5.3.0");
        assert_eq!(result.current_package.version, "5.4.0");
        assert_eq!(result.analysis.diff.files_added, 2);
        assert_eq!(result.analysis.diff.files_removed, 1);
        assert_eq!(result.analysis.diff.files_changed, 2);
        assert_eq!(
            result.analysis.diff.added_paths,
            vec!["package/dist", "package/dist/index.js"]
        );
        assert_eq!(
            result.analysis.diff.removed_paths,
            vec!["package/README.md"]
        );
        assert_eq!(
            result.analysis.diff.modified_paths,
            vec!["package/package.json", "package/source/index.js"]
        );
        assert!(result.current_root.join("package/dist/index.js").exists());
        assert_eq!(
            fs::read_to_string(result.current_root.join("package/source/index.js"))
                .expect("unpacked file should be readable"),
            "export const version = 'new';\n"
        );
        assert_eq!(
            server.request_log(),
            vec![
                "GET /chalk".to_string(),
                "GET /chalk/-/chalk-5.3.0.tgz".to_string(),
                "GET /chalk".to_string(),
                "GET /chalk/-/chalk-5.4.0.tgz".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_download_destination_outside_version_scoped_cache() {
        let registry = NpmRegistry::new();
        let package = package_version("chalk", "5.4.0");
        let fixture = TestDir::new("npm-download-destination");
        let invalid_destination = fixture.path().join("artifacts").join("chalk");

        let error = registry
            .cache_from_destination(&package, &invalid_destination)
            .expect_err("invalid cache destination should fail");

        assert!(error
            .to_string()
            .contains("does not match the version-scoped cache path"));
    }

    #[test]
    fn rejects_artifact_resolution_when_version_tarball_is_missing() {
        let registry = NpmRegistry::new();
        let error = registry
            .resolve_artifact_from_metadata(
                &package_version("chalk", "5.4.0"),
                &NpmPackageMetadata {
                    dist_tags: NpmDistTags {
                        latest: Some("5.4.0".to_string()),
                    },
                    versions: HashMap::from([(
                        "5.4.0".to_string(),
                        NpmVersionMetadata {
                            dist: Some(NpmDistMetadata {
                                tarball: None,
                                size_bytes: Some(27_391),
                            }),
                        },
                    )]),
                },
            )
            .expect_err("missing tarball should fail");

        assert_eq!(
            error.to_string(),
            "npm metadata for `chalk` version `5.4.0` is missing dist.tarball"
        );
    }

    #[test]
    fn rejects_artifact_header_responses_without_content_length() {
        let server = RequestSequenceServer::start(vec![ResponseSpec::head(
            200,
            "/chalk/-/chalk-5.4.0.tgz",
            None,
        )]);
        let registry = NpmRegistry::new();

        let error = registry
            .fetch_artifact_size_bytes(&format!("{}/chalk/-/chalk-5.4.0.tgz", server.base_url()))
            .expect_err("missing content-length should fail");

        assert_eq!(
            error.to_string(),
            format!(
                "npm artifact header response for `{}/chalk/-/chalk-5.4.0.tgz` is missing content-length",
                server.base_url()
            )
        );
        assert_eq!(
            server.request_log(),
            vec!["HEAD /chalk/-/chalk-5.4.0.tgz".to_string()]
        );
    }

    #[test]
    fn rejects_registry_metadata_without_latest_dist_tag() {
        let registry = NpmRegistry::new();
        let error = registry
            .parse_latest_version(
                "react",
                NpmPackageMetadata {
                    dist_tags: NpmDistTags { latest: None },
                    versions: HashMap::new(),
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

    fn package_version(package: &str, version: &str) -> PackageVersion {
        PackageVersion {
            ecosystem: Ecosystem::Npm,
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

        fn start(responses: Vec<ResponseSpec>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test server should bind");
            let address = listener.local_addr().expect("local addr should resolve");
            let base_url = format!("http://{}", address);
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
            let path = env::temp_dir().join(format!("pincushion-npm-{label}-{unique}"));
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

    fn write_tar_gz_archive(path: &Path, files: &[ArchiveFile<'_>]) -> std::io::Result<()> {
        fs::write(path, tar_gz_archive_bytes(files)?)
    }

    fn tar_gz_archive_bytes(files: &[ArchiveFile<'_>]) -> std::io::Result<Vec<u8>> {
        let cursor = std::io::Cursor::new(Vec::new());
        let encoder = GzEncoder::new(cursor, Compression::default());
        let mut builder = Builder::new(encoder);

        for file in files {
            let mut header = tar::Header::new_gnu();
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

    fn npm_versions_metadata_body(base_url: &str, old_size: u64, new_size: u64) -> String {
        serde_json::json!({
            "dist-tags": {
                "latest": "5.4.0"
            },
            "versions": {
                "5.3.0": {
                    "dist": {
                        "tarball": format!("{base_url}/chalk/-/chalk-5.3.0.tgz"),
                        "size": old_size,
                    }
                },
                "5.4.0": {
                    "dist": {
                        "tarball": format!("{base_url}/chalk/-/chalk-5.4.0.tgz"),
                        "size": new_size,
                    }
                }
            }
        })
        .to_string()
    }
}
