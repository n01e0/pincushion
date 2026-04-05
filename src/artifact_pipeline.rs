use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::diff::{DiffError, DiffSummary, ManifestDiff};
use crate::inventory::{InventoryError, InventorySummary};
use crate::registry::{
    DownloadedArtifact, PackageVersion, Registry, RegistryError, RegistryPipeline,
};
use crate::state::{
    reset_state_directory, version_scoped_state_directory, StateLayout, VersionChange,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactWorkspace {
    artifacts_root: PathBuf,
    unpacked_root: PathBuf,
}

impl ArtifactWorkspace {
    pub fn new(artifacts_root: impl AsRef<Path>, unpacked_root: impl AsRef<Path>) -> Self {
        Self {
            artifacts_root: artifacts_root.as_ref().to_path_buf(),
            unpacked_root: unpacked_root.as_ref().to_path_buf(),
        }
    }

    pub fn from_state_layout(state_layout: &StateLayout) -> Self {
        Self::new(state_layout.artifacts_dir(), state_layout.unpacked_dir())
    }

    pub fn artifact_destination_for(&self, package_version: &PackageVersion) -> PathBuf {
        version_scoped_state_directory(&self.artifacts_root, package_version)
    }

    pub fn unpack_destination_for(&self, package_version: &PackageVersion) -> PathBuf {
        version_scoped_state_directory(&self.unpacked_root, package_version)
    }

    pub fn reset_unpack_destination_for(
        &self,
        package_version: &PackageVersion,
    ) -> Result<PathBuf, ArtifactPipelineError> {
        let destination = self.unpack_destination_for(package_version);
        reset_state_directory(&destination).map_err(|source| ArtifactPipelineError::Io {
            path: destination.clone(),
            source,
        })?;
        Ok(destination)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessedVersionAnalysis {
    pub diff: DiffSummary,
    pub manifest_diff: Option<ManifestDiff>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessedVersionChange {
    pub previous_package: PackageVersion,
    pub current_package: PackageVersion,
    pub previous_artifact: DownloadedArtifact,
    pub current_artifact: DownloadedArtifact,
    pub previous_root: PathBuf,
    pub current_root: PathBuf,
    pub previous_inventory: InventorySummary,
    pub current_inventory: InventorySummary,
    pub analysis: ProcessedVersionAnalysis,
}

#[derive(Debug)]
pub struct ProcessedChangeResult {
    pub change: VersionChange,
    pub result: Result<ProcessedVersionChange, ArtifactPipelineError>,
}

impl<'a> RegistryPipeline<'a> {
    pub fn process_version_changes(
        &self,
        changes: &[VersionChange],
        workspace: &ArtifactWorkspace,
    ) -> Vec<ProcessedChangeResult> {
        changes
            .iter()
            .cloned()
            .map(|change| {
                let registry = self.registry_for(change.package.ecosystem);
                let result = process_version_change(registry, &change, workspace);
                ProcessedChangeResult { change, result }
            })
            .collect()
    }

    pub fn process_version_changes_in_state_layout(
        &self,
        changes: &[VersionChange],
        state_layout: &StateLayout,
    ) -> Vec<ProcessedChangeResult> {
        let workspace = ArtifactWorkspace::from_state_layout(state_layout);
        self.process_version_changes(changes, &workspace)
    }
}

pub fn process_version_change(
    registry: &dyn Registry,
    change: &VersionChange,
    workspace: &ArtifactWorkspace,
) -> Result<ProcessedVersionChange, ArtifactPipelineError> {
    let previous_package = previous_package_version(change);
    let current_package = change.package.clone();

    let previous_artifact = download_package_artifact(registry, &previous_package, workspace)?;
    let current_artifact = download_package_artifact(registry, &current_package, workspace)?;

    let previous_root = workspace.reset_unpack_destination_for(&previous_package)?;
    registry
        .unpack(&previous_artifact.path, &previous_root)
        .map_err(|source| ArtifactPipelineError::Unpack {
            package: previous_package.clone(),
            artifact: previous_artifact.path.clone(),
            source: Box::new(source),
        })?;

    let current_root = workspace.reset_unpack_destination_for(&current_package)?;
    registry
        .unpack(&current_artifact.path, &current_root)
        .map_err(|source| ArtifactPipelineError::Unpack {
            package: current_package.clone(),
            artifact: current_artifact.path.clone(),
            source: Box::new(source),
        })?;

    let previous_inventory = InventorySummary::collect(&previous_root).map_err(|source| {
        ArtifactPipelineError::Inventory {
            package: previous_package.clone(),
            root: previous_root.clone(),
            source: Box::new(source),
        }
    })?;
    let current_inventory = InventorySummary::collect(&current_root).map_err(|source| {
        ArtifactPipelineError::Inventory {
            package: current_package.clone(),
            root: current_root.clone(),
            source: Box::new(source),
        }
    })?;
    let analysis = analyze_processed_version_change(
        current_package.ecosystem,
        &previous_root,
        &current_root,
        &previous_inventory,
        &current_inventory,
    )
    .map_err(|source| ArtifactPipelineError::Analysis {
        package: current_package.clone(),
        source: Box::new(source),
    })?;

    Ok(ProcessedVersionChange {
        previous_package,
        current_package,
        previous_artifact,
        current_artifact,
        previous_root,
        current_root,
        previous_inventory,
        current_inventory,
        analysis,
    })
}

#[derive(Debug)]
pub enum ArtifactPipelineError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Download {
        package: PackageVersion,
        source: Box<RegistryError>,
    },
    Unpack {
        package: PackageVersion,
        artifact: PathBuf,
        source: Box<RegistryError>,
    },
    Inventory {
        package: PackageVersion,
        root: PathBuf,
        source: Box<InventoryError>,
    },
    Analysis {
        package: PackageVersion,
        source: Box<DiffError>,
    },
}

impl fmt::Display for ArtifactPipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    f,
                    "artifact pipeline filesystem error for {}: {source}",
                    path.display()
                )
            }
            Self::Download { package, source } => write!(
                f,
                "failed to download artifact for {} @ {}: {source}",
                package.package_key(),
                package.version
            ),
            Self::Unpack {
                package,
                artifact,
                source,
            } => write!(
                f,
                "failed to unpack artifact {} for {} @ {}: {source}",
                artifact.display(),
                package.package_key(),
                package.version
            ),
            Self::Inventory {
                package,
                root,
                source,
            } => write!(
                f,
                "failed to inventory unpacked files in {} for {} @ {}: {source}",
                root.display(),
                package.package_key(),
                package.version
            ),
            Self::Analysis { package, source } => write!(
                f,
                "failed to analyze unpacked diff for {} @ {}: {source}",
                package.package_key(),
                package.version
            ),
        }
    }
}

impl Error for ArtifactPipelineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Download { source, .. } | Self::Unpack { source, .. } => Some(source),
            Self::Inventory { source, .. } => Some(source),
            Self::Analysis { source, .. } => Some(source),
        }
    }
}

fn analyze_processed_version_change(
    ecosystem: crate::registry::Ecosystem,
    previous_root: &Path,
    current_root: &Path,
    previous_inventory: &InventorySummary,
    current_inventory: &InventorySummary,
) -> Result<ProcessedVersionAnalysis, DiffError> {
    let diff = DiffSummary::between(previous_inventory, current_inventory);
    let manifest_diff = ManifestDiff::extract(ecosystem, previous_root, current_root, &diff)?;

    Ok(ProcessedVersionAnalysis {
        diff,
        manifest_diff,
    })
}

fn download_package_artifact(
    registry: &dyn Registry,
    package: &PackageVersion,
    workspace: &ArtifactWorkspace,
) -> Result<DownloadedArtifact, ArtifactPipelineError> {
    let destination = workspace.artifact_destination_for(package);
    fs::create_dir_all(&destination).map_err(|source| ArtifactPipelineError::Io {
        path: destination.clone(),
        source,
    })?;

    registry
        .download_artifact(package, &destination)
        .map_err(|source| ArtifactPipelineError::Download {
            package: package.clone(),
            source: Box::new(source),
        })
}

fn previous_package_version(change: &VersionChange) -> PackageVersion {
    PackageVersion {
        ecosystem: change.package.ecosystem,
        package: change.package.package.clone(),
        version: change.previous_version.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::{self, Cursor};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::{Builder, EntryType, Header};

    use crate::registry::{Ecosystem, PackageVersion, Registry, RegistryError, RegistryPipeline};
    use crate::state::{StateLayout, VersionChange};
    use crate::unpack::SafeUnpacker;

    use super::ArtifactWorkspace;

    #[test]
    fn processes_changed_packages_through_shared_download_unpack_inventory_diff_pipeline() {
        let temp = TestDir::new("shared-pipeline");
        let state_layout =
            StateLayout::from_repo_root(temp.path()).expect("state layout should build");
        let workspace = ArtifactWorkspace::from_state_layout(&state_layout);

        let npm = FakeArchiveRegistry::new(Ecosystem::Npm)
            .with_package(
                "demo-npm",
                "1.0.0",
                vec![
                    file(
                        "package/package.json",
                        b"{\n  \"name\": \"demo-npm\",\n  \"version\": \"1.0.0\"\n}\n",
                    ),
                    file("package/index.js", b"module.exports = 'old';\n"),
                    file("package/README.md", b"hello\n"),
                ],
            )
            .with_package(
                "demo-npm",
                "1.1.0",
                vec![
                    file(
                        "package/package.json",
                        b"{\n  \"name\": \"demo-npm\",\n  \"version\": \"1.1.0\"\n}\n",
                    ),
                    file("package/index.js", b"module.exports = 'new';\n"),
                    file("package/dist/index.js", b"module.exports = 'bundle';\n"),
                ],
            );
        let crates = FakeArchiveRegistry::new(Ecosystem::Crates)
            .with_package(
                "demo-crate",
                "0.1.0",
                vec![
                    file(
                        "demo-crate/Cargo.toml",
                        b"[package]\nname = \"demo-crate\"\nversion = \"0.1.0\"\n",
                    ),
                    file(
                        "demo-crate/src/lib.rs",
                        b"pub fn version() -> &'static str { \"old\" }\n",
                    ),
                ],
            )
            .with_package(
                "demo-crate",
                "0.2.0",
                vec![
                    file(
                        "demo-crate/Cargo.toml",
                        b"[package]\nname = \"demo-crate\"\nversion = \"0.2.0\"\n",
                    ),
                    file(
                        "demo-crate/src/lib.rs",
                        b"pub fn version() -> &'static str { \"new\" }\n",
                    ),
                ],
            );
        let rubygems = FakeArchiveRegistry::new(Ecosystem::Rubygems);
        let pypi = FakeArchiveRegistry::new(Ecosystem::Pypi);
        let pipeline = RegistryPipeline::new(&npm, &rubygems, &pypi, &crates);

        let stale_path = state_layout
            .unpacked_version_dir_for(&package_version(Ecosystem::Npm, "demo-npm", "1.1.0"))
            .join("stale.txt");
        fs::create_dir_all(
            stale_path
                .parent()
                .expect("stale path should have a parent directory"),
        )
        .expect("stale unpack parent should be created");
        fs::write(&stale_path, b"stale").expect("stale unpack file should be written");

        let results = pipeline.process_version_changes_in_state_layout(
            &[
                version_change(Ecosystem::Npm, "demo-npm", "1.0.0", "1.1.0"),
                version_change(Ecosystem::Crates, "demo-crate", "0.1.0", "0.2.0"),
            ],
            &state_layout,
        );

        assert_eq!(results.len(), 2);

        let npm_result = results[0]
            .result
            .as_ref()
            .expect("npm change should process successfully");
        assert_eq!(npm_result.previous_package.version, "1.0.0");
        assert_eq!(npm_result.current_package.version, "1.1.0");
        assert_eq!(npm_result.analysis.diff.files_added, 2);
        assert_eq!(npm_result.analysis.diff.files_removed, 1);
        assert_eq!(npm_result.analysis.diff.files_changed, 2);
        assert_eq!(
            npm_result
                .analysis
                .manifest_diff
                .as_ref()
                .expect("npm manifest diff should be present")
                .paths,
            vec!["package/package.json"]
        );
        assert_eq!(
            npm_result.analysis.diff.added_paths,
            vec!["package/dist", "package/dist/index.js"]
        );
        assert_eq!(
            npm_result.analysis.diff.removed_paths,
            vec!["package/README.md"]
        );
        assert_eq!(
            npm_result.analysis.diff.modified_paths,
            vec!["package/index.js", "package/package.json"]
        );
        assert!(npm_result.previous_root.exists());
        assert!(npm_result.current_root.exists());
        assert_eq!(
            npm_result.previous_artifact.path.parent(),
            Some(
                workspace
                    .artifact_destination_for(&npm_result.previous_package)
                    .as_path()
            )
        );
        assert_eq!(
            npm_result.current_root,
            state_layout.unpacked_version_dir_for(&npm_result.current_package)
        );
        assert!(!stale_path.exists());
        assert!(npm_result
            .current_inventory
            .entries
            .iter()
            .any(|entry| { entry.path == Path::new("package/dist/index.js") }));

        let crates_result = results[1]
            .result
            .as_ref()
            .expect("crates change should process successfully");
        assert_eq!(crates_result.analysis.diff.files_added, 0);
        assert_eq!(crates_result.analysis.diff.files_removed, 0);
        assert_eq!(crates_result.analysis.diff.files_changed, 2);
        assert_eq!(
            crates_result
                .analysis
                .manifest_diff
                .as_ref()
                .expect("crate manifest diff should be present")
                .paths,
            vec!["demo-crate/Cargo.toml"]
        );
        assert_eq!(
            crates_result.analysis.diff.modified_paths,
            vec!["demo-crate/Cargo.toml", "demo-crate/src/lib.rs"]
        );

        assert_eq!(
            npm.operations(),
            vec![
                "download npm:demo-npm@1.0.0".to_string(),
                "download npm:demo-npm@1.1.0".to_string(),
                "unpack npm:demo-npm@1.0.0".to_string(),
                "unpack npm:demo-npm@1.1.0".to_string(),
            ]
        );
        assert_eq!(
            crates.operations(),
            vec![
                "download crates:demo-crate@0.1.0".to_string(),
                "download crates:demo-crate@0.2.0".to_string(),
                "unpack crates:demo-crate@0.1.0".to_string(),
                "unpack crates:demo-crate@0.2.0".to_string(),
            ]
        );
    }

    #[derive(Debug, Clone)]
    struct FakeArchiveRegistry {
        ecosystem: Ecosystem,
        packages: BTreeMap<(String, String), Vec<ArchiveFile>>,
        operations: Arc<Mutex<Vec<String>>>,
    }

    impl FakeArchiveRegistry {
        fn new(ecosystem: Ecosystem) -> Self {
            Self {
                ecosystem,
                packages: BTreeMap::new(),
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn with_package(mut self, package: &str, version: &str, files: Vec<ArchiveFile>) -> Self {
            self.packages
                .insert((package.to_string(), version.to_string()), files);
            self
        }

        fn operations(&self) -> Vec<String> {
            self.operations
                .lock()
                .expect("operations lock should succeed")
                .clone()
        }

        fn record_operation(&self, operation: String) {
            self.operations
                .lock()
                .expect("operations lock should succeed")
                .push(operation);
        }
    }

    impl Registry for FakeArchiveRegistry {
        fn ecosystem(&self) -> Ecosystem {
            self.ecosystem
        }

        fn latest_version(&self, package: &str) -> Result<PackageVersion, RegistryError> {
            Err(RegistryError::new(format!(
                "unexpected latest_version lookup for {package}"
            )))
        }

        fn download_artifact(
            &self,
            package: &PackageVersion,
            destination: &Path,
        ) -> Result<crate::registry::DownloadedArtifact, RegistryError> {
            self.record_operation(format!(
                "download {}@{}",
                package.package_key(),
                package.version
            ));

            let files = self
                .packages
                .get(&(package.package.clone(), package.version.clone()))
                .ok_or_else(|| {
                    RegistryError::new(format!(
                        "missing fixture for {} @ {}",
                        package.package_key(),
                        package.version
                    ))
                })?;
            fs::create_dir_all(destination).map_err(|source| {
                RegistryError::new(format!(
                    "failed to create fake artifact dir {}: {source}",
                    destination.display()
                ))
            })?;
            let artifact_path = destination.join(format!(
                "{}-{}.tar.gz",
                sanitize_test_component(&package.package),
                package.version
            ));
            write_tar_gz_archive(&artifact_path, files).map_err(|source| {
                RegistryError::new(format!(
                    "failed to write fake artifact {}: {source}",
                    artifact_path.display()
                ))
            })?;

            Ok(crate::registry::DownloadedArtifact {
                source_url: Some(format!(
                    "fixture://{}/{}/{}",
                    package.ecosystem.as_str(),
                    package.package,
                    package.version
                )),
                path: artifact_path,
            })
        }

        fn unpack(&self, artifact: &Path, destination: &Path) -> Result<(), RegistryError> {
            let file_stem = artifact
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .trim_end_matches(".tar.gz");
            let package = self
                .packages
                .keys()
                .find_map(|(package, version)| {
                    let expected = format!("{}-{version}", sanitize_test_component(package));
                    if expected == file_stem {
                        Some((package.clone(), version.clone()))
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    RegistryError::new(format!(
                        "could not infer package version from {}",
                        artifact.display()
                    ))
                })?;
            self.record_operation(format!(
                "unpack {}:{}@{}",
                self.ecosystem.as_str(),
                package.0,
                package.1
            ));

            SafeUnpacker::default()
                .unpack_tar_gz(artifact, destination)
                .map(|_| ())
                .map_err(|source| {
                    RegistryError::new(format!(
                        "failed to unpack fake artifact {}: {source}",
                        artifact.display()
                    ))
                })
        }
    }

    #[derive(Debug, Clone)]
    struct ArchiveFile {
        path: String,
        contents: Vec<u8>,
    }

    fn file(path: &str, contents: &[u8]) -> ArchiveFile {
        ArchiveFile {
            path: path.to_string(),
            contents: contents.to_vec(),
        }
    }

    fn package_version(ecosystem: Ecosystem, package: &str, version: &str) -> PackageVersion {
        PackageVersion {
            ecosystem,
            package: package.to_string(),
            version: version.to_string(),
        }
    }

    fn version_change(
        ecosystem: Ecosystem,
        package: &str,
        previous_version: &str,
        current_version: &str,
    ) -> VersionChange {
        VersionChange {
            package: package_version(ecosystem, package, current_version),
            previous_version: previous_version.to_string(),
        }
    }

    fn write_tar_gz_archive(path: &Path, files: &[ArchiveFile]) -> io::Result<()> {
        let file = File::create(path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);

        for archive_file in files {
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(archive_file.contents.len() as u64);
            header.set_cksum();
            builder.append_data(
                &mut header,
                archive_file.path.as_str(),
                Cursor::new(&archive_file.contents),
            )?;
        }

        let encoder = builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

    fn sanitize_test_component(component: &str) -> String {
        component
            .chars()
            .map(|ch| if ch == '/' { '_' } else { ch })
            .collect()
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
            let path =
                std::env::temp_dir().join(format!("pincushion-artifact-pipeline-{label}-{unique}"));
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
