use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::registry::PackageVersion;

pub type PackageKey = String;

pub const STATE_DIR_NAME: &str = ".pincushion";
pub const SEEN_FILE_NAME: &str = "seen.json";
pub const ARTIFACTS_DIR_NAME: &str = "artifacts";
pub const UNPACKED_DIR_NAME: &str = "unpacked";
pub const REPORTS_DIR_NAME: &str = "reports";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLayout {
    repo_root: PathBuf,
    state_dir: PathBuf,
    seen_file: PathBuf,
    artifacts_dir: PathBuf,
    unpacked_dir: PathBuf,
    reports_dir: PathBuf,
}

impl StateLayout {
    pub fn from_repo_root(repo_root: impl AsRef<Path>) -> io::Result<Self> {
        let repo_root = fs::canonicalize(repo_root.as_ref())?;
        Ok(Self::from_canonical_repo_root(repo_root))
    }

    pub fn from_config_path(config_path: impl AsRef<Path>) -> io::Result<Self> {
        let config_path = fs::canonicalize(config_path.as_ref())?;
        let repo_root = config_path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "config path {} does not have a parent directory",
                    config_path.display()
                ),
            )
        })?;

        Ok(Self::from_canonical_repo_root(repo_root.to_path_buf()))
    }

    fn from_canonical_repo_root(repo_root: PathBuf) -> Self {
        let state_dir = repo_root.join(STATE_DIR_NAME);
        let seen_file = state_dir.join(SEEN_FILE_NAME);
        let artifacts_dir = state_dir.join(ARTIFACTS_DIR_NAME);
        let unpacked_dir = state_dir.join(UNPACKED_DIR_NAME);
        let reports_dir = state_dir.join(REPORTS_DIR_NAME);

        Self {
            repo_root,
            state_dir,
            seen_file,
            artifacts_dir,
            unpacked_dir,
            reports_dir,
        }
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn seen_file(&self) -> &Path {
        &self.seen_file
    }

    pub fn artifacts_dir(&self) -> &Path {
        &self.artifacts_dir
    }

    pub fn unpacked_dir(&self) -> &Path {
        &self.unpacked_dir
    }

    pub fn reports_dir(&self) -> &Path {
        &self.reports_dir
    }

    pub fn ensure_dirs(&self) -> io::Result<()> {
        fs::create_dir_all(&self.artifacts_dir)?;
        fs::create_dir_all(&self.unpacked_dir)?;
        fs::create_dir_all(&self.reports_dir)?;
        Ok(())
    }

    pub fn load_seen_state(&self) -> Result<SeenState, StateError> {
        match fs::read_to_string(&self.seen_file) {
            Ok(contents) => {
                serde_json::from_str(&contents).map_err(|source| StateError::ParseSeen {
                    path: self.seen_file.clone(),
                    source,
                })
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(SeenState::default()),
            Err(source) => Err(StateError::Io {
                path: self.seen_file.clone(),
                source,
            }),
        }
    }

    pub fn save_seen_state(&self, seen_state: &SeenState) -> Result<(), StateError> {
        self.ensure_dirs().map_err(|source| StateError::Io {
            path: self.state_dir.clone(),
            source,
        })?;

        let contents =
            serde_json::to_string_pretty(seen_state).map_err(StateError::SerializeSeen)?;
        fs::write(&self.seen_file, format!("{contents}\n")).map_err(|source| StateError::Io {
            path: self.seen_file.clone(),
            source,
        })?;

        Ok(())
    }

    pub fn initialize_baseline_if_empty(
        &self,
        current_versions: &[PackageVersion],
    ) -> Result<BaselineState, StateError> {
        let seen_state = self.load_seen_state()?;
        if seen_state.is_empty() {
            let baseline = SeenState::from_package_versions(current_versions);
            self.save_seen_state(&baseline)?;
            Ok(BaselineState::Initialized(baseline))
        } else {
            Ok(BaselineState::Existing(seen_state))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineState {
    Initialized(SeenState),
    Existing(SeenState),
}

impl BaselineState {
    pub fn is_baseline_only(&self) -> bool {
        matches!(self, Self::Initialized(_))
    }

    pub fn seen_state(&self) -> &SeenState {
        match self {
            Self::Initialized(seen_state) | Self::Existing(seen_state) => seen_state,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionChange {
    pub package: PackageVersion,
    pub previous_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnchangedPackage {
    pub package: PackageVersion,
    pub previous_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewlyTrackedPackage {
    pub package: PackageVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangeDetection {
    pub changed: Vec<VersionChange>,
    pub unchanged: Vec<UnchangedPackage>,
    pub newly_tracked: Vec<NewlyTrackedPackage>,
}

impl ChangeDetection {
    pub fn has_version_changes(&self) -> bool {
        !self.changed.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeenState {
    pub packages: BTreeMap<PackageKey, String>,
}

impl SeenState {
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    pub fn version_for(&self, package_key: &str) -> Option<&str> {
        self.packages.get(package_key).map(String::as_str)
    }

    pub fn previous_version_for(&self, package_version: &PackageVersion) -> Option<&str> {
        self.version_for(&package_version.package_key())
    }

    pub fn detect_changes(&self, current_versions: &[PackageVersion]) -> ChangeDetection {
        let mut detection = ChangeDetection::default();

        for package_version in current_versions {
            match self.previous_version_for(package_version) {
                Some(previous_version) if previous_version == package_version.version => {
                    detection.unchanged.push(UnchangedPackage {
                        package: package_version.clone(),
                        previous_version: previous_version.to_string(),
                    });
                }
                Some(previous_version) => {
                    detection.changed.push(VersionChange {
                        package: package_version.clone(),
                        previous_version: previous_version.to_string(),
                    });
                }
                None => {
                    detection.newly_tracked.push(NewlyTrackedPackage {
                        package: package_version.clone(),
                    });
                }
            }
        }

        detection
    }

    pub fn from_package_versions(package_versions: &[PackageVersion]) -> Self {
        let mut seen_state = Self::default();

        for package_version in package_versions {
            seen_state.record(
                package_version.package_key(),
                package_version.version.clone(),
            );
        }

        seen_state
    }

    pub fn record(&mut self, package_key: PackageKey, version: impl Into<String>) {
        self.packages.insert(package_key, version.into());
    }
}

#[derive(Debug)]
pub enum StateError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    ParseSeen {
        path: PathBuf,
        source: serde_json::Error,
    },
    SerializeSeen(serde_json::Error),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "state I/O failed for {}: {source}", path.display())
            }
            Self::ParseSeen { path, source } => {
                write!(f, "failed to parse seen state {}: {source}", path.display())
            }
            Self::SerializeSeen(source) => write!(f, "failed to serialize seen state: {source}"),
        }
    }
}

impl Error for StateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::ParseSeen { source, .. } => Some(source),
            Self::SerializeSeen(source) => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::registry::{Ecosystem, PackageVersion};

    use super::{BaselineState, ChangeDetection, SeenState, StateLayout};

    #[test]
    fn creates_state_layout_from_repo_root() {
        let repo_root = TestDir::new("layout");
        let layout = StateLayout::from_repo_root(repo_root.path()).expect("layout should build");

        let canonical_repo_root =
            fs::canonicalize(repo_root.path()).expect("repo root should canonicalize");
        assert_eq!(layout.repo_root(), canonical_repo_root);
        assert_eq!(layout.state_dir(), canonical_repo_root.join(".pincushion"));
        assert_eq!(
            layout.seen_file(),
            canonical_repo_root.join(".pincushion/seen.json")
        );
        assert_eq!(
            layout.artifacts_dir(),
            canonical_repo_root.join(".pincushion/artifacts")
        );
        assert_eq!(
            layout.unpacked_dir(),
            canonical_repo_root.join(".pincushion/unpacked")
        );
        assert_eq!(
            layout.reports_dir(),
            canonical_repo_root.join(".pincushion/reports")
        );

        layout
            .ensure_dirs()
            .expect("state directories should be created");

        assert!(layout.state_dir().is_dir());
        assert!(layout.artifacts_dir().is_dir());
        assert!(layout.unpacked_dir().is_dir());
        assert!(layout.reports_dir().is_dir());
        assert!(!layout.seen_file().exists());
    }

    #[test]
    fn loads_and_saves_seen_state_from_config_path() {
        let repo_root = TestDir::new("seen-roundtrip");
        let config_path = repo_root.path().join("watchlist.yaml");
        fs::write(&config_path, "npm:\n  - serde\n").expect("config file should be written");

        let layout =
            StateLayout::from_config_path(&config_path).expect("layout should build from config");
        assert_eq!(
            layout.repo_root(),
            fs::canonicalize(repo_root.path()).expect("repo root should canonicalize")
        );

        let empty = layout
            .load_seen_state()
            .expect("missing seen state should default");
        assert_eq!(empty, SeenState::default());

        let mut seen = SeenState::default();
        seen.record(String::from("npm:serde"), "1.0.217");
        seen.record(String::from("crates:anyhow"), "1.0.95");

        layout
            .save_seen_state(&seen)
            .expect("seen state should be saved");

        let persisted =
            fs::read_to_string(layout.seen_file()).expect("seen file should be readable");
        assert!(persisted.contains("\n  \"packages\": {\n"));
        assert!(persisted.ends_with("\n"));

        let reloaded = layout
            .load_seen_state()
            .expect("saved seen state should reload");
        assert_eq!(reloaded, seen);
    }

    #[test]
    fn first_run_is_baseline_only_and_persists_current_versions() {
        let repo_root = TestDir::new("baseline-first-run");
        let layout = StateLayout::from_repo_root(repo_root.path()).expect("layout should build");
        let current_versions = vec![
            package_version(Ecosystem::Npm, "react", "19.0.0"),
            package_version(Ecosystem::Crates, "clap", "4.5.31"),
        ];

        let baseline = layout
            .initialize_baseline_if_empty(&current_versions)
            .expect("baseline initialization should succeed");

        assert!(baseline.is_baseline_only());
        assert_eq!(
            baseline.seen_state().version_for("npm:react"),
            Some("19.0.0")
        );
        assert_eq!(
            baseline.seen_state().version_for("crates:clap"),
            Some("4.5.31")
        );

        let persisted = layout
            .load_seen_state()
            .expect("persisted baseline should reload");
        assert_eq!(persisted, baseline.seen_state().clone());
    }

    #[test]
    fn existing_seen_state_skips_baseline_only_mode() {
        let repo_root = TestDir::new("baseline-existing");
        let layout = StateLayout::from_repo_root(repo_root.path()).expect("layout should build");

        let mut existing = SeenState::default();
        existing.record(String::from("npm:react"), "19.0.0");
        layout
            .save_seen_state(&existing)
            .expect("existing seen state should be saved");

        let result = layout
            .initialize_baseline_if_empty(&[package_version(Ecosystem::Npm, "react", "19.1.0")])
            .expect("existing seen state should be reused");

        assert_eq!(result, BaselineState::Existing(existing.clone()));
        assert!(!result.is_baseline_only());

        let persisted = layout
            .load_seen_state()
            .expect("seen state should still be readable");
        assert_eq!(persisted, existing);
    }

    #[test]
    fn previous_version_lookup_is_ecosystem_aware() {
        let mut seen = SeenState::default();
        seen.record(String::from("npm:requests"), "1.0.0");
        seen.record(String::from("pypi:requests"), "2.32.3");

        assert_eq!(
            seen.previous_version_for(&package_version(Ecosystem::Npm, "requests", "1.1.0")),
            Some("1.0.0")
        );
        assert_eq!(
            seen.previous_version_for(&package_version(Ecosystem::Pypi, "requests", "2.32.4")),
            Some("2.32.3")
        );
        assert_eq!(
            seen.previous_version_for(&package_version(Ecosystem::Crates, "requests", "0.1.0")),
            None
        );
    }

    #[test]
    fn detects_changed_unchanged_and_new_packages() {
        let seen = SeenState::from_package_versions(&[
            package_version(Ecosystem::Npm, "react", "19.0.0"),
            package_version(Ecosystem::Crates, "clap", "4.5.31"),
        ]);

        let detection: ChangeDetection = seen.detect_changes(&[
            package_version(Ecosystem::Npm, "react", "19.1.0"),
            package_version(Ecosystem::Crates, "clap", "4.5.31"),
            package_version(Ecosystem::Pypi, "requests", "2.32.3"),
        ]);

        assert!(detection.has_version_changes());
        assert_eq!(detection.changed.len(), 1);
        assert_eq!(detection.changed[0].package.package_key(), "npm:react");
        assert_eq!(detection.changed[0].previous_version, "19.0.0");
        assert_eq!(detection.changed[0].package.version, "19.1.0");

        assert_eq!(detection.unchanged.len(), 1);
        assert_eq!(detection.unchanged[0].package.package_key(), "crates:clap");
        assert_eq!(detection.unchanged[0].previous_version, "4.5.31");

        assert_eq!(detection.newly_tracked.len(), 1);
        assert_eq!(
            detection.newly_tracked[0].package.package_key(),
            "pypi:requests"
        );
    }

    fn package_version(ecosystem: Ecosystem, package: &str, version: &str) -> PackageVersion {
        PackageVersion {
            ecosystem,
            package: package.to_string(),
            version: version.to_string(),
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
            let path = env::temp_dir().join(format!("pincushion-state-{label}-{unique}"));
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
