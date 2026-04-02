use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::inventory::{FileEntry, InventorySummary};

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

fn path_to_string(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::inventory::{FileEntry, FileType, InventorySummary};

    use super::DiffSummary;

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
}
