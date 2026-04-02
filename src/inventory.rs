use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: PathBuf,
    pub file_type: FileType,
    pub size: u64,
    pub mode: u32,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InventorySummary {
    pub entries: Vec<FileEntry>,
}

impl InventorySummary {
    pub fn collect(root: impl AsRef<Path>) -> Result<Self, InventoryError> {
        let root = root.as_ref();
        let root = fs::canonicalize(root).map_err(|source| InventoryError::Io {
            path: root.to_path_buf(),
            source,
        })?;

        let mut entries = Vec::new();
        collect_directory_entries(&root, &root, &mut entries)?;
        entries.sort_by(|left, right| left.path.cmp(&right.path));

        Ok(Self { entries })
    }
}

#[derive(Debug)]
pub enum InventoryError {
    Io { path: PathBuf, source: io::Error },
    StripPrefix { path: PathBuf, root: PathBuf },
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    f,
                    "filesystem error while inventorying {}: {source}",
                    path.display()
                )
            }
            Self::StripPrefix { path, root } => write!(
                f,
                "failed to relativize inventory path {} against {}",
                path.display(),
                root.display()
            ),
        }
    }
}

impl Error for InventoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::StripPrefix { .. } => None,
        }
    }
}

fn collect_directory_entries(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<FileEntry>,
) -> Result<(), InventoryError> {
    let mut child_paths = fs::read_dir(directory)
        .map_err(|source| InventoryError::Io {
            path: directory.to_path_buf(),
            source,
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| InventoryError::Io {
                    path: directory.to_path_buf(),
                    source,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    child_paths.sort();

    for child_path in child_paths {
        let metadata = fs::symlink_metadata(&child_path).map_err(|source| InventoryError::Io {
            path: child_path.clone(),
            source,
        })?;
        let relative_path = child_path
            .strip_prefix(root)
            .map_err(|_| InventoryError::StripPrefix {
                path: child_path.clone(),
                root: root.to_path_buf(),
            })?
            .to_path_buf();
        let file_type = file_type_from_metadata(&metadata);
        let entry = FileEntry {
            path: relative_path,
            file_type: file_type.clone(),
            size: size_from_metadata(&metadata, &file_type),
            mode: mode_from_metadata(&metadata),
            digest: digest_for_path(&child_path, &file_type)?,
        };
        entries.push(entry);

        if file_type == FileType::Directory {
            collect_directory_entries(root, &child_path, entries)?;
        }
    }

    Ok(())
}

fn file_type_from_metadata(metadata: &fs::Metadata) -> FileType {
    let file_type = metadata.file_type();
    if file_type.is_file() {
        FileType::File
    } else if file_type.is_dir() {
        FileType::Directory
    } else if file_type.is_symlink() {
        FileType::Symlink
    } else {
        FileType::Other
    }
}

fn size_from_metadata(metadata: &fs::Metadata, file_type: &FileType) -> u64 {
    match file_type {
        FileType::File => metadata.len(),
        FileType::Directory | FileType::Symlink => 0,
        FileType::Other => metadata.len(),
    }
}

fn digest_for_path(path: &Path, file_type: &FileType) -> Result<Option<String>, InventoryError> {
    if *file_type != FileType::File {
        return Ok(None);
    }

    let mut file = File::open(path).map_err(|source| InventoryError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| InventoryError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(Some(hex_encode(&hasher.finalize())))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

#[cfg(unix)]
fn mode_from_metadata(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn mode_from_metadata(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{FileType, InventorySummary};

    #[test]
    fn collects_inventory_for_nested_tree() {
        let temp = TestDir::new("nested-tree");
        fs::create_dir_all(temp.path().join("pkg/src")).expect("directories should be created");
        fs::write(temp.path().join("pkg/README.md"), b"hello world\n")
            .expect("readme should be written");
        fs::write(temp.path().join("pkg/src/lib.rs"), b"pub fn hi() {}\n")
            .expect("lib should be written");

        let inventory = InventorySummary::collect(temp.path()).expect("inventory should build");

        let paths = inventory
            .entries
            .iter()
            .map(|entry| entry.path.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec!["pkg", "pkg/README.md", "pkg/src", "pkg/src/lib.rs"]
        );

        let readme = inventory
            .entries
            .iter()
            .find(|entry| entry.path == Path::new("pkg/README.md"))
            .expect("readme entry should exist");
        assert_eq!(readme.file_type, FileType::File);
        assert_eq!(readme.size, 12);
        assert_eq!(
            readme.digest.as_deref(),
            Some("a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447")
        );

        let directory = inventory
            .entries
            .iter()
            .find(|entry| entry.path == Path::new("pkg/src"))
            .expect("directory entry should exist");
        assert_eq!(directory.file_type, FileType::Directory);
        assert_eq!(directory.size, 0);
        assert_eq!(directory.digest, None);
    }

    #[cfg(unix)]
    #[test]
    fn records_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("symlink-tree");
        fs::create_dir_all(temp.path().join("pkg")).expect("directory should exist");
        fs::write(temp.path().join("pkg/target.txt"), b"target").expect("target should be written");
        symlink("target.txt", temp.path().join("pkg/link.txt")).expect("symlink should be created");

        let inventory = InventorySummary::collect(temp.path()).expect("inventory should build");
        let link = inventory
            .entries
            .iter()
            .find(|entry| entry.path == Path::new("pkg/link.txt"))
            .expect("symlink entry should exist");

        assert_eq!(link.file_type, FileType::Symlink);
        assert_eq!(link.size, 0);
        assert_eq!(link.digest, None);
    }

    #[test]
    fn fails_for_missing_root() {
        let temp = TestDir::new("missing-root");
        let missing = temp.path().join("does-not-exist");

        let error = InventorySummary::collect(&missing).expect_err("missing root should fail");
        assert!(error
            .to_string()
            .contains("filesystem error while inventorying"));
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
            let path = std::env::temp_dir().join(format!("pincushion-inventory-{label}-{unique}"));
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
