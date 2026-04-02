use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use tar::Archive;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackLimits {
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_single_file_bytes: u64,
}

impl Default for UnpackLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_total_bytes: 512 * 1024 * 1024,
            max_single_file_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackPlan {
    pub reject_absolute_paths: bool,
    pub reject_parent_segments: bool,
    pub materialize_links: bool,
    pub limits: UnpackLimits,
}

impl Default for UnpackPlan {
    fn default() -> Self {
        Self {
            reject_absolute_paths: true,
            reject_parent_segments: true,
            materialize_links: false,
            limits: UnpackLimits::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnpackStats {
    pub files_written: usize,
    pub directories_created: usize,
    pub total_bytes_written: u64,
}

#[derive(Debug, Clone)]
pub struct SafeUnpacker {
    plan: UnpackPlan,
}

impl SafeUnpacker {
    pub fn new(plan: UnpackPlan) -> Self {
        Self { plan }
    }

    pub fn plan(&self) -> &UnpackPlan {
        &self.plan
    }

    pub fn unpack_tar_gz(
        &self,
        artifact: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<UnpackStats, UnpackError> {
        let artifact = artifact.as_ref();
        let destination = destination.as_ref();
        fs::create_dir_all(destination).map_err(|source| UnpackError::Io {
            path: destination.to_path_buf(),
            source,
        })?;

        let file = File::open(artifact).map_err(|source| UnpackError::Io {
            path: artifact.to_path_buf(),
            source,
        })?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        let mut stats = UnpackStats::default();

        let entries = archive
            .entries()
            .map_err(|source| UnpackError::ArchiveRead {
                path: artifact.to_path_buf(),
                source,
            })?;

        for entry in entries {
            let mut entry = entry.map_err(|source| UnpackError::ArchiveRead {
                path: artifact.to_path_buf(),
                source,
            })?;
            let relative_path = entry.path().map_err(|source| UnpackError::EntryPath {
                artifact: artifact.to_path_buf(),
                source,
            })?;
            let relative_path = self.validate_entry_path(&relative_path)?;
            let output_path = destination.join(&relative_path);
            let entry_type = entry.header().entry_type();

            if entry_type.is_dir() {
                fs::create_dir_all(&output_path).map_err(|source| UnpackError::Io {
                    path: output_path.clone(),
                    source,
                })?;
                stats.directories_created += 1;
                continue;
            }

            if entry_type.is_symlink() || entry_type.is_hard_link() {
                if self.plan.materialize_links {
                    return Err(UnpackError::UnsupportedEntryType {
                        path: relative_path,
                        entry_type: "link".to_string(),
                    });
                }

                return Err(UnpackError::LinkEntryRejected {
                    path: relative_path,
                });
            }

            if !entry_type.is_file() {
                return Err(UnpackError::UnsupportedEntryType {
                    path: relative_path,
                    entry_type: format!("{entry_type:?}"),
                });
            }

            if stats.files_written >= self.plan.limits.max_files {
                return Err(UnpackError::FileCountLimitExceeded {
                    limit: self.plan.limits.max_files,
                });
            }

            let entry_size = entry.size();
            if entry_size > self.plan.limits.max_single_file_bytes {
                return Err(UnpackError::SingleFileLimitExceeded {
                    path: relative_path,
                    limit: self.plan.limits.max_single_file_bytes,
                    attempted: entry_size,
                });
            }

            let total_after_write = stats.total_bytes_written.saturating_add(entry_size);
            if total_after_write > self.plan.limits.max_total_bytes {
                return Err(UnpackError::TotalSizeLimitExceeded {
                    limit: self.plan.limits.max_total_bytes,
                    attempted: total_after_write,
                });
            }

            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent).map_err(|source| UnpackError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }

            let mut output = File::create(&output_path).map_err(|source| UnpackError::Io {
                path: output_path.clone(),
                source,
            })?;
            io::copy(&mut entry, &mut output).map_err(|source| UnpackError::Io {
                path: output_path.clone(),
                source,
            })?;

            stats.files_written += 1;
            stats.total_bytes_written = total_after_write;
        }

        Ok(stats)
    }

    pub fn unpack_crate(
        &self,
        artifact: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<UnpackStats, UnpackError> {
        self.unpack_tar_gz(artifact, destination)
    }

    fn validate_entry_path(&self, path: &Path) -> Result<PathBuf, UnpackError> {
        let mut validated = PathBuf::new();

        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir if self.plan.reject_absolute_paths => {
                    return Err(UnpackError::AbsolutePathRejected {
                        path: path.to_path_buf(),
                    })
                }
                Component::CurDir => {}
                Component::ParentDir if self.plan.reject_parent_segments => {
                    return Err(UnpackError::ParentPathRejected {
                        path: path.to_path_buf(),
                    })
                }
                Component::Normal(segment) => validated.push(segment),
                Component::Prefix(_) | Component::RootDir => validated.push(component.as_os_str()),
                Component::ParentDir => validated.push(component.as_os_str()),
            }
        }

        if validated.as_os_str().is_empty() {
            return Err(UnpackError::EmptyEntryPath {
                path: path.to_path_buf(),
            });
        }

        Ok(validated)
    }
}

impl Default for SafeUnpacker {
    fn default() -> Self {
        Self::new(UnpackPlan::default())
    }
}

#[derive(Debug)]
pub enum UnpackError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    ArchiveRead {
        path: PathBuf,
        source: io::Error,
    },
    EntryPath {
        artifact: PathBuf,
        source: io::Error,
    },
    AbsolutePathRejected {
        path: PathBuf,
    },
    ParentPathRejected {
        path: PathBuf,
    },
    EmptyEntryPath {
        path: PathBuf,
    },
    LinkEntryRejected {
        path: PathBuf,
    },
    UnsupportedEntryType {
        path: PathBuf,
        entry_type: String,
    },
    FileCountLimitExceeded {
        limit: usize,
    },
    SingleFileLimitExceeded {
        path: PathBuf,
        limit: u64,
        attempted: u64,
    },
    TotalSizeLimitExceeded {
        limit: u64,
        attempted: u64,
    },
}

impl fmt::Display for UnpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "filesystem error for {}: {source}", path.display())
            }
            Self::ArchiveRead { path, source } => {
                write!(f, "failed to read archive {}: {source}", path.display())
            }
            Self::EntryPath { artifact, source } => {
                write!(
                    f,
                    "failed to read archive entry path from {}: {source}",
                    artifact.display()
                )
            }
            Self::AbsolutePathRejected { path } => {
                write!(
                    f,
                    "archive entry `{}` uses an absolute path",
                    path.display()
                )
            }
            Self::ParentPathRejected { path } => {
                write!(
                    f,
                    "archive entry `{}` contains parent path traversal",
                    path.display()
                )
            }
            Self::EmptyEntryPath { path } => {
                write!(
                    f,
                    "archive entry `{}` resolves to an empty output path",
                    path.display()
                )
            }
            Self::LinkEntryRejected { path } => {
                write!(
                    f,
                    "archive entry `{}` is a symlink or hard link",
                    path.display()
                )
            }
            Self::UnsupportedEntryType { path, entry_type } => {
                write!(
                    f,
                    "archive entry `{}` uses unsupported type {entry_type}",
                    path.display()
                )
            }
            Self::FileCountLimitExceeded { limit } => {
                write!(f, "archive exceeds file-count limit of {limit}")
            }
            Self::SingleFileLimitExceeded {
                path,
                limit,
                attempted,
            } => write!(
                f,
                "archive entry `{}` exceeds single-file limit ({attempted} > {limit} bytes)",
                path.display()
            ),
            Self::TotalSizeLimitExceeded { limit, attempted } => write!(
                f,
                "archive exceeds total-size limit ({attempted} > {limit} bytes)"
            ),
        }
    }
}

impl Error for UnpackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. }
            | Self::ArchiveRead { source, .. }
            | Self::EntryPath { source, .. } => Some(source),
            Self::AbsolutePathRejected { .. }
            | Self::ParentPathRejected { .. }
            | Self::EmptyEntryPath { .. }
            | Self::LinkEntryRejected { .. }
            | Self::UnsupportedEntryType { .. }
            | Self::FileCountLimitExceeded { .. }
            | Self::SingleFileLimitExceeded { .. }
            | Self::TotalSizeLimitExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::{Builder, EntryType, Header};

    use super::*;

    #[test]
    fn unpacks_tar_gz_files_and_directories() {
        let temp = TestDir::new("tar-gz");
        let artifact = temp.path().join("package.tar.gz");
        let destination = temp.path().join("out");
        write_archive(
            &artifact,
            vec![
                ArchiveEntry::directory("package"),
                ArchiveEntry::file("package/README.md", b"hello"),
                ArchiveEntry::file("package/src/lib.rs", b"pub fn hi() {}\n"),
            ],
        );

        let stats = SafeUnpacker::default()
            .unpack_tar_gz(&artifact, &destination)
            .expect("tar.gz should unpack");

        assert_eq!(stats.files_written, 2);
        assert_eq!(stats.directories_created, 1);
        assert_eq!(stats.total_bytes_written, 20);
        assert_eq!(
            fs::read_to_string(destination.join("package/README.md")).expect("readme should exist"),
            "hello"
        );
        assert_eq!(
            fs::read_to_string(destination.join("package/src/lib.rs")).expect("lib should exist"),
            "pub fn hi() {}\n"
        );
    }

    #[test]
    fn unpacks_crate_archives_with_same_logic() {
        let temp = TestDir::new("crate");
        let artifact = temp.path().join("package.crate");
        let destination = temp.path().join("out");
        write_archive(
            &artifact,
            vec![ArchiveEntry::file(
                "crate/Cargo.toml",
                b"[package]\nname = \"demo\"\n",
            )],
        );

        let stats = SafeUnpacker::default()
            .unpack_crate(&artifact, &destination)
            .expect("crate should unpack");

        assert_eq!(stats.files_written, 1);
        assert_eq!(stats.total_bytes_written, 24);
        assert!(destination.join("crate/Cargo.toml").exists());
    }

    #[test]
    fn rejects_absolute_paths() {
        let temp = TestDir::new("absolute");
        let artifact = temp.path().join("bad.tar.gz");
        write_archive(&artifact, vec![ArchiveEntry::file("/etc/passwd", b"root")]);

        let error = SafeUnpacker::default()
            .unpack_tar_gz(&artifact, temp.path().join("out"))
            .expect_err("absolute path should be rejected");

        assert_eq!(
            error.to_string(),
            "archive entry `/etc/passwd` uses an absolute path"
        );
    }

    #[test]
    fn rejects_parent_path_traversal() {
        let temp = TestDir::new("parent");
        let artifact = temp.path().join("bad.tar.gz");
        write_archive(
            &artifact,
            vec![ArchiveEntry::file("pkg/../escape.txt", b"oops")],
        );

        let error = SafeUnpacker::default()
            .unpack_tar_gz(&artifact, temp.path().join("out"))
            .expect_err("parent traversal should be rejected");

        assert_eq!(
            error.to_string(),
            "archive entry `pkg/../escape.txt` contains parent path traversal"
        );
    }

    #[test]
    fn rejects_link_entries() {
        let temp = TestDir::new("symlink");
        let artifact = temp.path().join("bad.tar.gz");
        write_archive(&artifact, vec![ArchiveEntry::symlink("pkg/link", "target")]);

        let error = SafeUnpacker::default()
            .unpack_tar_gz(&artifact, temp.path().join("out"))
            .expect_err("symlink should be rejected");

        assert_eq!(
            error.to_string(),
            "archive entry `pkg/link` is a symlink or hard link"
        );
    }

    #[test]
    fn enforces_single_file_size_limit() {
        let temp = TestDir::new("single-limit");
        let artifact = temp.path().join("bad.tar.gz");
        write_archive(
            &artifact,
            vec![ArchiveEntry::file("pkg/huge.bin", &[0_u8; 8])],
        );
        let mut plan = UnpackPlan::default();
        plan.limits.max_single_file_bytes = 4;

        let error = SafeUnpacker::new(plan)
            .unpack_tar_gz(&artifact, temp.path().join("out"))
            .expect_err("single-file limit should be enforced");

        assert_eq!(
            error.to_string(),
            "archive entry `pkg/huge.bin` exceeds single-file limit (8 > 4 bytes)"
        );
    }

    #[test]
    fn enforces_total_size_limit() {
        let temp = TestDir::new("total-limit");
        let artifact = temp.path().join("bad.tar.gz");
        write_archive(
            &artifact,
            vec![
                ArchiveEntry::file("pkg/a.bin", &[0_u8; 4]),
                ArchiveEntry::file("pkg/b.bin", &[0_u8; 4]),
            ],
        );
        let mut plan = UnpackPlan::default();
        plan.limits.max_total_bytes = 6;

        let error = SafeUnpacker::new(plan)
            .unpack_tar_gz(&artifact, temp.path().join("out"))
            .expect_err("total-size limit should be enforced");

        assert_eq!(
            error.to_string(),
            "archive exceeds total-size limit (8 > 6 bytes)"
        );
    }

    #[test]
    fn enforces_file_count_limit() {
        let temp = TestDir::new("count-limit");
        let artifact = temp.path().join("bad.tar.gz");
        write_archive(
            &artifact,
            vec![
                ArchiveEntry::file("pkg/a.txt", b"a"),
                ArchiveEntry::file("pkg/b.txt", b"b"),
            ],
        );
        let mut plan = UnpackPlan::default();
        plan.limits.max_files = 1;

        let error = SafeUnpacker::new(plan)
            .unpack_tar_gz(&artifact, temp.path().join("out"))
            .expect_err("file-count limit should be enforced");

        assert_eq!(error.to_string(), "archive exceeds file-count limit of 1");
    }

    fn write_archive(path: &Path, entries: Vec<ArchiveEntry<'_>>) {
        let file = File::create(path).expect("archive file should be created");
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);

        for entry in entries {
            match entry {
                ArchiveEntry::Directory(path) => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Directory);
                    header.set_mode(0o755);
                    header.set_size(0);
                    set_header_path_unchecked(&mut header, path);
                    header.set_cksum();
                    builder
                        .append(&header, std::io::empty())
                        .expect("directory entry should be appended");
                }
                ArchiveEntry::File(path, contents) => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Regular);
                    header.set_mode(0o644);
                    header.set_size(contents.len() as u64);
                    set_header_path_unchecked(&mut header, path);
                    header.set_cksum();
                    builder
                        .append(&header, Cursor::new(contents))
                        .expect("file entry should be appended");
                }
                ArchiveEntry::Symlink(path, target) => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Symlink);
                    header.set_mode(0o777);
                    header.set_size(0);
                    set_header_path_unchecked(&mut header, path);
                    set_header_link_name_unchecked(&mut header, target);
                    header.set_cksum();
                    builder
                        .append(&header, std::io::empty())
                        .expect("symlink entry should be appended");
                }
            }
        }

        let encoder = builder.into_inner().expect("builder should finish");
        encoder.finish().expect("encoder should finish");
    }

    fn set_header_path_unchecked(header: &mut Header, path: &str) {
        let bytes = header.as_mut_bytes();
        bytes[..100].fill(0);
        let path_bytes = path.as_bytes();
        assert!(
            path_bytes.len() < 100,
            "test path should fit in tar header name field"
        );
        bytes[..path_bytes.len()].copy_from_slice(path_bytes);
    }

    fn set_header_link_name_unchecked(header: &mut Header, target: &str) {
        let bytes = header.as_mut_bytes();
        bytes[157..257].fill(0);
        let target_bytes = target.as_bytes();
        assert!(
            target_bytes.len() < 100,
            "test link target should fit in tar header link field"
        );
        bytes[157..157 + target_bytes.len()].copy_from_slice(target_bytes);
    }

    enum ArchiveEntry<'a> {
        Directory(&'a str),
        File(&'a str, &'a [u8]),
        Symlink(&'a str, &'a str),
    }

    impl<'a> ArchiveEntry<'a> {
        fn directory(path: &'a str) -> Self {
            Self::Directory(path)
        }

        fn file(path: &'a str, contents: &'a [u8]) -> Self {
            Self::File(path, contents)
        }

        fn symlink(path: &'a str, target: &'a str) -> Self {
            Self::Symlink(path, target)
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
            let path = std::env::temp_dir().join(format!("pincushion-unpack-{label}-{unique}"));
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
