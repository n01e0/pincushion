use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use tar::Archive;
use zip::ZipArchive;

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

        self.unpack_tar_archive(&mut archive, artifact, destination)
    }

    pub fn unpack_crate(
        &self,
        artifact: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<UnpackStats, UnpackError> {
        self.unpack_tar_gz(artifact, destination)
    }

    pub fn unpack_gem(
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
        let mut archive = Archive::new(file);
        let entries = archive
            .entries()
            .map_err(|source| UnpackError::ArchiveRead {
                path: artifact.to_path_buf(),
                source,
            })?;

        for entry in entries {
            let entry = entry.map_err(|source| UnpackError::ArchiveRead {
                path: artifact.to_path_buf(),
                source,
            })?;
            let entry_path = entry.path().map_err(|source| UnpackError::EntryPath {
                artifact: artifact.to_path_buf(),
                source,
            })?;
            let entry_name = entry_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();

            match entry_name {
                "data.tar.gz" => {
                    let mut decoder = GzDecoder::new(entry);
                    let mut inner_archive = Archive::new(&mut decoder);
                    return self.unpack_tar_archive(&mut inner_archive, artifact, destination);
                }
                "data.tar" => {
                    let mut inner_archive = Archive::new(entry);
                    return self.unpack_tar_archive(&mut inner_archive, artifact, destination);
                }
                _ => continue,
            }
        }

        Err(UnpackError::GemDataArchiveMissing {
            path: artifact.to_path_buf(),
        })
    }

    pub fn unpack_zip(
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
        let mut archive = ZipArchive::new(file).map_err(|source| UnpackError::ArchiveRead {
            path: artifact.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, source),
        })?;
        let mut stats = UnpackStats::default();

        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|source| UnpackError::ArchiveRead {
                    path: artifact.to_path_buf(),
                    source: io::Error::new(io::ErrorKind::InvalidData, source),
                })?;
            let relative_path = self.validate_entry_path(Path::new(entry.name()))?;
            let output_path = destination.join(&relative_path);

            if entry.is_dir() {
                fs::create_dir_all(&output_path).map_err(|source| UnpackError::Io {
                    path: output_path.clone(),
                    source,
                })?;
                stats.directories_created += 1;
                continue;
            }

            if entry
                .unix_mode()
                .is_some_and(|mode| matches!(mode & 0o170000, 0o120000 | 0o060000))
            {
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

    pub fn unpack_wheel(
        &self,
        artifact: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<UnpackStats, UnpackError> {
        self.unpack_zip(artifact, destination)
    }

    fn unpack_tar_archive<R: Read>(
        &self,
        archive: &mut Archive<R>,
        artifact: &Path,
        destination: &Path,
    ) -> Result<UnpackStats, UnpackError> {
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
    GemDataArchiveMissing {
        path: PathBuf,
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
            Self::GemDataArchiveMissing { path } => {
                write!(f, "gem archive {} is missing data.tar.gz", path.display())
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
            Self::GemDataArchiveMissing { .. }
            | Self::AbsolutePathRejected { .. }
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
    use zip::write::FileOptions;
    use zip::ZipWriter;

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
    fn unpacks_gem_archives_via_inner_data_tarball() {
        let temp = TestDir::new("gem");
        let artifact = temp.path().join("package.gem");
        let destination = temp.path().join("out");
        write_gem_archive(
            &artifact,
            vec![
                ArchiveEntry::file("lib/demo.rb", b"puts 'hi'\n"),
                ArchiveEntry::file("README.md", b"demo gem\n"),
            ],
        );

        let stats = SafeUnpacker::default()
            .unpack_gem(&artifact, &destination)
            .expect("gem should unpack");

        assert_eq!(stats.files_written, 2);
        assert_eq!(stats.total_bytes_written, 19);
        assert_eq!(
            fs::read_to_string(destination.join("lib/demo.rb")).expect("ruby file should exist"),
            "puts 'hi'\n"
        );
        assert_eq!(
            fs::read_to_string(destination.join("README.md")).expect("readme should exist"),
            "demo gem\n"
        );
    }

    #[test]
    fn rejects_gem_archives_without_data_tarball() {
        let temp = TestDir::new("gem-missing-data");
        let artifact = temp.path().join("broken.gem");
        write_gem_archive_without_data(&artifact);

        let error = SafeUnpacker::default()
            .unpack_gem(&artifact, temp.path().join("out"))
            .expect_err("gem without data tarball should fail");

        assert_eq!(
            error.to_string(),
            format!("gem archive {} is missing data.tar.gz", artifact.display())
        );
    }

    #[test]
    fn rejects_parent_path_traversal_in_gem_archives() {
        let temp = TestDir::new("gem-parent");
        let artifact = temp.path().join("bad.gem");
        write_gem_archive(
            &artifact,
            vec![ArchiveEntry::file("pkg/../escape.rb", b"oops")],
        );

        let error = SafeUnpacker::default()
            .unpack_gem(&artifact, temp.path().join("out"))
            .expect_err("gem parent traversal should be rejected");

        assert_eq!(
            error.to_string(),
            "archive entry `pkg/../escape.rb` contains parent path traversal"
        );
    }

    #[test]
    fn unpacks_zip_files_and_directories() {
        let temp = TestDir::new("zip");
        let artifact = temp.path().join("package.zip");
        let destination = temp.path().join("out");
        write_zip_archive(
            &artifact,
            vec![
                ArchiveEntry::directory("package/"),
                ArchiveEntry::file("package/README.md", b"hello"),
                ArchiveEntry::file("package/src/lib.rs", b"pub fn hi() {}\n"),
            ],
        );

        let stats = SafeUnpacker::default()
            .unpack_zip(&artifact, &destination)
            .expect("zip should unpack");

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
    fn unpacks_wheel_archives_with_same_logic() {
        let temp = TestDir::new("wheel");
        let artifact = temp.path().join("package.whl");
        let destination = temp.path().join("out");
        write_zip_archive(
            &artifact,
            vec![ArchiveEntry::file(
                "demo/__init__.py",
                b"__version__ = '0.1.0'\n",
            )],
        );

        let stats = SafeUnpacker::default()
            .unpack_wheel(&artifact, &destination)
            .expect("wheel should unpack");

        assert_eq!(stats.files_written, 1);
        assert_eq!(stats.total_bytes_written, 22);
        assert!(destination.join("demo/__init__.py").exists());
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

    #[test]
    fn rejects_absolute_paths_in_zip_archives() {
        let temp = TestDir::new("zip-absolute");
        let artifact = temp.path().join("bad.zip");
        write_zip_archive(&artifact, vec![ArchiveEntry::file("/etc/passwd", b"root")]);

        let error = SafeUnpacker::default()
            .unpack_zip(&artifact, temp.path().join("out"))
            .expect_err("absolute zip path should be rejected");

        assert_eq!(
            error.to_string(),
            "archive entry `/etc/passwd` uses an absolute path"
        );
    }

    #[test]
    fn rejects_parent_path_traversal_in_zip_archives() {
        let temp = TestDir::new("zip-parent");
        let artifact = temp.path().join("bad.zip");
        write_zip_archive(
            &artifact,
            vec![ArchiveEntry::file("pkg/../escape.txt", b"oops")],
        );

        let error = SafeUnpacker::default()
            .unpack_zip(&artifact, temp.path().join("out"))
            .expect_err("zip parent traversal should be rejected");

        assert_eq!(
            error.to_string(),
            "archive entry `pkg/../escape.txt` contains parent path traversal"
        );
    }

    #[test]
    fn rejects_link_entries_in_zip_archives() {
        let temp = TestDir::new("zip-symlink");
        let artifact = temp.path().join("bad.zip");
        write_zip_archive(&artifact, vec![ArchiveEntry::symlink("pkg/link", "target")]);

        let error = SafeUnpacker::default()
            .unpack_zip(&artifact, temp.path().join("out"))
            .expect_err("zip symlink should be rejected");

        assert_eq!(
            error.to_string(),
            "archive entry `pkg/link` is a symlink or hard link"
        );
    }

    #[test]
    fn enforces_single_file_size_limit_in_zip_archives() {
        let temp = TestDir::new("zip-single-limit");
        let artifact = temp.path().join("bad.zip");
        write_zip_archive(
            &artifact,
            vec![ArchiveEntry::file("pkg/huge.bin", &[0_u8; 8])],
        );
        let mut plan = UnpackPlan::default();
        plan.limits.max_single_file_bytes = 4;

        let error = SafeUnpacker::new(plan)
            .unpack_zip(&artifact, temp.path().join("out"))
            .expect_err("zip single-file limit should be enforced");

        assert_eq!(
            error.to_string(),
            "archive entry `pkg/huge.bin` exceeds single-file limit (8 > 4 bytes)"
        );
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

    fn write_gem_archive(path: &Path, data_entries: Vec<ArchiveEntry<'_>>) {
        let file = File::create(path).expect("gem file should be created");
        let mut builder = Builder::new(file);
        let metadata_bytes = gzip_bytes(b"--- !ruby/object:Gem::Specification {}\n");
        let data_bytes = tar_gz_bytes(data_entries);

        append_tar_file(&mut builder, "metadata.gz", &metadata_bytes);
        append_tar_file(&mut builder, "data.tar.gz", &data_bytes);

        builder.finish().expect("gem builder should finish");
    }

    fn write_gem_archive_without_data(path: &Path) {
        let file = File::create(path).expect("gem file should be created");
        let mut builder = Builder::new(file);
        let metadata_bytes = gzip_bytes(b"--- !ruby/object:Gem::Specification {}\n");
        append_tar_file(&mut builder, "metadata.gz", &metadata_bytes);
        builder.finish().expect("gem builder should finish");
    }

    fn write_zip_archive(path: &Path, entries: Vec<ArchiveEntry<'_>>) {
        let file = File::create(path).expect("zip file should be created");
        let mut writer = ZipWriter::new(file);
        let mut symlink_entries = Vec::new();

        for entry in entries {
            match entry {
                ArchiveEntry::Directory(path) => {
                    writer
                        .add_directory(path, FileOptions::default().unix_permissions(0o755))
                        .expect("directory entry should be appended");
                }
                ArchiveEntry::File(path, contents) => {
                    writer
                        .start_file(path, FileOptions::default().unix_permissions(0o644))
                        .expect("file entry should be appended");
                    std::io::Write::write_all(&mut writer, contents)
                        .expect("zip file contents should be written");
                }
                ArchiveEntry::Symlink(path, target) => {
                    symlink_entries.push(path.to_string());
                    writer
                        .start_file(path, FileOptions::default().unix_permissions(0o777))
                        .expect("symlink entry should be appended");
                    std::io::Write::write_all(&mut writer, target.as_bytes())
                        .expect("zip link contents should be written");
                }
            }
        }

        writer.finish().expect("zip writer should finish");

        if !symlink_entries.is_empty() {
            patch_zip_symlink_attributes(path, &symlink_entries);
        }
    }

    fn patch_zip_symlink_attributes(path: &Path, symlink_entries: &[String]) {
        let mut bytes = fs::read(path).expect("zip bytes should be readable");
        let mut offset = 0usize;

        while offset + 46 <= bytes.len() {
            if bytes[offset..].starts_with(&[0x50, 0x4B, 0x01, 0x02]) {
                let name_len =
                    u16::from_le_bytes([bytes[offset + 28], bytes[offset + 29]]) as usize;
                let extra_len =
                    u16::from_le_bytes([bytes[offset + 30], bytes[offset + 31]]) as usize;
                let comment_len =
                    u16::from_le_bytes([bytes[offset + 32], bytes[offset + 33]]) as usize;
                let name_start = offset + 46;
                let name_end = name_start + name_len;
                let name = String::from_utf8_lossy(&bytes[name_start..name_end]);

                if symlink_entries.iter().any(|entry| entry == &name) {
                    let version_made_by = (3_u16 << 8) | 20;
                    bytes[offset + 4..offset + 6].copy_from_slice(&version_made_by.to_le_bytes());
                    let external_attributes = (0o120777_u32) << 16;
                    bytes[offset + 38..offset + 42]
                        .copy_from_slice(&external_attributes.to_le_bytes());
                }

                offset = name_end + extra_len + comment_len;
            } else {
                offset += 1;
            }
        }

        fs::write(path, bytes).expect("patched zip bytes should be written");
    }

    fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut encoder, bytes).expect("gzip bytes should be written");
        encoder.finish().expect("gzip encoder should finish")
    }

    fn tar_gz_bytes(entries: Vec<ArchiveEntry<'_>>) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
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
        encoder.finish().expect("encoder should finish")
    }

    fn append_tar_file<W: std::io::Write>(builder: &mut Builder<W>, path: &str, contents: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(contents))
            .expect("tar entry should be appended");
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
