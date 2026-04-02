use std::path::PathBuf;

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
