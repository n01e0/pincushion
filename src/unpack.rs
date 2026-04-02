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
