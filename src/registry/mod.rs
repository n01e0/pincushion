use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

pub mod crates;
pub mod npm;
pub mod pypi;
pub mod rubygems;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Rubygems,
    Pypi,
    Crates,
}

impl Ecosystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Rubygems => "rubygems",
            Self::Pypi => "pypi",
            Self::Crates => "crates",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVersion {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
}

impl PackageVersion {
    pub fn package_key(&self) -> String {
        format!("{}:{}", self.ecosystem.as_str(), self.package)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedArtifact {
    pub source_url: Option<String>,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError {
    message: String,
}

impl RegistryError {
    pub fn placeholder(ecosystem: Ecosystem, operation: impl Into<String>) -> Self {
        let operation = operation.into();

        Self {
            message: format!(
                "{} registry placeholder: {operation} is not implemented yet",
                ecosystem.as_str()
            ),
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for RegistryError {}

pub type RegistryResult<T> = Result<T, RegistryError>;

pub trait Registry {
    fn ecosystem(&self) -> Ecosystem;
    fn latest_version(&self, package: &str) -> RegistryResult<PackageVersion>;
    fn download_artifact(
        &self,
        package: &PackageVersion,
        destination: &Path,
    ) -> RegistryResult<DownloadedArtifact>;
    fn unpack(&self, artifact: &Path, destination: &Path) -> RegistryResult<()>;
}
