use std::path::Path;

use super::{
    DownloadedArtifact, Ecosystem, PackageVersion, Registry, RegistryError, RegistryResult,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct CratesRegistry;

impl Registry for CratesRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Crates
    }

    fn latest_version(&self, _package: &str) -> RegistryResult<PackageVersion> {
        Err(RegistryError::placeholder(
            self.ecosystem(),
            "latest_version",
        ))
    }

    fn download_artifact(
        &self,
        _package: &PackageVersion,
        _destination: &Path,
    ) -> RegistryResult<DownloadedArtifact> {
        Err(RegistryError::placeholder(
            self.ecosystem(),
            "download_artifact",
        ))
    }

    fn unpack(&self, _artifact: &Path, _destination: &Path) -> RegistryResult<()> {
        Err(RegistryError::placeholder(self.ecosystem(), "unpack"))
    }
}
