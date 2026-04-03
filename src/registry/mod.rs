use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::blocking::Client;

use crate::config::WatchlistConfig;
use crate::http;

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
pub struct PackageCoordinate {
    pub ecosystem: Ecosystem,
    pub package: String,
}

impl PackageCoordinate {
    pub fn package_key(&self) -> String {
        format!("{}:{}", self.ecosystem.as_str(), self.package)
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

    pub fn coordinate(&self) -> PackageCoordinate {
        PackageCoordinate {
            ecosystem: self.ecosystem,
            package: self.package.clone(),
        }
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
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn placeholder(ecosystem: Ecosystem, operation: impl Into<String>) -> Self {
        let operation = operation.into();

        Self::new(format!(
            "{} registry placeholder: {operation} is not implemented yet",
            ecosystem.as_str()
        ))
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for RegistryError {}

pub type RegistryResult<T> = Result<T, RegistryError>;

pub(crate) fn blocking_metadata_client(timeout: Duration) -> RegistryResult<Client> {
    http::blocking_client(timeout)
        .map_err(|source| RegistryError::new(format!("failed to build registry client: {source}")))
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryLookupResult {
    pub package: PackageCoordinate,
    pub result: RegistryResult<PackageVersion>,
}

impl RegistryLookupResult {
    pub fn succeeded(&self) -> bool {
        self.result.is_ok()
    }
}

pub struct RegistryPipeline<'a> {
    npm: &'a dyn Registry,
    rubygems: &'a dyn Registry,
    pypi: &'a dyn Registry,
    crates: &'a dyn Registry,
}

impl<'a> RegistryPipeline<'a> {
    pub fn new(
        npm: &'a dyn Registry,
        rubygems: &'a dyn Registry,
        pypi: &'a dyn Registry,
        crates: &'a dyn Registry,
    ) -> Self {
        Self {
            npm,
            rubygems,
            pypi,
            crates,
        }
    }

    pub fn package_coordinates(&self, config: &WatchlistConfig) -> Vec<PackageCoordinate> {
        let mut packages = Vec::new();
        packages.extend(config.npm.iter().cloned().map(|package| PackageCoordinate {
            ecosystem: Ecosystem::Npm,
            package,
        }));
        packages.extend(
            config
                .rubygems
                .iter()
                .cloned()
                .map(|package| PackageCoordinate {
                    ecosystem: Ecosystem::Rubygems,
                    package,
                }),
        );
        packages.extend(
            config
                .pypi
                .iter()
                .cloned()
                .map(|package| PackageCoordinate {
                    ecosystem: Ecosystem::Pypi,
                    package,
                }),
        );
        packages.extend(
            config
                .crates
                .iter()
                .cloned()
                .map(|package| PackageCoordinate {
                    ecosystem: Ecosystem::Crates,
                    package,
                }),
        );
        packages
    }

    pub fn lookup_latest_versions(&self, config: &WatchlistConfig) -> Vec<RegistryLookupResult> {
        self.package_coordinates(config)
            .into_iter()
            .map(|package| RegistryLookupResult {
                result: self
                    .registry_for(package.ecosystem)
                    .latest_version(&package.package),
                package,
            })
            .collect()
    }

    fn registry_for(&self, ecosystem: Ecosystem) -> &'a dyn Registry {
        match ecosystem {
            Ecosystem::Npm => self.npm,
            Ecosystem::Rubygems => self.rubygems,
            Ecosystem::Pypi => self.pypi,
            Ecosystem::Crates => self.crates,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryAdapters {
    pub npm: npm::NpmRegistry,
    pub rubygems: rubygems::RubygemsRegistry,
    pub pypi: pypi::PypiRegistry,
    pub crates: crates::CratesRegistry,
}

impl RegistryAdapters {
    pub fn pipeline(&self) -> RegistryPipeline<'_> {
        RegistryPipeline::new(&self.npm, &self.rubygems, &self.pypi, &self.crates)
    }

    pub fn lookup_latest_versions(&self, config: &WatchlistConfig) -> Vec<RegistryLookupResult> {
        self.pipeline().lookup_latest_versions(config)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Debug, Default)]
    struct FakeRegistry {
        ecosystem: Option<Ecosystem>,
        versions: BTreeMap<String, RegistryResult<PackageVersion>>,
    }

    impl FakeRegistry {
        fn for_ecosystem(ecosystem: Ecosystem) -> Self {
            Self {
                ecosystem: Some(ecosystem),
                versions: BTreeMap::new(),
            }
        }

        fn with_version(mut self, package: &str, version: &str) -> Self {
            let ecosystem = self.ecosystem.expect("ecosystem should be set");
            self.versions.insert(
                package.to_string(),
                Ok(PackageVersion {
                    ecosystem,
                    package: package.to_string(),
                    version: version.to_string(),
                }),
            );
            self
        }

        fn with_error(mut self, package: &str, message: &str) -> Self {
            self.versions.insert(
                package.to_string(),
                Err(RegistryError::new(message.to_string())),
            );
            self
        }
    }

    impl Registry for FakeRegistry {
        fn ecosystem(&self) -> Ecosystem {
            self.ecosystem.expect("ecosystem should be set")
        }

        fn latest_version(&self, package: &str) -> RegistryResult<PackageVersion> {
            self.versions.get(package).cloned().unwrap_or_else(|| {
                Err(RegistryError::new(format!(
                    "unexpected package lookup: {package}"
                )))
            })
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

    #[test]
    fn builds_package_coordinates_for_all_ecosystems() {
        let npm = FakeRegistry::for_ecosystem(Ecosystem::Npm);
        let rubygems = FakeRegistry::for_ecosystem(Ecosystem::Rubygems);
        let pypi = FakeRegistry::for_ecosystem(Ecosystem::Pypi);
        let crates = FakeRegistry::for_ecosystem(Ecosystem::Crates);
        let pipeline = RegistryPipeline::new(&npm, &rubygems, &pypi, &crates);
        let config = WatchlistConfig::from_yaml_str(
            r#"
            npm:
              - react
            rubygems:
              - rails
            pypi:
              - requests
            crates:
              - clap
            "#,
        )
        .expect("config should parse");

        let coordinates = pipeline.package_coordinates(&config);

        assert_eq!(coordinates.len(), 4);
        assert_eq!(coordinates[0].package_key(), "npm:react");
        assert_eq!(coordinates[1].package_key(), "rubygems:rails");
        assert_eq!(coordinates[2].package_key(), "pypi:requests");
        assert_eq!(coordinates[3].package_key(), "crates:clap");
    }

    #[test]
    fn runs_all_ecosystems_through_the_same_lookup_pipeline() {
        let npm = FakeRegistry::for_ecosystem(Ecosystem::Npm).with_version("react", "19.0.0");
        let rubygems =
            FakeRegistry::for_ecosystem(Ecosystem::Rubygems).with_version("rails", "8.0.0");
        let pypi = FakeRegistry::for_ecosystem(Ecosystem::Pypi).with_error("requests", "pypi down");
        let crates = FakeRegistry::for_ecosystem(Ecosystem::Crates).with_version("clap", "4.5.31");
        let pipeline = RegistryPipeline::new(&npm, &rubygems, &pypi, &crates);
        let config = WatchlistConfig::from_yaml_str(
            r#"
            npm:
              - react
            rubygems:
              - rails
            pypi:
              - requests
            crates:
              - clap
            "#,
        )
        .expect("config should parse");

        let results = pipeline.lookup_latest_versions(&config);

        assert_eq!(results.len(), 4);
        assert_eq!(results[0].package.package_key(), "npm:react");
        assert_eq!(
            results[0]
                .result
                .as_ref()
                .expect("npm result should succeed"),
            &PackageVersion {
                ecosystem: Ecosystem::Npm,
                package: "react".to_string(),
                version: "19.0.0".to_string(),
            }
        );

        assert_eq!(results[1].package.package_key(), "rubygems:rails");
        assert_eq!(
            results[1]
                .result
                .as_ref()
                .expect("rubygems result should succeed")
                .version,
            "8.0.0"
        );

        assert_eq!(results[2].package.package_key(), "pypi:requests");
        assert_eq!(
            results[2]
                .result
                .as_ref()
                .expect_err("pypi should fail")
                .to_string(),
            "pypi down"
        );

        assert_eq!(results[3].package.package_key(), "crates:clap");
        assert_eq!(
            results[3]
                .result
                .as_ref()
                .expect("crates result should succeed")
                .version,
            "4.5.31"
        );
    }

    #[test]
    fn adapters_wrapper_uses_default_pipeline() {
        let adapters = RegistryAdapters::default();
        let config = WatchlistConfig::from_yaml_str(
            r#"
            npm:
              - react
            rubygems:
              - rails
            pypi:
              - requests
            crates:
              - clap
            "#,
        )
        .expect("config should parse");

        let coordinates = adapters.pipeline().package_coordinates(&config);

        assert_eq!(coordinates.len(), 4);
        assert_eq!(coordinates[0].ecosystem, Ecosystem::Npm);
        assert_eq!(coordinates[1].ecosystem, Ecosystem::Rubygems);
        assert_eq!(coordinates[2].ecosystem, Ecosystem::Pypi);
        assert_eq!(coordinates[3].ecosystem, Ecosystem::Crates);
    }
}
