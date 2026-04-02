use std::collections::BTreeMap;

pub type PackageKey = String;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeenState {
    pub packages: BTreeMap<PackageKey, String>,
}

impl SeenState {
    pub fn record(&mut self, package_key: PackageKey, version: impl Into<String>) {
        self.packages.insert(package_key, version.into());
    }
}
