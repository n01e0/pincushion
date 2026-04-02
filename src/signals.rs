use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

use crate::diff::{DiffError, DiffSummary, SuspiciousExcerpt, SuspiciousExcerptRequest};
use crate::inventory::{FileEntry, FileType, InventorySummary};
use crate::registry::Ecosystem;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    InstallScriptAdded,
    InstallScriptChanged,
    GemExtensionAdded,
    GemExecutablesChanged,
    DependencyAdded,
    DependencyRemoved,
    DependencySourceChanged,
    EntrypointChanged,
    BinaryAdded,
    ExecutableAdded,
    BuildScriptChanged,
    ObfuscatedJsAdded,
    SuspiciousPythonLoaderAdded,
    LargeEncodedBlobAdded,
    NetworkProcessEnvAccessAdded,
}

impl Signal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstallScriptAdded => "install-script-added",
            Self::InstallScriptChanged => "install-script-changed",
            Self::GemExtensionAdded => "gem-extension-added",
            Self::GemExecutablesChanged => "gem-executables-changed",
            Self::DependencyAdded => "dependency-added",
            Self::DependencyRemoved => "dependency-removed",
            Self::DependencySourceChanged => "dependency-source-changed",
            Self::EntrypointChanged => "entrypoint-changed",
            Self::BinaryAdded => "binary-added",
            Self::ExecutableAdded => "executable-added",
            Self::BuildScriptChanged => "build-script-changed",
            Self::ObfuscatedJsAdded => "obfuscated-js-added",
            Self::SuspiciousPythonLoaderAdded => "suspicious-python-loader-added",
            Self::LargeEncodedBlobAdded => "large-encoded-blob-added",
            Self::NetworkProcessEnvAccessAdded => "network-process-env-access-added",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignalAnalysis {
    pub signals: Vec<Signal>,
    pub interesting_files: Vec<SuspiciousExcerpt>,
}

impl SignalAnalysis {
    pub fn analyze_v0(
        ecosystem: Ecosystem,
        old_root: impl AsRef<Path>,
        new_root: impl AsRef<Path>,
        _old_inventory: &InventorySummary,
        new_inventory: &InventorySummary,
        diff: &DiffSummary,
    ) -> Result<Self, SignalError> {
        let old_root = old_root.as_ref();
        let new_root = new_root.as_ref();
        let mut builder = AnalysisBuilder::default();

        analyze_generic_file_signals(new_root, new_inventory, diff, &mut builder)?;

        match ecosystem {
            Ecosystem::Npm => analyze_npm_signals(old_root, new_root, diff, &mut builder)?,
            Ecosystem::Crates => analyze_cargo_signals(old_root, new_root, diff, &mut builder)?,
            Ecosystem::Rubygems => {
                analyze_rubygems_signals(old_root, new_root, diff, &mut builder)?
            }
            Ecosystem::Pypi => analyze_pypi_signals(old_root, new_root, diff, &mut builder)?,
        }

        let interesting_files = SuspiciousExcerpt::extract_many(new_root, &builder.requests)
            .map_err(SignalError::Diff)?;

        Ok(Self {
            signals: builder.signals,
            interesting_files,
        })
    }
}

#[derive(Debug, Default)]
struct AnalysisBuilder {
    signals: Vec<Signal>,
    requests: Vec<SuspiciousExcerptRequest>,
}

impl AnalysisBuilder {
    fn push_signal(&mut self, signal: Signal) {
        if !self.signals.contains(&signal) {
            self.signals.push(signal);
        }
    }

    fn push_excerpt_request(
        &mut self,
        path: impl Into<String>,
        reason: impl Into<String>,
        needles: Vec<String>,
    ) {
        let request = SuspiciousExcerptRequest {
            path: path.into(),
            reason: reason.into(),
            needles,
        };
        if !self.requests.contains(&request) {
            self.requests.push(request);
        }
    }

    fn push_signal_with_excerpt(
        &mut self,
        signal: Signal,
        path: impl Into<String>,
        reason: impl Into<String>,
        needles: Vec<String>,
    ) {
        self.push_signal(signal);
        self.push_excerpt_request(path, reason, needles);
    }
}

#[derive(Debug)]
pub enum SignalError {
    Io { path: PathBuf, source: io::Error },
    Diff(DiffError),
}

impl fmt::Display for SignalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    f,
                    "failed to analyze signal input {}: {source}",
                    path.display()
                )
            }
            Self::Diff(source) => write!(f, "failed to extract suspicious excerpts: {source}"),
        }
    }
}

impl Error for SignalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Diff(source) => Some(source),
        }
    }
}

fn analyze_generic_file_signals(
    new_root: &Path,
    new_inventory: &InventorySummary,
    diff: &DiffSummary,
    builder: &mut AnalysisBuilder,
) -> Result<(), SignalError> {
    let new_entries = inventory_index(new_inventory);

    for added_path in &diff.added_paths {
        let Some(entry) = new_entries.get(added_path.as_str()) else {
            continue;
        };
        if entry.file_type != FileType::File {
            continue;
        }

        if is_executable_entry(entry) {
            builder.push_signal_with_excerpt(
                Signal::ExecutableAdded,
                added_path.clone(),
                "executable file added",
                Vec::new(),
            );
        }

        if is_binary_added(new_root, entry)? {
            builder.push_signal(Signal::BinaryAdded);
        }
    }

    if diff
        .changed_paths
        .iter()
        .any(|path| is_build_script_path(path))
    {
        let build_path = diff
            .changed_paths
            .iter()
            .find(|path| is_build_script_path(path))
            .cloned()
            .unwrap_or_else(|| "build.rs".to_string());
        builder.push_signal_with_excerpt(
            Signal::BuildScriptChanged,
            build_path,
            "build script changed",
            Vec::new(),
        );
    }

    Ok(())
}

fn analyze_npm_signals(
    old_root: &Path,
    new_root: &Path,
    diff: &DiffSummary,
    builder: &mut AnalysisBuilder,
) -> Result<(), SignalError> {
    let Some(manifest_path) =
        find_changed_path(diff, |path| file_name(path) == Some("package.json"))
    else {
        return Ok(());
    };

    let old_manifest = read_optional_json(old_root.join(&manifest_path))?;
    let new_manifest = read_optional_json(new_root.join(&manifest_path))?;

    let old_dependencies = npm_dependencies(old_manifest.as_ref());
    let new_dependencies = npm_dependencies(new_manifest.as_ref());
    let dependency_changes = compare_dependency_maps(&old_dependencies, &new_dependencies);
    if !dependency_changes.added.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencyAdded,
            manifest_path.clone(),
            "dependency added",
            dependency_changes.added.clone(),
        );
    }
    if !dependency_changes.removed.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencyRemoved,
            manifest_path.clone(),
            "dependency removed",
            dependency_changes.removed.clone(),
        );
    }
    if !dependency_changes.source_changed.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencySourceChanged,
            manifest_path.clone(),
            "dependency source changed",
            dependency_changes.source_changed.clone(),
        );
    }

    let old_scripts = npm_string_map(old_manifest.as_ref(), &["scripts"]);
    let new_scripts = npm_string_map(new_manifest.as_ref(), &["scripts"]);
    let install_script_keys = [
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "prepublish",
        "prepublishOnly",
    ];
    let added_install_scripts = added_keys(&old_scripts, &new_scripts, &install_script_keys);
    if !added_install_scripts.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::InstallScriptAdded,
            manifest_path.clone(),
            "install script added",
            added_install_scripts,
        );
    }
    let changed_install_scripts = changed_keys(&old_scripts, &new_scripts, &install_script_keys);
    if !changed_install_scripts.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::InstallScriptChanged,
            manifest_path.clone(),
            "install script changed",
            changed_install_scripts,
        );
    }

    let build_script_keys = ["build", "prebuild", "postbuild"];
    let changed_build_scripts =
        changed_or_added_keys(&old_scripts, &new_scripts, &build_script_keys);
    if !changed_build_scripts.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::BuildScriptChanged,
            manifest_path.clone(),
            "build script changed",
            changed_build_scripts,
        );
    }

    let entrypoint_fields = [
        "main", "module", "browser", "exports", "bin", "types", "typings",
    ];
    let changed_entrypoints = changed_json_fields(
        old_manifest.as_ref(),
        new_manifest.as_ref(),
        &entrypoint_fields,
    );
    if !changed_entrypoints.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::EntrypointChanged,
            manifest_path.clone(),
            "entrypoint changed",
            changed_entrypoints,
        );
    }

    if npm_bin_added(old_manifest.as_ref(), new_manifest.as_ref()) {
        builder.push_signal_with_excerpt(
            Signal::ExecutableAdded,
            manifest_path,
            "manifest bin entry added",
            vec!["bin".to_string()],
        );
    }

    Ok(())
}

fn analyze_cargo_signals(
    old_root: &Path,
    new_root: &Path,
    diff: &DiffSummary,
    builder: &mut AnalysisBuilder,
) -> Result<(), SignalError> {
    let Some(manifest_path) = find_changed_path(diff, |path| file_name(path) == Some("Cargo.toml"))
    else {
        return Ok(());
    };

    let old_manifest = read_optional_toml(old_root.join(&manifest_path))?;
    let new_manifest = read_optional_toml(new_root.join(&manifest_path))?;

    let old_dependencies = cargo_dependencies(old_manifest.as_ref());
    let new_dependencies = cargo_dependencies(new_manifest.as_ref());
    let dependency_changes = compare_dependency_maps(&old_dependencies, &new_dependencies);
    if !dependency_changes.added.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencyAdded,
            manifest_path.clone(),
            "dependency added",
            dependency_changes.added.clone(),
        );
    }
    if !dependency_changes.removed.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencyRemoved,
            manifest_path.clone(),
            "dependency removed",
            dependency_changes.removed.clone(),
        );
    }
    if !dependency_changes.source_changed.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencySourceChanged,
            manifest_path.clone(),
            "dependency source changed",
            dependency_changes.source_changed.clone(),
        );
    }

    let changed_entrypoints =
        changed_cargo_entrypoints(old_manifest.as_ref(), new_manifest.as_ref());
    if !changed_entrypoints.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::EntrypointChanged,
            manifest_path.clone(),
            "entrypoint changed",
            changed_entrypoints,
        );
    }

    let changed_build = changed_cargo_build_settings(old_manifest.as_ref(), new_manifest.as_ref());
    if !changed_build.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::BuildScriptChanged,
            manifest_path,
            "build script changed",
            changed_build,
        );
    }

    Ok(())
}

fn analyze_rubygems_signals(
    old_root: &Path,
    new_root: &Path,
    diff: &DiffSummary,
    builder: &mut AnalysisBuilder,
) -> Result<(), SignalError> {
    let Some(manifest_path) = find_changed_path(diff, |path| {
        matches!(file_name(path), Some("Gemfile") | Some("Gemfile.lock"))
            || path.ends_with(".gemspec")
    }) else {
        return Ok(());
    };

    let old_text = read_optional_text(old_root.join(&manifest_path))?.unwrap_or_default();
    let new_text = read_optional_text(new_root.join(&manifest_path))?.unwrap_or_default();

    let added_dependencies = added_matching_lines(&old_text, &new_text, |line| {
        line.contains("add_dependency")
            || line.contains("add_runtime_dependency")
            || line.contains("add_development_dependency")
    });
    if !added_dependencies.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencyAdded,
            manifest_path.clone(),
            "dependency added",
            added_dependencies,
        );
    }

    let removed_dependencies = removed_matching_lines(&old_text, &new_text, |line| {
        line.contains("add_dependency")
            || line.contains("add_runtime_dependency")
            || line.contains("add_development_dependency")
    });
    if !removed_dependencies.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencyRemoved,
            manifest_path.clone(),
            "dependency removed",
            removed_dependencies,
        );
    }

    let changed_executables =
        changed_text_feature(&old_text, &new_text, &["executables", "bindir"]);
    if !changed_executables.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::EntrypointChanged,
            manifest_path,
            "entrypoint changed",
            changed_executables,
        );
    }

    Ok(())
}

fn analyze_pypi_signals(
    old_root: &Path,
    new_root: &Path,
    diff: &DiffSummary,
    builder: &mut AnalysisBuilder,
) -> Result<(), SignalError> {
    let Some(manifest_path) = find_changed_path(diff, |path| {
        matches!(
            file_name(path),
            Some("pyproject.toml")
                | Some("setup.py")
                | Some("setup.cfg")
                | Some("Pipfile")
                | Some("Pipfile.lock")
                | Some("poetry.lock")
                | Some("pdm.lock")
        ) || path.contains("requirements")
    }) else {
        return Ok(());
    };

    let old_text = read_optional_text(old_root.join(&manifest_path))?.unwrap_or_default();
    let new_text = read_optional_text(new_root.join(&manifest_path))?.unwrap_or_default();

    let added_dependencies = added_matching_lines(&old_text, &new_text, |line| {
        line.contains("dependencies")
            || line.contains("install_requires")
            || line.contains("requirements")
    });
    if !added_dependencies.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencyAdded,
            manifest_path.clone(),
            "dependency added",
            added_dependencies,
        );
    }

    let removed_dependencies = removed_matching_lines(&old_text, &new_text, |line| {
        line.contains("dependencies")
            || line.contains("install_requires")
            || line.contains("requirements")
    });
    if !removed_dependencies.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::DependencyRemoved,
            manifest_path.clone(),
            "dependency removed",
            removed_dependencies,
        );
    }

    let changed_entrypoints = changed_text_feature(
        &old_text,
        &new_text,
        &[
            "entry_points",
            "console_scripts",
            "[project.scripts]",
            "[project.entry-points",
        ],
    );
    if !changed_entrypoints.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::EntrypointChanged,
            manifest_path.clone(),
            "entrypoint changed",
            changed_entrypoints,
        );
    }

    let changed_build = changed_text_feature(&old_text, &new_text, &["build-system", "setup.py"]);
    if !changed_build.is_empty() {
        builder.push_signal_with_excerpt(
            Signal::BuildScriptChanged,
            manifest_path,
            "build script changed",
            changed_build,
        );
    }

    Ok(())
}

fn inventory_index(inventory: &InventorySummary) -> BTreeMap<String, &FileEntry> {
    inventory
        .entries
        .iter()
        .map(|entry| (entry.path.to_string_lossy().into_owned(), entry))
        .collect()
}

fn is_executable_entry(entry: &FileEntry) -> bool {
    entry.file_type == FileType::File && entry.mode & 0o111 != 0
}

fn is_binary_added(root: &Path, entry: &FileEntry) -> Result<bool, SignalError> {
    let path = root.join(&entry.path);
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    if matches!(
        extension,
        "exe" | "dll" | "so" | "dylib" | "node" | "jar" | "class" | "wasm" | "a" | "o" | "bin"
    ) {
        return Ok(true);
    }

    let bytes = fs::read(&path).map_err(|source| SignalError::Io {
        path: path.clone(),
        source,
    })?;
    let sample = if bytes.len() > 4096 {
        &bytes[..4096]
    } else {
        &bytes[..]
    };
    if sample.is_empty() {
        return Ok(false);
    }

    if sample.contains(&0) {
        return Ok(true);
    }

    let non_text = sample
        .iter()
        .filter(|byte| !matches!(byte, b'\n' | b'\r' | b'\t' | 0x20..=0x7e))
        .count();
    Ok(non_text * 5 > sample.len())
}

fn is_build_script_path(path: &str) -> bool {
    matches!(
        file_name(path),
        Some("build.rs") | Some("setup.py") | Some("binding.gyp")
    )
}

fn read_optional_json(path: PathBuf) -> Result<Option<JsonValue>, SignalError> {
    let Some(text) = read_optional_text(path)? else {
        return Ok(None);
    };
    Ok(serde_json::from_str(&text).ok())
}

fn read_optional_toml(path: PathBuf) -> Result<Option<TomlValue>, SignalError> {
    let Some(text) = read_optional_text(path)? else {
        return Ok(None);
    };
    Ok(text.parse::<TomlValue>().ok())
}

fn read_optional_text(path: PathBuf) -> Result<Option<String>, SignalError> {
    match fs::read_to_string(&path) {
        Ok(text) => Ok(Some(text)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(SignalError::Io { path, source }),
    }
}

fn find_changed_path<F>(diff: &DiffSummary, predicate: F) -> Option<String>
where
    F: Fn(&str) -> bool,
{
    diff.changed_paths
        .iter()
        .find(|path| predicate(path))
        .cloned()
}

fn file_name(path: &str) -> Option<&str> {
    Path::new(path).file_name().and_then(|name| name.to_str())
}

#[derive(Debug, Default)]
struct DependencyChanges {
    added: Vec<String>,
    removed: Vec<String>,
    source_changed: Vec<String>,
}

fn compare_dependency_maps(
    old_dependencies: &BTreeMap<String, DependencySpec>,
    new_dependencies: &BTreeMap<String, DependencySpec>,
) -> DependencyChanges {
    let mut changes = DependencyChanges::default();

    for name in new_dependencies.keys() {
        if !old_dependencies.contains_key(name) {
            changes.added.push(name.clone());
        }
    }

    for name in old_dependencies.keys() {
        if !new_dependencies.contains_key(name) {
            changes.removed.push(name.clone());
        }
    }

    for (name, old_spec) in old_dependencies {
        let Some(new_spec) = new_dependencies.get(name) else {
            continue;
        };
        if old_spec.source_fingerprint != new_spec.source_fingerprint
            && (!old_spec.source_fingerprint.is_empty() || !new_spec.source_fingerprint.is_empty())
        {
            changes.source_changed.push(name.clone());
        }
    }

    changes
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DependencySpec {
    source_fingerprint: String,
}

fn npm_dependencies(value: Option<&JsonValue>) -> BTreeMap<String, DependencySpec> {
    const SECTIONS: [&str; 6] = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundleDependencies",
        "bundledDependencies",
    ];

    let mut dependencies = BTreeMap::new();
    let Some(value) = value else {
        return dependencies;
    };

    for section in SECTIONS {
        let Some(section_value) = value.get(section) else {
            continue;
        };
        match section_value {
            JsonValue::Object(map) => {
                for (name, spec) in map {
                    dependencies.insert(
                        name.clone(),
                        DependencySpec {
                            source_fingerprint: npm_source_fingerprint(spec),
                        },
                    );
                }
            }
            JsonValue::Array(list) => {
                for name in list.iter().filter_map(|value| value.as_str()) {
                    dependencies.insert(
                        name.to_string(),
                        DependencySpec {
                            source_fingerprint: String::new(),
                        },
                    );
                }
            }
            _ => {}
        }
    }

    dependencies
}

fn npm_source_fingerprint(value: &JsonValue) -> String {
    let Some(spec) = value.as_str() else {
        return String::new();
    };
    let lowered = spec.to_lowercase();
    if [
        "git+",
        "git://",
        "http://",
        "https://",
        "file:",
        "link:",
        "workspace:",
        "github:",
    ]
    .iter()
    .any(|prefix| lowered.starts_with(prefix))
    {
        lowered
    } else {
        String::new()
    }
}

fn npm_string_map(value: Option<&JsonValue>, path: &[&str]) -> BTreeMap<String, String> {
    let mut current = match value {
        Some(value) => value,
        None => return BTreeMap::new(),
    };

    for key in path {
        let Some(next) = current.get(*key) else {
            return BTreeMap::new();
        };
        current = next;
    }

    current
        .as_object()
        .into_iter()
        .flat_map(|map| map.iter())
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
        .collect()
}

fn added_keys(
    old_map: &BTreeMap<String, String>,
    new_map: &BTreeMap<String, String>,
    keys: &[&str],
) -> Vec<String> {
    keys.iter()
        .copied()
        .filter(|key| !old_map.contains_key(*key) && new_map.contains_key(*key))
        .map(str::to_string)
        .collect()
}

fn changed_keys(
    old_map: &BTreeMap<String, String>,
    new_map: &BTreeMap<String, String>,
    keys: &[&str],
) -> Vec<String> {
    keys.iter()
        .copied()
        .filter(|key| {
            matches!((old_map.get(*key), new_map.get(*key)), (Some(old), Some(new)) if old != new)
        })
        .map(str::to_string)
        .collect()
}

fn changed_or_added_keys(
    old_map: &BTreeMap<String, String>,
    new_map: &BTreeMap<String, String>,
    keys: &[&str],
) -> Vec<String> {
    keys.iter()
        .copied()
        .filter(|key| match (old_map.get(*key), new_map.get(*key)) {
            (None, Some(_)) | (Some(_), None) => true,
            (Some(old), Some(new)) => old != new,
            (None, None) => false,
        })
        .map(str::to_string)
        .collect()
}

fn changed_json_fields(
    old_value: Option<&JsonValue>,
    new_value: Option<&JsonValue>,
    fields: &[&str],
) -> Vec<String> {
    fields
        .iter()
        .copied()
        .filter(|field| {
            old_value.and_then(|value| value.get(*field))
                != new_value.and_then(|value| value.get(*field))
        })
        .map(str::to_string)
        .collect()
}

fn npm_bin_added(old_value: Option<&JsonValue>, new_value: Option<&JsonValue>) -> bool {
    let old_bin = old_value.and_then(|value| value.get("bin"));
    let new_bin = new_value.and_then(|value| value.get("bin"));

    match (old_bin, new_bin) {
        (None, Some(JsonValue::String(_))) | (None, Some(JsonValue::Object(_))) => true,
        (Some(JsonValue::String(_)), Some(JsonValue::Object(map))) => !map.is_empty(),
        (Some(JsonValue::Object(old_map)), Some(JsonValue::Object(new_map))) => {
            new_map.keys().any(|key| !old_map.contains_key(key))
        }
        _ => false,
    }
}

fn cargo_dependencies(value: Option<&TomlValue>) -> BTreeMap<String, DependencySpec> {
    let mut dependencies = BTreeMap::new();
    let Some(value) = value else {
        return dependencies;
    };

    collect_cargo_dependency_tables(value, &mut dependencies);
    if let Some(targets) = value.get("target").and_then(TomlValue::as_table) {
        for target in targets.values() {
            collect_cargo_dependency_tables(target, &mut dependencies);
        }
    }

    dependencies
}

fn collect_cargo_dependency_tables(
    value: &TomlValue,
    dependencies: &mut BTreeMap<String, DependencySpec>,
) {
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = value.get(section).and_then(TomlValue::as_table) else {
            continue;
        };
        for (name, spec) in table {
            dependencies.insert(
                name.clone(),
                DependencySpec {
                    source_fingerprint: cargo_source_fingerprint(spec),
                },
            );
        }
    }
}

fn cargo_source_fingerprint(value: &TomlValue) -> String {
    let Some(table) = value.as_table() else {
        return String::new();
    };

    let mut parts = Vec::new();
    for key in ["path", "git", "registry", "package", "branch", "tag", "rev"] {
        if let Some(value) = table.get(key) {
            parts.push(format!("{key}={}", toml_value_string(value)));
        }
    }
    parts.join(";")
}

fn changed_cargo_entrypoints(
    old_value: Option<&TomlValue>,
    new_value: Option<&TomlValue>,
) -> Vec<String> {
    let mut changed = Vec::new();

    if cargo_toml_path(old_value, &["lib", "path"]) != cargo_toml_path(new_value, &["lib", "path"])
    {
        changed.push("lib.path".to_string());
    }
    if cargo_toml_path(old_value, &["package", "default-run"])
        != cargo_toml_path(new_value, &["package", "default-run"])
    {
        changed.push("package.default-run".to_string());
    }
    if cargo_bin_fingerprint(old_value) != cargo_bin_fingerprint(new_value) {
        changed.push("[[bin]]".to_string());
    }

    changed
}

fn changed_cargo_build_settings(
    old_value: Option<&TomlValue>,
    new_value: Option<&TomlValue>,
) -> Vec<String> {
    let mut changed = Vec::new();
    if cargo_toml_path(old_value, &["package", "build"])
        != cargo_toml_path(new_value, &["package", "build"])
    {
        changed.push("package.build".to_string());
    }
    changed
}

fn cargo_toml_path(value: Option<&TomlValue>, path: &[&str]) -> Option<String> {
    let mut current = value?;
    for key in path {
        current = current.get(*key)?;
    }
    Some(toml_value_string(current))
}

fn cargo_bin_fingerprint(value: Option<&TomlValue>) -> Vec<String> {
    value
        .and_then(|value| value.get("bin"))
        .and_then(TomlValue::as_array)
        .into_iter()
        .flat_map(|bins| bins.iter())
        .filter_map(TomlValue::as_table)
        .map(|bin| {
            let name = bin.get("name").map(toml_value_string).unwrap_or_default();
            let path = bin.get("path").map(toml_value_string).unwrap_or_default();
            format!("{name}:{path}")
        })
        .collect()
}

fn toml_value_string(value: &TomlValue) -> String {
    match value {
        TomlValue::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn added_matching_lines<F>(old_text: &str, new_text: &str, predicate: F) -> Vec<String>
where
    F: Fn(&str) -> bool,
{
    let old_lines = old_text.lines().map(str::trim).collect::<Vec<_>>();
    new_text
        .lines()
        .map(str::trim)
        .filter(|line| predicate(line) && !old_lines.contains(line))
        .map(str::to_string)
        .collect()
}

fn removed_matching_lines<F>(old_text: &str, new_text: &str, predicate: F) -> Vec<String>
where
    F: Fn(&str) -> bool,
{
    let new_lines = new_text.lines().map(str::trim).collect::<Vec<_>>();
    old_text
        .lines()
        .map(str::trim)
        .filter(|line| predicate(line) && !new_lines.contains(line))
        .map(str::to_string)
        .collect()
}

fn changed_text_feature(old_text: &str, new_text: &str, keywords: &[&str]) -> Vec<String> {
    keywords
        .iter()
        .copied()
        .filter(|keyword| {
            old_text.contains(keyword) != new_text.contains(keyword)
                || old_text != new_text && new_text.contains(keyword)
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::diff::DiffSummary;
    use crate::inventory::{FileEntry, FileType, InventorySummary};
    use crate::registry::Ecosystem;

    use super::{Signal, SignalAnalysis};

    #[test]
    fn analyzes_npm_manifest_signals_and_excerpts() {
        let old_root = TestDir::new("npm-old");
        let new_root = TestDir::new("npm-new");
        fs::write(
            old_root.path().join("package.json"),
            concat!(
                "{\n",
                "  \"main\": \"index.js\",\n",
                "  \"dependencies\": {\n",
                "    \"left-pad\": \"^1.0.0\",\n",
                "    \"remote\": \"git+https://old.example/repo.git\"\n",
                "  },\n",
                "  \"scripts\": {\n",
                "    \"install\": \"node install-old.js\",\n",
                "    \"build\": \"webpack --mode production\"\n",
                "  }\n",
                "}\n"
            ),
        )
        .expect("old package.json should be written");
        fs::write(
            new_root.path().join("package.json"),
            concat!(
                "{\n",
                "  \"main\": \"dist/index.js\",\n",
                "  \"bin\": {\n",
                "    \"demo\": \"bin/demo.js\"\n",
                "  },\n",
                "  \"dependencies\": {\n",
                "    \"left-pad\": \"^1.0.0\",\n",
                "    \"remote\": \"git+https://new.example/repo.git\",\n",
                "    \"chalk\": \"^5.0.0\"\n",
                "  },\n",
                "  \"scripts\": {\n",
                "    \"install\": \"node install-new.js\",\n",
                "    \"postinstall\": \"node postinstall.js\",\n",
                "    \"build\": \"vite build\"\n",
                "  }\n",
                "}\n"
            ),
        )
        .expect("new package.json should be written");

        let analysis = SignalAnalysis::analyze_v0(
            Ecosystem::Npm,
            old_root.path(),
            new_root.path(),
            &InventorySummary::default(),
            &InventorySummary::default(),
            &DiffSummary {
                files_changed: 1,
                changed_paths: vec!["package.json".to_string()],
                modified_paths: vec!["package.json".to_string()],
                ..DiffSummary::default()
            },
        )
        .expect("npm analysis should succeed");

        assert_eq!(
            analysis.signals,
            vec![
                Signal::DependencyAdded,
                Signal::DependencySourceChanged,
                Signal::InstallScriptAdded,
                Signal::InstallScriptChanged,
                Signal::BuildScriptChanged,
                Signal::EntrypointChanged,
                Signal::ExecutableAdded,
            ]
        );
        assert!(analysis
            .interesting_files
            .iter()
            .any(
                |excerpt| excerpt.reason == "dependency added" && excerpt.excerpt.contains("chalk")
            ));
        assert!(analysis
            .interesting_files
            .iter()
            .any(|excerpt| excerpt.reason == "install script added"
                && excerpt.excerpt.contains("postinstall")));
    }

    #[test]
    fn analyzes_cargo_manifest_and_build_script_signals() {
        let old_root = TestDir::new("cargo-old");
        let new_root = TestDir::new("cargo-new");
        fs::write(
            old_root.path().join("Cargo.toml"),
            concat!(
                "[package]\n",
                "name = \"demo\"\n",
                "version = \"0.1.0\"\n\n",
                "[dependencies]\n",
                "serde = \"1\"\n",
                "remote = { git = \"https://old.example/repo.git\" }\n\n",
                "[[bin]]\n",
                "name = \"demo\"\n",
                "path = \"src/main.rs\"\n"
            ),
        )
        .expect("old Cargo.toml should be written");
        fs::write(
            new_root.path().join("Cargo.toml"),
            concat!(
                "[package]\n",
                "name = \"demo\"\n",
                "version = \"0.1.0\"\n",
                "build = \"build.rs\"\n\n",
                "[dependencies]\n",
                "serde = \"1\"\n",
                "remote = { git = \"https://new.example/repo.git\" }\n",
                "clap = \"4\"\n\n",
                "[[bin]]\n",
                "name = \"demo-cli\"\n",
                "path = \"src/bin/demo.rs\"\n"
            ),
        )
        .expect("new Cargo.toml should be written");
        fs::write(new_root.path().join("build.rs"), "fn main() {}\n")
            .expect("build.rs should be written");

        let analysis = SignalAnalysis::analyze_v0(
            Ecosystem::Crates,
            old_root.path(),
            new_root.path(),
            &InventorySummary::default(),
            &InventorySummary::default(),
            &DiffSummary {
                files_added: 1,
                files_changed: 1,
                changed_paths: vec!["build.rs".to_string(), "Cargo.toml".to_string()],
                added_paths: vec!["build.rs".to_string()],
                modified_paths: vec!["Cargo.toml".to_string()],
                ..DiffSummary::default()
            },
        )
        .expect("cargo analysis should succeed");

        assert_eq!(
            analysis.signals,
            vec![
                Signal::BuildScriptChanged,
                Signal::DependencyAdded,
                Signal::DependencySourceChanged,
                Signal::EntrypointChanged,
            ]
        );
        assert!(analysis
            .interesting_files
            .iter()
            .any(|excerpt| excerpt.path == "Cargo.toml" && excerpt.excerpt.contains("clap")));
        assert!(analysis
            .interesting_files
            .iter()
            .any(|excerpt| excerpt.path == "build.rs"));
    }

    #[test]
    fn detects_added_binary_and_executable_files() {
        let old_root = TestDir::new("files-old");
        let new_root = TestDir::new("files-new");
        fs::create_dir_all(new_root.path().join("bin")).expect("bin dir should exist");
        fs::create_dir_all(new_root.path().join("native")).expect("native dir should exist");
        fs::write(new_root.path().join("bin/tool.sh"), b"#!/bin/sh\necho hi\n")
            .expect("script should be written");
        fs::write(
            new_root.path().join("native/addon.node"),
            [0_u8, 159, 146, 150],
        )
        .expect("binary should be written");

        let new_inventory = InventorySummary {
            entries: vec![
                FileEntry {
                    path: PathBuf::from("bin/tool.sh"),
                    file_type: FileType::File,
                    size: 18,
                    mode: 0o100755,
                    digest: None,
                },
                FileEntry {
                    path: PathBuf::from("native/addon.node"),
                    file_type: FileType::File,
                    size: 4,
                    mode: 0o100644,
                    digest: None,
                },
            ],
        };

        let analysis = SignalAnalysis::analyze_v0(
            Ecosystem::Pypi,
            old_root.path(),
            new_root.path(),
            &InventorySummary::default(),
            &new_inventory,
            &DiffSummary {
                files_added: 2,
                changed_paths: vec!["bin/tool.sh".to_string(), "native/addon.node".to_string()],
                added_paths: vec!["bin/tool.sh".to_string(), "native/addon.node".to_string()],
                ..DiffSummary::default()
            },
        )
        .expect("generic file analysis should succeed");

        assert_eq!(
            analysis.signals,
            vec![Signal::ExecutableAdded, Signal::BinaryAdded]
        );
        assert!(analysis
            .interesting_files
            .iter()
            .any(|excerpt| excerpt.path == "bin/tool.sh" && excerpt.excerpt.contains("echo hi")));
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
            let path = std::env::temp_dir().join(format!("pincushion-signals-{label}-{unique}"));
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
