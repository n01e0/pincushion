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
