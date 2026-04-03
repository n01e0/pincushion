#![allow(dead_code)]

mod config;
mod diff;
mod fetch;
mod http;
mod inventory;
mod registry;
mod report;
mod review;
mod signals;
mod state;
mod unpack;

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use config::{ConfigError, WatchlistConfig};
use registry::{RegistryAdapters, RegistryLookupResult};
use state::{BaselineState, SeenState, StateError, StateLayout};

const USAGE: &str = concat!(
    "Usage:\n",
    "  pincushion check --config <path>\n",
    "  pincushion --help\n",
);

fn main() -> ExitCode {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

    match run_app(env::args_os(), &mut stdout) {
        Ok(exit_code) => exit_code,
        Err(error) => {
            let _ = writeln!(stderr, "error: {error}");
            error.exit_code()
        }
    }
}

fn run_app<I, S, W>(args: I, stdout: &mut W) -> Result<ExitCode, AppError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    W: Write,
{
    match parse_args(args)? {
        CliCommand::Help => {
            write!(stdout, "{USAGE}").map_err(AppError::Output)?;
            Ok(ExitCode::SUCCESS)
        }
        CliCommand::Check { config_path } => {
            execute_check_with_lookup(&config_path, stdout, |config| {
                RegistryAdapters::default().lookup_latest_versions(config)
            })
            .map(CheckOutcome::exit_code)
        }
    }
}

fn execute_check_with_lookup<W, F>(
    config_path: &Path,
    stdout: &mut W,
    lookup_latest_versions: F,
) -> Result<CheckOutcome, AppError>
where
    W: Write,
    F: FnOnce(&WatchlistConfig) -> Vec<RegistryLookupResult>,
{
    let config = WatchlistConfig::load_from_path(config_path).map_err(AppError::Config)?;
    let state_layout =
        StateLayout::from_config_path(config_path).map_err(|source| AppError::StateLayout {
            path: config_path.to_path_buf(),
            source,
        })?;

    writeln!(stdout, "Loaded config {}", config_path.display()).map_err(AppError::Output)?;

    let lookup_results = lookup_latest_versions(&config);
    let mut current_versions = Vec::new();
    let mut lookup_failures = Vec::new();

    for lookup in lookup_results {
        match lookup.result {
            Ok(package_version) => current_versions.push(package_version),
            Err(error) => lookup_failures.push((lookup.package.package_key(), error.to_string())),
        }
    }

    writeln!(
        stdout,
        "Resolved {} package(s) successfully.",
        current_versions.len()
    )
    .map_err(AppError::Output)?;

    let outcome = CheckOutcome {
        partial_failures: lookup_failures.len(),
        ..CheckOutcome::default()
    };

    if !lookup_failures.is_empty() {
        writeln!(
            stdout,
            "Failed to resolve {} package(s):",
            lookup_failures.len()
        )
        .map_err(AppError::Output)?;
        for (package_key, error) in &lookup_failures {
            writeln!(stdout, "  - {package_key}: {error}").map_err(AppError::Output)?;
        }
    }

    if current_versions.is_empty() {
        writeln!(
            stdout,
            "No package versions were resolved; skipping state update."
        )
        .map_err(AppError::Output)?;
        return Ok(outcome);
    }

    match state_layout
        .initialize_baseline_if_empty(&current_versions)
        .map_err(AppError::State)?
    {
        BaselineState::Initialized(seen_state) => {
            print_baseline_summary(stdout, &state_layout, &seen_state)?;
            Ok(outcome)
        }
        BaselineState::Existing(previous_seen_state) => {
            let detection = previous_seen_state.detect_changes(&current_versions);
            let next_seen_state = SeenState::from_package_versions(&current_versions);
            state_layout
                .save_seen_state(&next_seen_state)
                .map_err(AppError::State)?;
            print_change_summary(stdout, &state_layout, &detection)?;
            Ok(outcome)
        }
    }
}

fn print_baseline_summary<W>(
    stdout: &mut W,
    state_layout: &StateLayout,
    seen_state: &SeenState,
) -> Result<(), AppError>
where
    W: Write,
{
    writeln!(
        stdout,
        "Initialized baseline at {}.",
        state_layout.seen_file().display()
    )
    .map_err(AppError::Output)?;
    writeln!(
        stdout,
        "First run is baseline-only; skipping change processing."
    )
    .map_err(AppError::Output)?;

    for (package_key, version) in &seen_state.packages {
        writeln!(stdout, "  - {package_key} @ {version}").map_err(AppError::Output)?;
    }

    Ok(())
}

fn print_change_summary<W>(
    stdout: &mut W,
    state_layout: &StateLayout,
    detection: &state::ChangeDetection,
) -> Result<(), AppError>
where
    W: Write,
{
    writeln!(
        stdout,
        "Detected {} changed, {} unchanged, and {} newly tracked package(s).",
        detection.changed.len(),
        detection.unchanged.len(),
        detection.newly_tracked.len(),
    )
    .map_err(AppError::Output)?;

    if detection.changed.is_empty() && detection.newly_tracked.is_empty() {
        writeln!(stdout, "No version changes detected.").map_err(AppError::Output)?;
    }

    if !detection.changed.is_empty() {
        writeln!(stdout, "Changed:").map_err(AppError::Output)?;
        for change in &detection.changed {
            writeln!(
                stdout,
                "  - {}: {} -> {}",
                change.package.package_key(),
                change.previous_version,
                change.package.version
            )
            .map_err(AppError::Output)?;
        }
    }

    if !detection.unchanged.is_empty() {
        writeln!(stdout, "Unchanged:").map_err(AppError::Output)?;
        for package in &detection.unchanged {
            writeln!(
                stdout,
                "  - {} @ {}",
                package.package.package_key(),
                package.package.version
            )
            .map_err(AppError::Output)?;
        }
    }

    if !detection.newly_tracked.is_empty() {
        writeln!(stdout, "Newly tracked:").map_err(AppError::Output)?;
        for package in &detection.newly_tracked {
            writeln!(
                stdout,
                "  - {} @ {}",
                package.package.package_key(),
                package.package.version
            )
            .map_err(AppError::Output)?;
        }
    }

    writeln!(
        stdout,
        "Updated seen state {}",
        state_layout.seen_file().display()
    )
    .map_err(AppError::Output)?;

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Help,
    Check { config_path: PathBuf },
}

fn parse_args<I, S>(args: I) -> Result<CliCommand, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut args = args.into_iter().map(Into::into);
    let _program = args.next();

    let Some(command) = args.next() else {
        return Err(CliError::Usage(
            "missing subcommand; expected `check`".to_string(),
        ));
    };

    match command.to_string_lossy().as_ref() {
        "-h" | "--help" => Ok(CliCommand::Help),
        "check" => parse_check_args(args),
        other => Err(CliError::Usage(format!(
            "unknown subcommand `{other}`; expected `check`"
        ))),
    }
}

fn parse_check_args<I>(args: I) -> Result<CliCommand, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut config_path = None;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "-h" | "--help" => return Ok(CliCommand::Help),
            "--config" => {
                let value = args.next().ok_or_else(|| {
                    CliError::Usage("missing value for required `--config <path>`".to_string())
                })?;

                if config_path.is_some() {
                    return Err(CliError::Usage(
                        "`--config` may only be provided once".to_string(),
                    ));
                }

                config_path = Some(PathBuf::from(value));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument `{other}` for `check`"
                )));
            }
        }
    }

    let config_path = config_path.ok_or_else(|| {
        CliError::Usage("missing required argument `--config <path>`".to_string())
    })?;

    Ok(CliCommand::Check { config_path })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct CheckOutcome {
    suspicious_packages: usize,
    partial_failures: usize,
}

impl CheckOutcome {
    fn exit_code(self) -> ExitCode {
        if self.partial_failures > 0 {
            return ExitCode::from(ExitCodePolicy::PartialFailure.code());
        }

        if self.suspicious_packages > 0 {
            return ExitCode::from(ExitCodePolicy::SuspiciousFound.code());
        }

        ExitCode::SUCCESS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitCodePolicy {
    SuspiciousFound,
    PartialFailure,
}

impl ExitCodePolicy {
    const fn code(self) -> u8 {
        match self {
            Self::SuspiciousFound => 10,
            Self::PartialFailure => 20,
        }
    }
}

#[derive(Debug)]
enum AppError {
    Cli(CliError),
    Config(ConfigError),
    StateLayout { path: PathBuf, source: io::Error },
    State(StateError),
    Output(io::Error),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli(error) => write!(f, "{error}"),
            Self::Config(error) => write!(f, "{error}"),
            Self::StateLayout { path, source } => write!(
                f,
                "failed to derive state layout from config {}: {source}",
                path.display()
            ),
            Self::State(error) => write!(f, "{error}"),
            Self::Output(error) => write!(f, "failed to write CLI output: {error}"),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cli(error) => Some(error),
            Self::Config(error) => Some(error),
            Self::StateLayout { source, .. } => Some(source),
            Self::State(error) => Some(error),
            Self::Output(error) => Some(error),
        }
    }
}

impl AppError {
    fn exit_code(&self) -> ExitCode {
        ExitCode::FAILURE
    }
}

impl From<CliError> for AppError {
    fn from(value: CliError) -> Self {
        Self::Cli(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliError {
    Usage(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(f, "{message}\n\n{USAGE}"),
        }
    }
}

impl Error for CliError {}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::registry::{
        Ecosystem, PackageCoordinate, PackageVersion, RegistryError, RegistryLookupResult,
    };

    use super::{execute_check_with_lookup, parse_args, CheckOutcome, CliCommand, ExitCodePolicy};

    #[test]
    fn parses_check_command_with_config_path() {
        let command = parse_args(["pincushion", "check", "--config", "configs/watchlist.yaml"])
            .expect("check command should parse");

        assert_eq!(
            command,
            CliCommand::Check {
                config_path: PathBuf::from("configs/watchlist.yaml"),
            }
        );
    }

    #[test]
    fn rejects_check_command_without_config_path() {
        let error =
            parse_args(["pincushion", "check"]).expect_err("config flag should be required");

        assert!(error
            .to_string()
            .contains("missing required argument `--config <path>`"));
    }

    #[test]
    fn initializes_baseline_on_first_successful_run() {
        let fixture = TestFixture::new("baseline");
        fixture.write_config("npm:\n  - react\nreview:\n  provider: none\n");

        let mut stdout = Vec::new();
        let outcome = execute_check_with_lookup(fixture.config_path(), &mut stdout, |_config| {
            vec![lookup_success(Ecosystem::Npm, "react", "19.1.0")]
        })
        .expect("baseline run should succeed");

        assert_eq!(outcome.exit_code(), std::process::ExitCode::SUCCESS);

        let output = String::from_utf8(stdout).expect("stdout should be utf8");
        assert!(output.contains("Initialized baseline at"));
        assert!(output.contains("First run is baseline-only"));
        assert!(output.contains("npm:react @ 19.1.0"));

        let seen_contents = fs::read_to_string(fixture.seen_file_path())
            .expect("baseline run should persist seen state");
        assert!(seen_contents.contains("\"npm:react\": \"19.1.0\""));
    }

    #[test]
    fn reports_changes_unchanged_and_new_packages_on_subsequent_runs() {
        let fixture = TestFixture::new("changes");
        fixture.write_config(
            "npm:\n  - react\ncrates:\n  - clap\npypi:\n  - requests\nreview:\n  provider: none\n",
        );
        fixture.write_seen(
            "{\n  \"packages\": {\n    \"npm:react\": \"19.0.0\",\n    \"crates:clap\": \"4.5.31\"\n  }\n}\n",
        );

        let mut stdout = Vec::new();
        let outcome = execute_check_with_lookup(fixture.config_path(), &mut stdout, |_config| {
            vec![
                lookup_success(Ecosystem::Npm, "react", "19.1.0"),
                lookup_success(Ecosystem::Crates, "clap", "4.5.31"),
                lookup_success(Ecosystem::Pypi, "requests", "2.32.3"),
            ]
        })
        .expect("follow-up run should succeed");

        assert_eq!(outcome.exit_code(), std::process::ExitCode::SUCCESS);

        let output = String::from_utf8(stdout).expect("stdout should be utf8");
        assert!(output.contains("Detected 1 changed, 1 unchanged, and 1 newly tracked package(s)."));
        assert!(output.contains("npm:react: 19.0.0 -> 19.1.0"));
        assert!(output.contains("crates:clap @ 4.5.31"));
        assert!(output.contains("pypi:requests @ 2.32.3"));
        assert!(output.contains("Updated seen state"));

        let seen_contents = fs::read_to_string(fixture.seen_file_path())
            .expect("follow-up run should update seen state");
        assert!(seen_contents.contains("\"npm:react\": \"19.1.0\""));
        assert!(seen_contents.contains("\"crates:clap\": \"4.5.31\""));
        assert!(seen_contents.contains("\"pypi:requests\": \"2.32.3\""));
    }

    #[test]
    fn reports_lookup_failures_as_partial_failure_and_persists_successful_versions() {
        let fixture = TestFixture::new("lookup-failure");
        fixture.write_config("npm:\n  - react\npypi:\n  - requests\nreview:\n  provider: none\n");

        let mut stdout = Vec::new();
        let outcome = execute_check_with_lookup(fixture.config_path(), &mut stdout, |_config| {
            vec![
                lookup_success(Ecosystem::Npm, "react", "19.1.0"),
                lookup_failure(Ecosystem::Pypi, "requests", "timeout"),
            ]
        })
        .expect("partial failure run should still complete");

        assert_eq!(
            outcome.exit_code(),
            std::process::ExitCode::from(ExitCodePolicy::PartialFailure.code())
        );

        let output = String::from_utf8(stdout).expect("stdout should be utf8");
        assert!(output.contains("Resolved 1 package(s) successfully."));
        assert!(output.contains("Failed to resolve 1 package(s):"));
        assert!(output.contains("pypi:requests: timeout"));
        assert!(output.contains("Initialized baseline at"));

        let seen_contents = fs::read_to_string(fixture.seen_file_path())
            .expect("successful lookups should still update seen state");
        assert!(seen_contents.contains("\"npm:react\": \"19.1.0\""));
        assert!(!seen_contents.contains("pypi:requests"));
    }

    #[test]
    fn returns_partial_failure_when_all_package_lookups_fail() {
        let fixture = TestFixture::new("all-lookup-failure");
        fixture.write_config("npm:\n  - react\nreview:\n  provider: none\n");

        let mut stdout = Vec::new();
        let outcome = execute_check_with_lookup(fixture.config_path(), &mut stdout, |_config| {
            vec![lookup_failure(Ecosystem::Npm, "react", "timeout")]
        })
        .expect("all-failure run should still complete");

        assert_eq!(
            outcome.exit_code(),
            std::process::ExitCode::from(ExitCodePolicy::PartialFailure.code())
        );

        let output = String::from_utf8(stdout).expect("stdout should be utf8");
        assert!(output.contains("Resolved 0 package(s) successfully."));
        assert!(output.contains("No package versions were resolved; skipping state update."));
        assert!(!fixture.seen_file_path().exists());
    }

    #[test]
    fn exit_code_policy_prioritizes_partial_failure_over_suspicious_results() {
        let partial_failure = CheckOutcome {
            suspicious_packages: 1,
            partial_failures: 1,
        };
        let suspicious_only = CheckOutcome {
            suspicious_packages: 1,
            partial_failures: 0,
        };

        assert_eq!(
            partial_failure.exit_code(),
            std::process::ExitCode::from(ExitCodePolicy::PartialFailure.code())
        );
        assert_eq!(
            suspicious_only.exit_code(),
            std::process::ExitCode::from(ExitCodePolicy::SuspiciousFound.code())
        );
    }

    fn lookup_success(ecosystem: Ecosystem, package: &str, version: &str) -> RegistryLookupResult {
        RegistryLookupResult {
            package: PackageCoordinate {
                ecosystem,
                package: package.to_string(),
            },
            result: Ok(PackageVersion {
                ecosystem,
                package: package.to_string(),
                version: version.to_string(),
            }),
        }
    }

    fn lookup_failure(ecosystem: Ecosystem, package: &str, message: &str) -> RegistryLookupResult {
        RegistryLookupResult {
            package: PackageCoordinate {
                ecosystem,
                package: package.to_string(),
            },
            result: Err(RegistryError::new(message.to_string())),
        }
    }

    struct TestFixture {
        root: PathBuf,
        config_path: PathBuf,
    }

    impl TestFixture {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos();
            let root = env::temp_dir().join(format!("pincushion-main-{label}-{unique}"));
            fs::create_dir_all(&root).expect("fixture root should be created");
            let config_path = root.join("watchlist.yaml");
            Self { root, config_path }
        }

        fn config_path(&self) -> &Path {
            &self.config_path
        }

        fn seen_file_path(&self) -> PathBuf {
            self.root.join(".pincushion/seen.json")
        }

        fn write_config(&self, contents: &str) {
            fs::write(&self.config_path, contents).expect("config should be written");
        }

        fn write_seen(&self, contents: &str) {
            let seen_path = self.seen_file_path();
            fs::create_dir_all(
                seen_path
                    .parent()
                    .expect("seen state should have a parent directory"),
            )
            .expect("state directory should be created");
            fs::write(seen_path, contents).expect("seen state should be written");
        }
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
