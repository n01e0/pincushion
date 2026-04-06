#![allow(dead_code)]

mod artifact_pipeline;
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

use artifact_pipeline::ProcessedChangeResult;
use config::{ConfigError, WatchlistConfig};
use registry::{RegistryAdapters, RegistryLookupResult};
use report::{JsonReportInput, JsonReportWriter, MarkdownReportWriter, ReportError};
use review::{ReviewBackend, ReviewBackendError, ReviewInput, ReviewInputAnalysis};
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
            let adapters = RegistryAdapters::default();
            execute_check_with_processing(
                &config_path,
                stdout,
                |config| adapters.lookup_latest_versions(config),
                |changes, state_layout| {
                    adapters
                        .pipeline()
                        .process_version_changes_in_state_layout(changes, state_layout)
                },
            )
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
    execute_check_with_processing(
        config_path,
        stdout,
        lookup_latest_versions,
        |_changes, _state_layout| Vec::new(),
    )
}

fn execute_check_with_processing<W, FLookup, FProcess>(
    config_path: &Path,
    stdout: &mut W,
    lookup_latest_versions: FLookup,
    process_changed_packages: FProcess,
) -> Result<CheckOutcome, AppError>
where
    W: Write,
    FLookup: FnOnce(&WatchlistConfig) -> Vec<RegistryLookupResult>,
    FProcess: FnOnce(&[state::VersionChange], &StateLayout) -> Vec<ProcessedChangeResult>,
{
    let config = WatchlistConfig::load_from_path(config_path).map_err(AppError::Config)?;
    let review_backend = ReviewBackend::from_provider(config.review.provider.clone())
        .map_err(AppError::ReviewBackend)?;
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
            let artifact_processing = if detection.changed.is_empty() {
                Vec::new()
            } else {
                process_changed_packages(&detection.changed, &state_layout)
            };
            let next_seen_state = SeenState::from_package_versions(&current_versions);
            state_layout
                .save_seen_state(&next_seen_state)
                .map_err(AppError::State)?;
            let report_paths = write_reports_for_processed_changes(
                &state_layout,
                &artifact_processing,
                &review_backend,
            )
            .map_err(AppError::Report)?;
            print_change_summary(
                stdout,
                &state_layout,
                &detection,
                &artifact_processing,
                &report_paths,
            )?;
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
    artifact_processing: &[ProcessedChangeResult],
    report_paths: &[GeneratedReportPaths],
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

    print_artifact_processing_summary(stdout, artifact_processing)?;
    print_generated_reports_summary(stdout, report_paths)?;

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

fn print_artifact_processing_summary<W>(
    stdout: &mut W,
    artifact_processing: &[ProcessedChangeResult],
) -> Result<(), AppError>
where
    W: Write,
{
    if artifact_processing.is_empty() {
        return Ok(());
    }

    writeln!(stdout, "Artifact processing:").map_err(AppError::Output)?;

    for processed in artifact_processing {
        match &processed.result {
            Ok(result) => {
                writeln!(
                    stdout,
                    "  - {}: diff {} added, {} removed, {} changed",
                    processed.change.package.package_key(),
                    result.analysis.diff.files_added,
                    result.analysis.diff.files_removed,
                    result.analysis.diff.files_changed
                )
                .map_err(AppError::Output)?;

                if !result.analysis.diff.added_paths.is_empty() {
                    writeln!(
                        stdout,
                        "    added: {}",
                        result.analysis.diff.added_paths.join(", ")
                    )
                    .map_err(AppError::Output)?;
                }
                if !result.analysis.diff.removed_paths.is_empty() {
                    writeln!(
                        stdout,
                        "    removed: {}",
                        result.analysis.diff.removed_paths.join(", ")
                    )
                    .map_err(AppError::Output)?;
                }
                if !result.analysis.diff.modified_paths.is_empty() {
                    writeln!(
                        stdout,
                        "    modified: {}",
                        result.analysis.diff.modified_paths.join(", ")
                    )
                    .map_err(AppError::Output)?;
                }
                if !result.analysis.diff.has_changes() {
                    writeln!(stdout, "    no file changes detected after unpack")
                        .map_err(AppError::Output)?;
                }
            }
            Err(error) => {
                writeln!(
                    stdout,
                    "  - {}: artifact processing failed: {error}",
                    processed.change.package.package_key()
                )
                .map_err(AppError::Output)?;
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeneratedReportPaths {
    package_key: String,
    json_path: PathBuf,
    markdown_path: PathBuf,
}

fn write_reports_for_processed_changes(
    state_layout: &StateLayout,
    artifact_processing: &[ProcessedChangeResult],
    review_backend: &ReviewBackend,
) -> Result<Vec<GeneratedReportPaths>, ReportError> {
    let json_writer = JsonReportWriter::new(state_layout);
    let markdown_writer = MarkdownReportWriter::new(state_layout);
    let mut report_paths = Vec::new();

    for processed in artifact_processing {
        let Ok(result) = &processed.result else {
            continue;
        };

        let review_input = review_input_for_processed_change(result);
        let review_decision = review_backend.review_fail_closed(&review_input);
        let input = JsonReportInput {
            status: &review_decision.status,
            ecosystem: result.current_package.ecosystem,
            package: &result.current_package.package,
            old_version: &result.previous_package.version,
            new_version: &result.current_package.version,
            diff: &result.analysis.diff,
            signals: &result.analysis.signal_analysis.signals,
            manifest_diff: result
                .analysis
                .manifest_diff
                .as_ref()
                .map(|value| value.diff.clone()),
            interesting_files: &result.analysis.signal_analysis.interesting_files,
            review: &review_decision.output,
        };
        let json_path = json_writer.write_analysis(input.clone())?;
        let markdown_path = markdown_writer.write_analysis(input)?;
        report_paths.push(GeneratedReportPaths {
            package_key: result.current_package.package_key(),
            json_path,
            markdown_path,
        });
    }

    Ok(report_paths)
}

fn review_input_for_processed_change(
    result: &artifact_pipeline::ProcessedVersionChange,
) -> ReviewInput {
    ReviewInput::from_analysis(
        ReviewInputAnalysis {
            ecosystem: result.current_package.ecosystem.as_str().to_string(),
            package: result.current_package.package.clone(),
            old_version: result.previous_package.version.clone(),
            new_version: result.current_package.version.clone(),
            manifest_diff: result
                .analysis
                .manifest_diff
                .as_ref()
                .map(|value| value.diff.clone()),
            interesting_files: result.analysis.signal_analysis.interesting_files.clone(),
        },
        &result.analysis.diff,
        &result.analysis.signal_analysis.signals,
    )
}

fn print_generated_reports_summary<W>(
    stdout: &mut W,
    report_paths: &[GeneratedReportPaths],
) -> Result<(), AppError>
where
    W: Write,
{
    if report_paths.is_empty() {
        return Ok(());
    }

    writeln!(stdout, "Reports:").map_err(AppError::Output)?;
    for report in report_paths {
        writeln!(
            stdout,
            "  - {}: {} | {}",
            report.package_key,
            report.json_path.display(),
            report.markdown_path.display()
        )
        .map_err(AppError::Output)?;
    }

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
    ReviewBackend(ReviewBackendError),
    Report(ReportError),
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
            Self::ReviewBackend(error) => write!(f, "{error}"),
            Self::Report(error) => write!(f, "{error}"),
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
            Self::ReviewBackend(error) => Some(error),
            Self::Report(error) => Some(error),
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
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::{Builder, Header};

    use crate::artifact_pipeline::{
        ArtifactPipelineError, ProcessedChangeResult, ProcessedVersionAnalysis,
        ProcessedVersionChange,
    };
    use crate::diff::DiffSummary;
    use crate::inventory::InventorySummary;
    use crate::registry::crates::CratesRegistry;
    use crate::registry::{
        DownloadedArtifact, Ecosystem, PackageCoordinate, PackageVersion, Registry, RegistryError,
        RegistryLookupResult, RegistryPipeline,
    };
    use crate::signals::{Signal, SignalAnalysis};
    use crate::state::VersionChange;

    use super::{
        execute_check_with_lookup, execute_check_with_processing, parse_args,
        review_input_for_processed_change, CheckOutcome, CliCommand, ExitCodePolicy,
    };

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
    fn checks_workspace_crates_dependency_through_lookup_fetch_unpack_and_diff() {
        const WORKSPACE_CRATE_DEPENDENCY: &str = "reqwest";
        assert!(
            include_str!("../Cargo.toml").contains("\nreqwest ="),
            "expected {WORKSPACE_CRATE_DEPENDENCY} to remain a workspace crates dependency"
        );

        let fixture = TestFixture::new("workspace-crates-e2e");
        fixture.write_config("crates:\n  - reqwest\nreview:\n  provider: none\n");
        fixture.write_seen("{\n  \"packages\": {\n    \"crates:reqwest\": \"0.11.26\"\n  }\n}\n");

        let old_crate = crate_archive_bytes(&[
            ArchiveFile::new(
                "reqwest/Cargo.toml",
                b"[package]\nname = \"reqwest\"\nversion = \"0.11.26\"\n",
            ),
            ArchiveFile::new(
                "reqwest/src/client.rs",
                b"pub fn client() {\n    println!(\"old\");\n}\n",
            ),
            ArchiveFile::new("reqwest/README.md", b"old readme\n"),
        ])
        .expect("old reqwest crate should be created");
        let new_crate = crate_archive_bytes(&[
            ArchiveFile::new(
                "reqwest/Cargo.toml",
                b"[package]\nname = \"reqwest\"\nversion = \"0.12.13\"\n",
            ),
            ArchiveFile::new(
                "reqwest/src/client.rs",
                b"pub fn client() {\n    println!(\"new\");\n}\n",
            ),
            ArchiveFile::new("reqwest/src/blocking.rs", b"pub fn blocking() {}\n"),
        ])
        .expect("new reqwest crate should be created");
        let old_size = old_crate.len() as u64;
        let new_size = new_crate.len() as u64;

        let server = RequestSequenceServer::start(vec![
            ResponseSpec::json_get(
                200,
                "/api/v1/crates/reqwest",
                r#"{"crate":{"max_stable_version":"0.12.13","newest_version":"0.12.13"}}"#,
            ),
            ResponseSpec::head(
                200,
                "/api/v1/crates/reqwest/0.11.26/download",
                Some(old_size),
            ),
            ResponseSpec::redirect(
                "/api/v1/crates/reqwest/0.11.26/download",
                "/files/reqwest-0.11.26.crate",
            ),
            ResponseSpec::get(200, "/files/reqwest-0.11.26.crate", old_crate),
            ResponseSpec::head(
                200,
                "/api/v1/crates/reqwest/0.12.13/download",
                Some(new_size),
            ),
            ResponseSpec::redirect(
                "/api/v1/crates/reqwest/0.12.13/download",
                "/files/reqwest-0.12.13.crate",
            ),
            ResponseSpec::get(200, "/files/reqwest-0.12.13.crate", new_crate),
        ]);
        let crates =
            CratesRegistry::with_base_urls(server.metadata_base_url(), server.download_base_url());
        let npm = NoopRegistry::new(Ecosystem::Npm);
        let rubygems = NoopRegistry::new(Ecosystem::Rubygems);
        let pypi = NoopRegistry::new(Ecosystem::Pypi);
        let pipeline = RegistryPipeline::new(&npm, &rubygems, &pypi, &crates);

        let mut stdout = Vec::new();
        let outcome = execute_check_with_processing(
            fixture.config_path(),
            &mut stdout,
            |config| pipeline.lookup_latest_versions(config),
            |changes, state_layout| {
                pipeline.process_version_changes_in_state_layout(changes, state_layout)
            },
        )
        .expect("workspace crates e2e run should succeed");

        assert_eq!(outcome.exit_code(), std::process::ExitCode::SUCCESS);

        let output = String::from_utf8(stdout).expect("stdout should be utf8");
        assert!(output.contains("Detected 1 changed, 0 unchanged, and 0 newly tracked package(s)."));
        assert!(output.contains("Changed:"));
        assert!(output.contains("crates:reqwest: 0.11.26 -> 0.12.13"));
        assert!(output.contains("Artifact processing:"));
        assert!(output.contains("crates:reqwest: diff 1 added, 1 removed, 2 changed"));
        assert!(output.contains("added: reqwest/src/blocking.rs"));
        assert!(output.contains("removed: reqwest/README.md"));
        assert!(output.contains("modified: reqwest/Cargo.toml, reqwest/src/client.rs"));

        let unpacked_root = fixture
            .root_path()
            .join(".pincushion/unpacked/crates/reqwest/0.12.13/reqwest");
        assert_eq!(
            fs::read_to_string(unpacked_root.join("src/client.rs"))
                .expect("new reqwest client source should exist"),
            "pub fn client() {\n    println!(\"new\");\n}\n"
        );
        assert!(unpacked_root.join("src/blocking.rs").exists());

        assert_eq!(
            server.request_log(),
            vec![
                "GET /api/v1/crates/reqwest".to_string(),
                "HEAD /api/v1/crates/reqwest/0.11.26/download".to_string(),
                "GET /api/v1/crates/reqwest/0.11.26/download".to_string(),
                "GET /files/reqwest-0.11.26.crate".to_string(),
                "HEAD /api/v1/crates/reqwest/0.12.13/download".to_string(),
                "GET /api/v1/crates/reqwest/0.12.13/download".to_string(),
                "GET /files/reqwest-0.12.13.crate".to_string(),
            ]
        );
    }

    #[test]
    fn reports_artifact_processing_results_and_diff_summary_for_changed_packages() {
        let fixture = TestFixture::new("artifact-summary");
        fixture.write_config("npm:\n  - react\ncrates:\n  - clap\nreview:\n  provider: none\n");
        fixture.write_seen(
            "{\n  \"packages\": {\n    \"npm:react\": \"19.0.0\",\n    \"crates:clap\": \"4.5.30\"\n  }\n}\n",
        );

        let mut stdout = Vec::new();
        let outcome = execute_check_with_processing(
            fixture.config_path(),
            &mut stdout,
            |_config| {
                vec![
                    lookup_success(Ecosystem::Npm, "react", "19.1.0"),
                    lookup_success(Ecosystem::Crates, "clap", "4.5.31"),
                ]
            },
            |changes, _state_layout| {
                assert_eq!(changes.len(), 2);
                vec![
                    processed_success(
                        &changes[0],
                        DiffSummary {
                            files_added: 1,
                            files_removed: 1,
                            files_changed: 2,
                            changed_paths: vec![
                                "dist/index.js".to_string(),
                                "README.md".to_string(),
                                "package.json".to_string(),
                                "src/index.js".to_string(),
                            ],
                            added_paths: vec!["dist/index.js".to_string()],
                            removed_paths: vec!["README.md".to_string()],
                            modified_paths: vec![
                                "package.json".to_string(),
                                "src/index.js".to_string(),
                            ],
                        },
                    ),
                    processed_failure(
                        &changes[1],
                        ArtifactPipelineError::Download {
                            package: PackageVersion {
                                ecosystem: Ecosystem::Crates,
                                package: "clap".to_string(),
                                version: "4.5.30".to_string(),
                            },
                            source: Box::new(RegistryError::placeholder(
                                Ecosystem::Crates,
                                "download_artifact",
                            )),
                        },
                    ),
                ]
            },
        )
        .expect("artifact summary run should succeed");

        assert_eq!(outcome.exit_code(), std::process::ExitCode::SUCCESS);

        let output = String::from_utf8(stdout).expect("stdout should be utf8");
        assert!(output.contains("Changed:"));
        assert!(output.contains("Artifact processing:"));
        assert!(output.contains("npm:react: diff 1 added, 1 removed, 2 changed"));
        assert!(output.contains("added: dist/index.js"));
        assert!(output.contains("removed: README.md"));
        assert!(output.contains("modified: package.json, src/index.js"));
        assert!(output.contains("crates:clap: artifact processing failed:"));
        assert!(output
            .contains("crates registry placeholder: download_artifact is not implemented yet"));
    }

    #[test]
    fn writes_reports_with_real_signal_analysis_for_successful_processed_changes() {
        let fixture = TestFixture::new("signal-report");
        fixture.write_config("npm:\n  - react\nreview:\n  provider: none\n");
        fixture.write_seen("{\n  \"packages\": {\n    \"npm:react\": \"19.0.0\"\n  }\n}\n");

        let mut stdout = Vec::new();
        execute_check_with_processing(
            fixture.config_path(),
            &mut stdout,
            |_config| vec![lookup_success(Ecosystem::Npm, "react", "19.1.0")],
            |changes, _state_layout| {
                vec![processed_success_with_signals(
                    &changes[0],
                    DiffSummary {
                        files_added: 1,
                        files_removed: 0,
                        files_changed: 1,
                        changed_paths: vec![
                            "package.json".to_string(),
                            "postinstall.js".to_string(),
                        ],
                        added_paths: vec!["postinstall.js".to_string()],
                        removed_paths: Vec::new(),
                        modified_paths: vec!["package.json".to_string()],
                    },
                    SignalAnalysis {
                        signals: vec![Signal::InstallScriptAdded],
                        interesting_files: Vec::new(),
                    },
                )]
            },
        )
        .expect("signal report run should succeed");

        let output = String::from_utf8(stdout).expect("stdout should be utf8");
        assert!(output.contains("Reports:"));

        let json_report = fixture
            .root_path()
            .join(".pincushion/reports/npm/react/19.0.0_to_19.1.0.json");
        let markdown_report = fixture
            .root_path()
            .join(".pincushion/reports/npm/react/19.0.0_to_19.1.0.md");
        let json_contents =
            fs::read_to_string(&json_report).expect("json report should be written for signals");
        let markdown_contents = fs::read_to_string(&markdown_report)
            .expect("markdown report should be written for signals");

        assert!(json_contents.contains("install-script-added"));
        assert!(json_contents.contains("postinstall.js"));
        assert!(markdown_contents.contains("install-script-added"));
        assert!(markdown_contents.contains("postinstall.js"));
        assert!(json_contents
            .contains("review backend is disabled (provider=none); manual review required"));
    }

    #[test]
    fn builds_review_input_from_real_processed_change_analysis() {
        let change = version_change(Ecosystem::Npm, "react", "19.0.0", "19.1.0");
        let processed = processed_success_with_signals(
            &change,
            DiffSummary {
                files_added: 1,
                files_removed: 2,
                files_changed: 3,
                changed_paths: vec!["package.json".to_string()],
                added_paths: vec!["postinstall.js".to_string()],
                removed_paths: vec!["README.md".to_string(), "docs.md".to_string()],
                modified_paths: vec![
                    "package.json".to_string(),
                    "src/index.js".to_string(),
                    "src/cli.js".to_string(),
                ],
            },
            SignalAnalysis {
                signals: vec![Signal::InstallScriptAdded],
                interesting_files: vec![crate::diff::SuspiciousExcerpt {
                    path: "postinstall.js".to_string(),
                    reason: "new install script".to_string(),
                    excerpt: "node postinstall.js".to_string(),
                }],
            },
        );
        let result = processed.result.expect("processed change should succeed");

        let review_input = review_input_for_processed_change(&result);

        assert_eq!(review_input.ecosystem, "npm");
        assert_eq!(review_input.package, "react");
        assert_eq!(review_input.old_version, "19.0.0");
        assert_eq!(review_input.new_version, "19.1.0");
        assert_eq!(review_input.summary.files_added, 1);
        assert_eq!(review_input.summary.files_removed, 2);
        assert_eq!(review_input.summary.files_changed, 3);
        assert_eq!(review_input.summary.signals, vec!["install-script-added"]);
        assert_eq!(review_input.interesting_files.len(), 1);
        assert_eq!(review_input.interesting_files[0].path, "postinstall.js");
    }

    #[test]
    fn fail_closed_reviewer_writes_human_review_required_and_suspicious_report() {
        let fixture = TestFixture::new("review-fail-closed");
        fixture.write_config("npm:\n  - react\nreview:\n  provider: codex\n");
        fixture.write_seen("{\n  \"packages\": {\n    \"npm:react\": \"19.0.0\"\n  }\n}\n");
        fixture.write_executable("codex", "#!/bin/sh\necho reviewer boom >&2\nexit 23\n");

        let _path_guard = ScopedPathOverride::prepend(fixture.root_path());
        let mut stdout = Vec::new();
        execute_check_with_processing(
            fixture.config_path(),
            &mut stdout,
            |_config| vec![lookup_success(Ecosystem::Npm, "react", "19.1.0")],
            |changes, _state_layout| {
                vec![processed_success_with_signals(
                    &changes[0],
                    DiffSummary {
                        files_added: 1,
                        files_removed: 0,
                        files_changed: 1,
                        changed_paths: vec![
                            "package.json".to_string(),
                            "postinstall.js".to_string(),
                        ],
                        added_paths: vec!["postinstall.js".to_string()],
                        removed_paths: Vec::new(),
                        modified_paths: vec!["package.json".to_string()],
                    },
                    SignalAnalysis {
                        signals: vec![Signal::InstallScriptAdded],
                        interesting_files: vec![crate::diff::SuspiciousExcerpt {
                            path: "postinstall.js".to_string(),
                            reason: "new install script".to_string(),
                            excerpt: "node postinstall.js".to_string(),
                        }],
                    },
                )]
            },
        )
        .expect("fail-closed review run should still complete");

        let json_report = fixture
            .root_path()
            .join(".pincushion/reports/npm/react/19.0.0_to_19.1.0.json");
        let json_contents =
            fs::read_to_string(&json_report).expect("json report should be written");

        assert!(json_contents.contains("human-review-required"));
        assert!(json_contents.contains("\"verdict\": \"suspicious\""));
        assert!(json_contents.contains("reviewer boom"));
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

    fn version_change(
        ecosystem: Ecosystem,
        package: &str,
        previous_version: &str,
        current_version: &str,
    ) -> VersionChange {
        VersionChange {
            package: PackageVersion {
                ecosystem,
                package: package.to_string(),
                version: current_version.to_string(),
            },
            previous_version: previous_version.to_string(),
        }
    }

    fn processed_success(change: &VersionChange, diff: DiffSummary) -> ProcessedChangeResult {
        processed_success_with_signals(change, diff, SignalAnalysis::default())
    }

    fn processed_success_with_signals(
        change: &VersionChange,
        diff: DiffSummary,
        signal_analysis: SignalAnalysis,
    ) -> ProcessedChangeResult {
        ProcessedChangeResult {
            change: change.clone(),
            result: Ok(ProcessedVersionChange {
                previous_package: PackageVersion {
                    ecosystem: change.package.ecosystem,
                    package: change.package.package.clone(),
                    version: change.previous_version.clone(),
                },
                current_package: change.package.clone(),
                previous_artifact: DownloadedArtifact {
                    source_url: Some("https://example.test/old".to_string()),
                    path: PathBuf::from("/tmp/old-artifact"),
                },
                current_artifact: DownloadedArtifact {
                    source_url: Some("https://example.test/new".to_string()),
                    path: PathBuf::from("/tmp/new-artifact"),
                },
                previous_root: PathBuf::from("/tmp/old-unpacked"),
                current_root: PathBuf::from("/tmp/new-unpacked"),
                previous_inventory: InventorySummary::default(),
                current_inventory: InventorySummary::default(),
                analysis: ProcessedVersionAnalysis {
                    diff,
                    manifest_diff: None,
                    signal_analysis,
                },
            }),
        }
    }

    fn processed_failure(
        change: &VersionChange,
        error: ArtifactPipelineError,
    ) -> ProcessedChangeResult {
        ProcessedChangeResult {
            change: change.clone(),
            result: Err(error),
        }
    }

    #[derive(Debug, Clone)]
    struct ResponseSpec {
        status_code: u16,
        method: String,
        path: String,
        content_type: &'static str,
        body: Vec<u8>,
        content_length: Option<u64>,
        extra_headers: Vec<(String, String)>,
    }

    impl ResponseSpec {
        fn get(status_code: u16, path: &str, body: impl AsRef<[u8]>) -> Self {
            Self {
                status_code,
                method: "GET".to_string(),
                path: path.to_string(),
                content_type: "application/octet-stream",
                body: body.as_ref().to_vec(),
                content_length: None,
                extra_headers: Vec::new(),
            }
        }

        fn json_get(status_code: u16, path: &str, body: &str) -> Self {
            Self {
                status_code,
                method: "GET".to_string(),
                path: path.to_string(),
                content_type: "application/json",
                body: body.as_bytes().to_vec(),
                content_length: None,
                extra_headers: Vec::new(),
            }
        }

        fn redirect(path: &str, location: &str) -> Self {
            Self {
                status_code: 302,
                method: "GET".to_string(),
                path: path.to_string(),
                content_type: "text/plain",
                body: Vec::new(),
                content_length: Some(0),
                extra_headers: vec![("Location".to_string(), location.to_string())],
            }
        }

        fn head(status_code: u16, path: &str, content_length: Option<u64>) -> Self {
            Self {
                status_code,
                method: "HEAD".to_string(),
                path: path.to_string(),
                content_type: "application/octet-stream",
                body: Vec::new(),
                content_length,
                extra_headers: Vec::new(),
            }
        }
    }

    struct RequestSequenceServer {
        root_url: String,
        request_log: Arc<Mutex<Vec<String>>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl RequestSequenceServer {
        fn start(responses: Vec<ResponseSpec>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("test server should bind");
            let address = listener.local_addr().expect("local addr should resolve");
            let root_url = format!("http://{}", address);
            let request_log = Arc::new(Mutex::new(Vec::new()));
            let request_log_for_thread = request_log.clone();

            let thread = thread::spawn(move || {
                for response_spec in responses {
                    let (mut stream, _) = listener.accept().expect("request should arrive");
                    let mut buffer = [0_u8; 4096];
                    let read = stream
                        .read(&mut buffer)
                        .expect("request should be readable");
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let mut request_line_parts =
                        request.lines().next().unwrap_or("").split_whitespace();
                    let method = request_line_parts.next().unwrap_or("");
                    let path = request_line_parts.next().unwrap_or("");
                    request_log_for_thread
                        .lock()
                        .expect("request log lock should succeed")
                        .push(format!("{method} {path}"));
                    assert_eq!(method, response_spec.method, "unexpected request method");
                    assert_eq!(path, response_spec.path, "unexpected request path");

                    let mut response = format!(
                        "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nConnection: close\r\n",
                        response_spec.status_code, response_spec.content_type
                    );
                    if let Some(content_length) = response_spec.content_length {
                        response.push_str(&format!("Content-Length: {content_length}\r\n"));
                    }
                    if response_spec.method != "HEAD" && response_spec.content_length.is_none() {
                        response
                            .push_str(&format!("Content-Length: {}\r\n", response_spec.body.len()));
                    }
                    for (name, value) in &response_spec.extra_headers {
                        response.push_str(&format!("{name}: {value}\r\n"));
                    }
                    response.push_str("\r\n");
                    let mut response_bytes = response.into_bytes();
                    if response_spec.method != "HEAD" {
                        response_bytes.extend_from_slice(&response_spec.body);
                    }
                    stream
                        .write_all(&response_bytes)
                        .expect("response should be written");
                }
            });

            Self {
                root_url,
                request_log,
                thread: Some(thread),
            }
        }

        fn metadata_base_url(&self) -> String {
            format!("{}/api/v1/crates", self.root_url)
        }

        fn download_base_url(&self) -> String {
            format!("{}/api/v1/crates", self.root_url)
        }

        fn request_log(mut self) -> Vec<String> {
            if let Some(thread) = self.thread.take() {
                thread.join().expect("server thread should finish");
            }
            self.request_log
                .lock()
                .expect("request log lock should succeed")
                .clone()
        }
    }

    struct ArchiveFile<'a> {
        path: &'a str,
        contents: &'a [u8],
    }

    impl<'a> ArchiveFile<'a> {
        fn new(path: &'a str, contents: &'a [u8]) -> Self {
            Self { path, contents }
        }
    }

    fn crate_archive_bytes(files: &[ArchiveFile<'_>]) -> std::io::Result<Vec<u8>> {
        let cursor = Cursor::new(Vec::new());
        let encoder = GzEncoder::new(cursor, Compression::default());
        let mut builder = Builder::new(encoder);

        for file in files {
            let mut header = Header::new_gnu();
            header.set_path(file.path)?;
            header.set_mode(0o644);
            header.set_size(file.contents.len() as u64);
            header.set_cksum();
            builder.append(&header, Cursor::new(file.contents))?;
        }

        let encoder = builder.into_inner()?;
        let cursor = encoder.finish()?;
        Ok(cursor.into_inner())
    }

    #[derive(Debug, Clone, Copy)]
    struct NoopRegistry {
        ecosystem: Ecosystem,
    }

    impl NoopRegistry {
        fn new(ecosystem: Ecosystem) -> Self {
            Self { ecosystem }
        }
    }

    impl Registry for NoopRegistry {
        fn ecosystem(&self) -> Ecosystem {
            self.ecosystem
        }

        fn latest_version(&self, package: &str) -> Result<PackageVersion, RegistryError> {
            Err(RegistryError::new(format!(
                "unexpected latest_version lookup for {}:{}",
                self.ecosystem.as_str(),
                package
            )))
        }

        fn download_artifact(
            &self,
            package: &PackageVersion,
            _destination: &Path,
        ) -> Result<DownloadedArtifact, RegistryError> {
            Err(RegistryError::new(format!(
                "unexpected download for {}",
                package.package_key()
            )))
        }

        fn unpack(&self, artifact: &Path, _destination: &Path) -> Result<(), RegistryError> {
            Err(RegistryError::new(format!(
                "unexpected unpack for {}",
                artifact.display()
            )))
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

        fn root_path(&self) -> &Path {
            &self.root
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

        fn write_executable(&self, name: &str, contents: &str) {
            let path = self.root.join(name);
            fs::write(&path, contents).expect("executable should be written");
            let mut permissions = fs::metadata(&path)
                .expect("executable metadata should be readable")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("executable permissions should update");
        }
    }

    struct ScopedPathOverride {
        original_path: Option<std::ffi::OsString>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl ScopedPathOverride {
        fn prepend(path: &Path) -> Self {
            static PATH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let guard = PATH_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .expect("path lock should succeed");
            let original_path = env::var_os("PATH");
            let mut combined = std::ffi::OsString::from(path.as_os_str());
            if let Some(original) = &original_path {
                combined.push(":");
                combined.push(original);
            }
            // SAFETY: tests serialize PATH mutation with a global mutex and restore it on drop.
            unsafe { env::set_var("PATH", combined) };

            Self {
                original_path,
                _guard: guard,
            }
        }
    }

    impl Drop for ScopedPathOverride {
        fn drop(&mut self) {
            match &self.original_path {
                Some(value) => {
                    // SAFETY: paired with the serialized PATH override in `prepend`.
                    unsafe { env::set_var("PATH", value) };
                }
                None => {
                    // SAFETY: paired with the serialized PATH override in `prepend`.
                    unsafe { env::remove_var("PATH") };
                }
            }
        }
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
