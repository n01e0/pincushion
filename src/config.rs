use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchlistConfig {
    pub npm: Vec<String>,
    pub rubygems: Vec<String>,
    pub pypi: Vec<String>,
    pub crates: Vec<String>,
    pub review: ReviewConfig,
}

impl WatchlistConfig {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        Self::from_yaml_str(&contents)
    }

    pub fn from_yaml_str(input: &str) -> Result<Self, ConfigError> {
        let raw: RawWatchlistConfig = serde_yaml::from_str(input).map_err(ConfigError::Parse)?;
        let config = Self {
            npm: normalize_packages(raw.npm),
            rubygems: normalize_packages(raw.rubygems),
            pypi: normalize_packages(raw.pypi),
            crates: normalize_packages(raw.crates),
            review: ReviewConfig {
                provider: raw.review.provider,
            },
        };

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        validate_package_list("npm", &self.npm, &mut errors);
        validate_package_list("rubygems", &self.rubygems, &mut errors);
        validate_package_list("pypi", &self.pypi, &mut errors);
        validate_package_list("crates", &self.crates, &mut errors);

        let total_packages =
            self.npm.len() + self.rubygems.len() + self.pypi.len() + self.crates.len();
        if total_packages == 0 {
            errors.push(String::from(
                "watchlist must include at least one package across npm, rubygems, pypi, or crates",
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Validation(errors))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReviewConfig {
    pub provider: ReviewProvider,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewProvider {
    #[default]
    None,
    Codex,
    ClaudeCode,
}

#[derive(Debug)]
pub enum ConfigError {
    Io { path: PathBuf, source: io::Error },
    Parse(serde_yaml::Error),
    Validation(Vec<String>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read config {}: {source}", path.display())
            }
            Self::Parse(source) => write!(f, "failed to parse watchlist yaml: {source}"),
            Self::Validation(errors) => {
                write!(f, "invalid watchlist config: {}", errors.join("; "))
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::Validation(_) => None,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawWatchlistConfig {
    #[serde(default)]
    npm: Vec<String>,
    #[serde(default)]
    rubygems: Vec<String>,
    #[serde(default)]
    pypi: Vec<String>,
    #[serde(default)]
    crates: Vec<String>,
    #[serde(default)]
    review: RawReviewConfig,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawReviewConfig {
    #[serde(default)]
    provider: ReviewProvider,
}

fn normalize_packages(packages: Vec<String>) -> Vec<String> {
    packages
        .into_iter()
        .map(|package| package.trim().to_string())
        .collect()
}

fn validate_package_list(ecosystem: &str, packages: &[String], errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();

    for package in packages {
        if package.is_empty() {
            errors.push(format!("{ecosystem} package names must not be empty"));
            continue;
        }

        if package.chars().any(char::is_whitespace) {
            errors.push(format!(
                "{ecosystem} package `{package}` must not contain whitespace"
            ));
        }

        if !seen.insert(package.clone()) {
            errors.push(format!(
                "{ecosystem} package `{package}` is listed more than once"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{ConfigError, ReviewProvider, WatchlistConfig};

    #[test]
    fn parses_minimal_watchlist_schema() {
        let config = WatchlistConfig::from_yaml_str(
            r#"
            npm:
              - react
              - axios
            rubygems:
              - rails
            pypi:
              - requests
            crates:
              - clap
            review:
              provider: claude-code
            "#,
        )
        .expect("config should parse");

        assert_eq!(config.npm, vec!["react", "axios"]);
        assert_eq!(config.rubygems, vec!["rails"]);
        assert_eq!(config.pypi, vec!["requests"]);
        assert_eq!(config.crates, vec!["clap"]);
        assert_eq!(config.review.provider, ReviewProvider::ClaudeCode);
    }

    #[test]
    fn review_provider_defaults_to_none() {
        let config = WatchlistConfig::from_yaml_str(
            r#"
            npm:
              - react
            "#,
        )
        .expect("config should parse");

        assert_eq!(config.review.provider, ReviewProvider::None);
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = WatchlistConfig::from_yaml_str(
            r#"
            npm:
              - react
            unknown:
              - nope
            "#,
        )
        .expect_err("unknown keys should be rejected");

        assert!(matches!(error, ConfigError::Parse(_)));
        assert!(error.to_string().contains("unknown field `unknown`"));
    }

    #[test]
    fn rejects_invalid_package_lists() {
        let error = WatchlistConfig::from_yaml_str(
            r#"
            npm:
              - react
              - "  "
              - react
            pypi:
              - has spaces
            "#,
        )
        .expect_err("invalid package names should fail validation");

        assert!(matches!(error, ConfigError::Validation(_)));
        let message = error.to_string();
        assert!(message.contains("npm package names must not be empty"));
        assert!(message.contains("npm package `react` is listed more than once"));
        assert!(message.contains("pypi package `has spaces` must not contain whitespace"));
    }

    #[test]
    fn rejects_empty_watchlist() {
        let error = WatchlistConfig::from_yaml_str("review:\n  provider: none\n")
            .expect_err("empty watchlist should fail validation");

        assert!(matches!(error, ConfigError::Validation(_)));
        assert!(error
            .to_string()
            .contains("watchlist must include at least one package"));
    }

    #[test]
    fn loads_config_from_path() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let path = env::temp_dir().join(format!("pincushion-watchlist-{unique}.yaml"));

        fs::write(&path, "npm:\n  - react\nreview:\n  provider: codex\n")
            .expect("config file should be written");

        let config = WatchlistConfig::load_from_path(&path).expect("config should load from disk");
        fs::remove_file(&path).expect("temp config should be removed");

        assert_eq!(config.npm, vec!["react"]);
        assert_eq!(config.review.provider, ReviewProvider::Codex);
    }
}
