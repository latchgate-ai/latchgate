//! Logging configuration: level, format, file output, and rotation.

use serde::Deserialize;

/// # TOML
///
/// ```toml
/// log_level = "info"
/// log_format = "auto"
/// log_file = "/var/log/latchgate/gate.log"
/// log_rotation = "daily"
/// log_max_files = 7
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Minimum tracing level. Default: `"info"`.
    /// Env var: `LATCHGATE_LOG_LEVEL`.
    #[serde(rename = "log_level", default = "default_level")]
    pub level: String,

    /// Output format. Default: `Auto` (pretty for TTY, JSON otherwise).
    /// Env var: `LATCHGATE_LOG_FORMAT`.
    #[serde(rename = "log_format", default)]
    pub format: LogFormat,

    /// Path to a structured JSON log file.
    ///
    /// When set, every log event is appended as a JSON line to this file
    /// (regardless of `format`). The file is created if it does not
    /// exist; the parent directory must exist.
    ///
    /// Env var: `LATCHGATE_LOG_FILE`.
    ///
    /// `latchgate up` sets this automatically to `{runtime_dir}/logs/gate.log`.
    /// `latchgate serve` defaults to `None` (stderr only).
    #[serde(rename = "log_file", default)]
    pub file: Option<String>,

    /// Log file rotation policy. Only meaningful when `file` is set.
    ///
    /// Default: `Daily`. Env var: `LATCHGATE_LOG_ROTATION`.
    #[serde(rename = "log_rotation", default = "default_rotation")]
    pub rotation: LogRotation,

    /// Maximum number of rotated log files to keep.
    ///
    /// Older files are deleted. Default: 7.
    /// Env var: `LATCHGATE_LOG_MAX_FILES`.
    #[serde(rename = "log_max_files", default = "default_max_files")]
    pub max_files: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Auto,
            file: None,
            rotation: LogRotation::Daily,
            max_files: 7,
        }
    }
}

/// Log output format.
///
/// Log output format.
///
/// `Auto` resolves at startup: `Pretty` when stderr is a TTY, `Json`
/// otherwise.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Auto,
    Json,
    Pretty,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    Daily,
    Hourly,
    /// Never rotate — single file, grows without bound.
    Never,
}

fn default_level() -> String {
    "info".to_string()
}

fn default_rotation() -> LogRotation {
    LogRotation::Daily
}

fn default_max_files() -> usize {
    7
}
