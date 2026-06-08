//! Generic host I/O backend initialisation.
//!
//! Single ispatch loop over `Config.host_io`. Adding a new backend
//! requires only a new match arm here — no changes to core, kernel,
//! or API.

use std::collections::HashMap;

use tracing::info;

use crate::wasm::WasmRuntime;
use crate::ProviderError;

/// Extract the `url` string from a `toml::Value::Table`.
///
/// Returns `None` if the value is not a table or the `url` key is missing/not
/// a string. Callers treat `None` as a configuration error.
fn extract_url(config: &toml::Value) -> Option<&str> {
    config.as_table()?.get("url")?.as_str()
}

/// Initialise all host I/O backends declared in `[host_io.*]` config sections.
///
/// Iterates over the `host_io` map and dispatches to the appropriate
/// `WasmRuntime::init_*` method based on the backend name.
///
/// SECURITY: unknown backend names are rejected with a hard error — not
/// silently ignored. A typo in the config (e.g. `[host_io.databse]`) must
/// not fail silently, causing the operator to believe a backend is active
/// when it is not.
pub async fn init_backends(
    runtime: &WasmRuntime,
    host_io: &HashMap<String, toml::Value>,
) -> Result<(), ProviderError> {
    for (name, config) in host_io {
        let url = extract_url(config).ok_or_else(|| ProviderError::ExecutionFailed {
            reason: format!(
                "host_io.{name}: missing or invalid 'url' field — \
                 expected [host_io.{name}] with url = \"...\""
            ),
        })?;

        match name.as_str() {
            "database" => {
                runtime.init_database(url).await?;
            }
            "queue" => {
                runtime.init_queue(url).await?;
            }
            "storage" => {
                runtime.init_storage(url)?;
            }
            "smtp" => {
                runtime.init_smtp(url)?;
            }
            other => {
                return Err(ProviderError::ExecutionFailed {
                    reason: format!(
                        "host_io.{other}: unknown backend — \
                         valid backends are: database, queue, storage, smtp"
                    ),
                });
            }
        }

        info!(backend = name, "host_io backend initialised");
    }

    // Log disabled backends for operational visibility.
    let known = ["database", "queue", "storage", "smtp"];
    for k in &known {
        if !host_io.contains_key(*k) {
            info!(backend = *k, "host_io backend not configured — disabled");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_url_from_valid_table() {
        let val: toml::Value = toml::from_str(r#"url = "postgres://localhost/db""#).unwrap();
        assert_eq!(extract_url(&val), Some("postgres://localhost/db"));
    }

    #[test]
    fn extract_url_missing_key_returns_none() {
        let val: toml::Value = toml::from_str(r#"host = "localhost""#).unwrap();
        assert_eq!(extract_url(&val), None);
    }

    #[test]
    fn extract_url_not_a_table_returns_none() {
        let val = toml::Value::String("postgres://localhost".into());
        assert_eq!(extract_url(&val), None);
    }

    #[test]
    fn extract_url_non_string_url_returns_none() {
        let val: toml::Value = toml::from_str("url = 42").unwrap();
        assert_eq!(extract_url(&val), None);
    }
}
