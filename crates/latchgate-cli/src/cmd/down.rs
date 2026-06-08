//! `latchgate down` — tear down containers and optionally prune data.

use std::path::Path;

use crate::output::Printer;

/// Tear down a `latchgate up` session and optionally delete the data directory.
///
/// Exit codes:
///   0 — cleaned up (or nothing to clean).
///   1 — docker compose down or prune failed.
pub fn run(pr: &Printer, prune: bool, yes: bool, data_dir: Option<&Path>) -> i32 {
    let state = super::up::state_dir();
    let compose_file = state.join(super::up::COMPOSE_FILENAME);

    if compose_file.exists() {
        super::up::cleanup(pr);
    } else if !prune {
        pr.info("No active latchgate up session found. Nothing to clean up.");
        return 0;
    }

    if prune {
        return run_prune(pr, yes, data_dir);
    }

    0
}

fn run_prune(pr: &Printer, yes: bool, data_dir: Option<&Path>) -> i32 {
    let dir = match data_dir {
        Some(d) => d.to_path_buf(),
        None => {
            pr.error("Cannot resolve data directory — no config loaded.");
            pr.hint("Pass --config or run from a directory with .latchgate/latchgate.toml.");
            return 1;
        }
    };

    if !dir.exists() {
        pr.info(&format!("Data directory does not exist: {}", dir.display()));
        return 0;
    }

    if !yes && !pr.json && !confirm_prune(pr, &dir) {
        pr.info("Aborted.");
        return 0;
    }

    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {
            pr.success(&format!("Removed {}", dir.display()));
            0
        }
        Err(e) => {
            pr.error(&format!("Failed to remove {}: {e}", dir.display()));
            1
        }
    }
}

fn confirm_prune(pr: &Printer, dir: &Path) -> bool {
    pr.blank();
    eprintln!(
        "  {}  This will permanently delete the data directory:",
        pr.warn_sym(),
    );
    eprintln!("     {}", dir.display());
    eprintln!("     The audit trail cannot be recovered.");
    pr.blank();
    eprint!(
        "  Type {} to confirm, anything else to cancel: ",
        pr.bold("yes")
    );

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    line.trim() == "yes"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_nonexistent_dir_succeeds() {
        let pr = Printer::new(true);
        let dir = std::path::Path::new("/nonexistent/latchgate/data");
        let code = run_prune(&pr, true, Some(dir));
        assert_eq!(code, 0);
    }

    #[test]
    fn prune_removes_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("audit.db"), "test").unwrap();

        let pr = Printer::new(true);
        let code = run_prune(&pr, true, Some(&data));
        assert_eq!(code, 0);
        assert!(!data.exists());
    }

    #[test]
    fn prune_without_data_dir_fails() {
        let pr = Printer::new(true);
        let code = run_prune(&pr, true, None);
        assert_eq!(code, 1);
    }
}
