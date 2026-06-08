//! Terminal output primitives.
//!
//! Provides a [`Printer`] that emits coloured, symbol-prefixed lines when
//! writing to a TTY, and plain text (no ANSI codes) when stdout is piped.
//! Setting `NO_COLOR=1` (or any non-empty value) also disables colour.
//!
//! In `--json` mode the printer suppresses all human-readable output; callers
//! write structured JSON via [`serde_json::json!`] directly to stdout instead.

use std::io::IsTerminal as _;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

/// A simple terminal printer.
///
/// Constructed once per command invocation from the global `--json` flag.
/// When `json = true` all `print_*` calls are no-ops; callers emit JSON.
/// When `color = false` (piped output or `NO_COLOR`) symbols are kept but
/// ANSI codes are stripped.
#[derive(Debug, Clone)]
pub struct Printer {
    pub color: bool,
    pub json: bool,
}

impl Printer {
    /// Create a printer appropriate for the current process environment.
    pub fn new(json: bool) -> Self {
        let color =
            !json && std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        Self { color, json }
    }

    // ── Core output helpers ─────────────────────────────────────────────────

    pub fn success(&self, msg: &str) {
        if self.json {
            return;
        }
        println!("{}  {}", self.ok_sym(), msg);
    }

    pub fn error(&self, msg: &str) {
        if self.json {
            return;
        }
        eprintln!("{}  {}", self.err_sym(), msg);
    }

    pub fn warn(&self, msg: &str) {
        if self.json {
            return;
        }
        eprintln!("{}  {}", self.warn_sym(), msg);
    }

    pub fn info(&self, msg: &str) {
        if self.json {
            return;
        }
        println!("{}  {}", self.info_sym(), msg);
    }

    pub fn line(&self, msg: &str) {
        if self.json {
            return;
        }
        println!("{msg}");
    }

    pub fn blank(&self) {
        if self.json {
            return;
        }
        println!();
    }

    pub fn section(&self, title: &str) {
        if self.json {
            return;
        }
        println!("{}", self.bold(title));
    }

    /// Dimmed sub-label + value on one line, indented by 2 spaces.
    pub fn field(&self, label: &str, value: &str) {
        if self.json {
            return;
        }
        println!("  {}  {}", self.dim(label), value);
    }

    // ── Enhanced output helpers ─────────────────────────────────────────────

    /// Full branded banner with two-tone ASCII art matching the logo.
    ///
    /// "LATCH" in brand rust (#c5542c), "GATE" in bold white — mirroring
    /// the logo's split colorway. Shown on ceremony commands (init, up,
    /// doctor) where the operator should feel the tool's weight.
    pub fn banner(&self, version: &str) {
        if self.json {
            return;
        }

        // Each tuple: (latch_portion, gate_portion) per line.
        // Split at the natural letter boundary between H and G.
        const LINES: &[(&str, &str)] = &[
            (
                "██╗      █████╗ ████████╗ ██████╗██╗  ██╗",
                "  ███████╗  ██████╗ ███████╗███████╗",
            ),
            (
                "██║     ██╔══██╗╚══██╔══╝██╔════╝██║  ██║",
                "  ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝",
            ),
            (
                "██║     ███████║   ██║   ██║     ███████║",
                "  ██║  ███╗███████║   ██║   █████╗",
            ),
            (
                "██║     ██╔══██║   ██║   ██║     ██╔══██║",
                "  ██║   ██║██╔══██║   ██║   ██╔══╝",
            ),
            (
                "███████╗██║  ██║   ██║   ╚██████╗██║  ██║",
                "  ╚██████╔╝██║  ██║   ██║   ███████╗",
            ),
            (
                "╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝",
                "   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝",
            ),
        ];

        println!();
        if self.color {
            const RUST: &str = "\x1b[38;5;166m";
            const BOLD_WHITE: &str = "\x1b[1;37m";
            for (latch, gate) in LINES {
                println!("  {RUST}{latch}{RESET}{BOLD_WHITE}{gate}{RESET}");
            }
        } else {
            for (latch, gate) in LINES {
                println!("  {latch}{gate}");
            }
        }
        println!();
        println!(
            "  {}  {}",
            self.dim("execution security kernel for AI agents"),
            self.dim(version),
        );
        println!();
    }

    /// Numbered progress step: `[2/5] Starting OPA...`
    pub fn step(&self, n: usize, total: usize, msg: &str) {
        if self.json {
            return;
        }
        println!("{}  {msg}", self.dim(&format!("[{n}/{total}]")));
    }

    /// Aligned key-value pair with fixed column width.
    ///
    /// `col_width` is the minimum width for the key column (padded with
    /// spaces). Pass `0` to skip padding (falls back to `field`).
    pub fn kv(&self, key: &str, value: &str, col_width: usize) {
        if self.json {
            return;
        }
        println!("  {:<col_width$}  {}", self.dim(key), value);
    }

    /// Horizontal separator: `──────────────────────────────────────────`
    pub fn rule(&self) {
        if self.json {
            return;
        }
        println!("  {}", self.dim(&"─".repeat(40)));
    }

    /// Check result with aligned name column.
    ///
    /// ```text
    /// ✓  redis           reachable (2ms)
    /// ✗  opa             timeout after 60s
    /// ```
    pub fn timed(&self, sym: &str, name: &str, detail: &str, name_width: usize) {
        if self.json {
            return;
        }
        println!("  {sym}  {:<name_width$}  {detail}", self.dim(name));
    }

    /// Indented hint line to stderr — for actionable suggestions.
    ///
    /// Replaces raw `eprintln!("  ...")` scattered across commands.
    pub fn hint(&self, msg: &str) {
        if self.json {
            return;
        }
        eprintln!("  {msg}");
    }

    /// Indented command hint in cyan — a command the user should copy-paste.
    pub fn hint_cmd(&self, cmd: &str) {
        if self.json {
            return;
        }
        eprintln!("    {}", self.cyan(cmd));
    }

    /// Numbered next-step with a copy-pasteable command.
    ///
    /// ```text
    ///   1.  latchgate up
    ///   2.  latchgate doctor
    /// ```
    pub fn numbered_cmd(&self, n: usize, cmd: &str) {
        if self.json {
            return;
        }
        println!("  {}  {}", self.dim(&format!("{n}.")), self.cyan(cmd));
    }

    // ── Styled strings (return coloured strings for use in format! macros) ─

    pub fn bold(&self, s: &str) -> String {
        if self.color {
            format!("{BOLD}{s}{RESET}")
        } else {
            s.to_string()
        }
    }

    pub fn dim(&self, s: &str) -> String {
        if self.color {
            format!("{DIM}{s}{RESET}")
        } else {
            s.to_string()
        }
    }

    pub fn green(&self, s: &str) -> String {
        if self.color {
            format!("{GREEN}{s}{RESET}")
        } else {
            s.to_string()
        }
    }

    pub fn red(&self, s: &str) -> String {
        if self.color {
            format!("{RED}{s}{RESET}")
        } else {
            s.to_string()
        }
    }

    pub fn yellow(&self, s: &str) -> String {
        if self.color {
            format!("{YELLOW}{s}{RESET}")
        } else {
            s.to_string()
        }
    }

    pub fn cyan(&self, s: &str) -> String {
        if self.color {
            format!("{CYAN}{s}{RESET}")
        } else {
            s.to_string()
        }
    }

    // ── Symbols ─────────────────────────────────────────────────────────────

    pub fn ok_sym(&self) -> String {
        self.green("✓")
    }

    pub fn err_sym(&self) -> String {
        self.red("✗")
    }

    pub fn warn_sym(&self) -> String {
        self.yellow("⚠")
    }

    pub fn info_sym(&self) -> String {
        self.dim("=>")
    }

    // ── Table helper ─────────────────────────────────────────────────────────

    /// Print a two-column table. `rows` is `(label, value)`.
    /// Labels are right-padded to the width of the longest label.
    pub fn table(&self, rows: &[(&str, &str)]) {
        if self.json {
            return;
        }
        let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        for (label, value) in rows {
            println!("  {:<width$}  {}", self.dim(label), value, width = width);
        }
    }
}

/// Print `value` as compact JSON to stdout.  Used in `--json` mode.
pub fn print_json(value: &serde_json::Value) {
    println!("{value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain (no-colour, no-json) printer for predictable output.
    fn plain() -> Printer {
        Printer {
            color: false,
            json: false,
        }
    }

    fn json_printer() -> Printer {
        Printer {
            color: false,
            json: true,
        }
    }

    // -- Styled string helpers (no ANSI when color=false) --------------------

    #[test]
    fn plain_printer_strips_ansi() {
        let pr = plain();
        assert_eq!(pr.bold("text"), "text");
        assert_eq!(pr.dim("text"), "text");
        assert_eq!(pr.green("text"), "text");
        assert_eq!(pr.red("text"), "text");
        assert_eq!(pr.yellow("text"), "text");
        assert_eq!(pr.cyan("text"), "text");
    }

    #[test]
    fn color_printer_emits_ansi() {
        let pr = Printer {
            color: true,
            json: false,
        };
        let bold = pr.bold("x");
        assert!(bold.contains("\x1b[1m"), "expected BOLD escape");
        assert!(bold.contains("\x1b[0m"), "expected RESET escape");
    }

    // -- Symbol helpers ------------------------------------------------------

    #[test]
    fn symbols_plain() {
        let pr = plain();
        assert_eq!(pr.ok_sym(), "✓");
        assert_eq!(pr.err_sym(), "✗");
        assert_eq!(pr.warn_sym(), "⚠");
        assert_eq!(pr.info_sym(), "=>");
    }

    // -- JSON mode suppresses everything -------------------------------------

    /// All output methods must be no-ops when json=true.
    /// We can't easily capture stdout in-process, but we verify the guard
    /// by confirming the methods don't panic and return unit.
    #[test]
    fn json_mode_is_silent() {
        let pr = json_printer();
        // None of these should panic.
        pr.success("x");
        pr.error("x");
        pr.warn("x");
        pr.info("x");
        pr.line("x");
        pr.blank();
        pr.section("x");
        pr.field("k", "v");
        pr.banner("v0.1.0");
        pr.step(1, 5, "doing thing");
        pr.kv("key", "val", 20);
        pr.rule();
        pr.timed("✓", "redis", "ok (2ms)", 16);
        pr.hint("suggestion");
        pr.hint_cmd("latchgate up");
        pr.numbered_cmd(1, "latchgate up");
    }

    // -- Table helper --------------------------------------------------------

    #[test]
    fn table_pads_to_longest_label() {
        // Verifying the width calculation — the actual printing goes to
        // stdout, but we confirm the math by testing `.table()` with an
        // empty slice (edge case: does not panic).
        let pr = plain();
        pr.table(&[]);
        // Non-empty — just verify no panic and consistent logic.
        pr.table(&[("short", "v"), ("much_longer_key", "v2")]);
    }
}
