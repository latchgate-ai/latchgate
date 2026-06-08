//! `latchgate completions` — shell completion script generation.
//!
//! Delegates to `clap_complete` for Bash, Zsh, Fish, and PowerShell.
//! Output is written to stdout so the operator can redirect to the
//! appropriate completions directory for their shell.
//!
//! # Examples
//!
//! ```bash
//! latchgate completions bash > ~/.local/share/bash-completion/completions/latchgate
//! latchgate completions zsh  > ~/.zfunc/_latchgate
//! latchgate completions fish > ~/.config/fish/completions/latchgate.fish
//! ```

use clap::CommandFactory;
use clap_complete::Shell;

use crate::output::Printer;

/// Generate shell completion scripts and write to stdout.
pub fn run(shell: Shell, pr: &Printer) -> i32 {
    let mut cmd = crate::Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());

    // Hint the install location (stderr, so it doesn't pollute the output).
    if !pr.json {
        let hint = match shell {
            Shell::Bash => {
                "# Install: latchgate completions bash \
                 > ~/.local/share/bash-completion/completions/latchgate"
            }
            Shell::Zsh => {
                "# Install: latchgate completions zsh > ~/.zfunc/_latchgate && \
                 compinit"
            }
            Shell::Fish => {
                "# Install: latchgate completions fish \
                 > ~/.config/fish/completions/latchgate.fish"
            }
            Shell::PowerShell => "# Install: latchgate completions powershell >> $PROFILE",
            _ => "",
        };
        if !hint.is_empty() {
            eprintln!("{hint}");
        }
    }

    0
}
