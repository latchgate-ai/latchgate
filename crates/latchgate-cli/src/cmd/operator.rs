//! `latchgate operator` — operator key management.
//!
//! Subcommands:
//!   keygen — generate a DPoP keypair for operator authentication

use std::path::PathBuf;

use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::json;

use latchgate_auth::dpop::generate_dpop_keypair;

use crate::output::{print_json, Printer};

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum OperatorCommand {
    /// Generate a DPoP keypair for operator authentication (ES256 / P-256).
    ///
    /// Writes the private key to a PEM file (mode 0600) and prints the
    /// JWK thumbprint for use in `[operator_credentials]` config.
    ///
    /// Production deployments require every operator to have a unique keypair
    /// with the thumbprint registered as `dpop_jkt` in latchgate.toml.
    Keygen {
        /// Path for the private key PEM file.
        #[arg(long, short, value_name = "PATH")]
        output: Option<PathBuf>,
    },
}

pub fn run_keygen(output: &Option<PathBuf>, pr: &Printer, json_mode: bool) -> i32 {
    let dest = output
        .clone()
        .unwrap_or_else(|| PathBuf::from("operator-key.pem"));

    if dest.exists() {
        if json_mode {
            print_json(&json!({
                "ok": false,
                "error": format!("{} already exists — will not overwrite", dest.display()),
            }));
        } else {
            pr.blank();
            pr.error(&format!(
                "{} already exists. Choose a different path with --output.",
                dest.display()
            ));
            pr.blank();
        }
        return 1;
    }

    let (signing_key, _pub_key) = match generate_dpop_keypair() {
        Ok(pair) => pair,
        Err(e) => {
            let msg = format!("key generation failed: {e}");
            if json_mode {
                print_json(&json!({ "ok": false, "error": msg }));
            } else {
                pr.error(&msg);
            }
            return 1;
        }
    };

    let thumbprint = match signing_key.thumbprint() {
        Ok(t) => t,
        Err(e) => {
            let msg = format!("thumbprint computation failed: {e}");
            if json_mode {
                print_json(&json!({ "ok": false, "error": msg }));
            } else {
                pr.error(&msg);
            }
            return 1;
        }
    };

    // Serialize to PKCS#8 PEM.
    let pem_doc = match signing_key.as_inner().to_pkcs8_pem(LineEnding::LF) {
        Ok(doc) => doc,
        Err(e) => {
            let msg = format!("PEM serialization failed: {e}");
            if json_mode {
                print_json(&json!({ "ok": false, "error": msg }));
            } else {
                pr.error(&msg);
            }
            return 1;
        }
    };

    // Write with restricted permissions.
    if let Err(e) = write_private_key(&dest, pem_doc.as_ref()) {
        let msg = format!("cannot write {}: {e}", dest.display());
        if json_mode {
            print_json(&json!({ "ok": false, "error": msg }));
        } else {
            pr.error(&msg);
        }
        return 1;
    }

    if json_mode {
        print_json(&json!({
            "ok": true,
            "private_key_path": dest.to_string_lossy(),
            "dpop_jkt": thumbprint,
        }));
        return 0;
    }

    pr.blank();
    pr.success("Operator DPoP keypair generated (ES256 / P-256)");
    pr.blank();

    println!("  {}  {}", pr.dim("Private key:"), dest.display(),);
    println!("  {}  {}", pr.dim("Thumbprint: "), pr.cyan(&thumbprint),);

    pr.blank();
    println!("  Add to latchgate.toml:");
    pr.blank();
    println!("    [operator_credentials.{}]", infer_name(&dest));
    println!("    api_key = \"{}\"", generate_api_key());
    println!("    dpop_jkt = \"{thumbprint}\"");

    pr.blank();
    println!("  Use with CLI:");
    pr.blank();
    println!("    latchgate approvals list \\",);
    println!("      --operator-key <api_key> \\",);
    println!("      --operator-private-key {}", dest.display(),);

    pr.blank();
    0
}

/// Write PEM content with 0o600 permissions on Unix.
fn write_private_key(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Infer an operator name from the filename (strip extension and common prefixes).
fn infer_name(path: &std::path::Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("operator")
        .trim_start_matches("operator-")
        .trim_start_matches("operator_")
        .to_string()
}

/// Generate a random API key (32 hex chars).
fn generate_api_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
