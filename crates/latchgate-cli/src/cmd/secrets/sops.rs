//! SOPS + age encryption helpers.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use super::yaml::{parse_yaml_map, serialize_yaml_map};

/// Resolved paths for SOPS operations.
pub(crate) struct SopsPaths {
    pub key_file: std::path::PathBuf,
    pub secrets_file: std::path::PathBuf,
    pub pubkey: String,
}

/// Validate and resolve sops_secrets_file + sops_key_file from config.
pub(crate) fn resolve_sops_paths(cfg: &latchgate_config::Config) -> Result<SopsPaths, String> {
    let secrets_file = cfg
        .secrets
        .sops_secrets_file
        .as_deref()
        .ok_or("sops_secrets_file not configured — run 'latchgate secrets init' first")?;

    let key_file = cfg
        .secrets
        .sops_key_file
        .as_deref()
        .ok_or("sops_key_file not configured — run 'latchgate secrets init' first")?;

    let secrets_path = std::path::PathBuf::from(secrets_file);
    let key_path = std::path::PathBuf::from(key_file);

    if !secrets_path.is_file() {
        return Err(format!(
            "secrets file {} does not exist — run 'latchgate secrets init'",
            secrets_path.display()
        ));
    }
    if !key_path.is_file() {
        return Err(format!(
            "key file {} does not exist — run 'latchgate secrets init'",
            key_path.display()
        ));
    }

    let pubkey = extract_age_public_key(&key_path)?;

    Ok(SopsPaths {
        key_file: key_path,
        secrets_file: secrets_path,
        pubkey,
    })
}

/// Check that a binary is available on `$PATH`.
pub(crate) fn check_binary(name: &str, install_url: &str) -> Result<(), String> {
    match Command::new(name).arg("--version").output() {
        Ok(o) if o.status.success() => Ok(()),
        _ => Err(format!(
            "'{name}' not found on PATH — install from {install_url}"
        )),
    }
}

/// Extract the age public key from the comment line in a key file.
///
/// The format is: `# public key: age1...`
pub(crate) fn extract_age_public_key(key_path: &Path) -> Result<String, String> {
    let content = std::fs::read_to_string(key_path)
        .map_err(|e| format!("cannot read {}: {e}", key_path.display()))?;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("# public key: ") {
            let pk = rest.trim();
            if pk.starts_with("age1") {
                return Ok(pk.to_string());
            }
        }
    }

    Err(format!(
        "cannot find 'age1...' public key in {} — file may be corrupt",
        key_path.display()
    ))
}

/// Encrypt a plaintext file in-place with sops + age.
pub(crate) fn sops_encrypt_in_place(
    sops_bin: &str,
    key_file: &Path,
    pubkey: &str,
    target: &Path,
) -> Result<(), String> {
    let output = Command::new(sops_bin)
        .arg("--encrypt")
        .arg("--age")
        .arg(pubkey)
        .arg("--in-place")
        .arg(target)
        .env("SOPS_AGE_KEY_FILE", key_file)
        .output()
        .map_err(|e| format!("failed to run {sops_bin}: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("sops encrypt failed: {}", stderr.trim()));
    }

    Ok(())
}

/// Decrypt a SOPS-encrypted YAML file and parse as a flat string map.
pub(crate) fn sops_decrypt_yaml(
    sops_bin: &str,
    key_file: &Path,
    secrets_file: &Path,
) -> Result<BTreeMap<String, String>, String> {
    let output = Command::new(sops_bin)
        .arg("--decrypt")
        .arg(secrets_file)
        .env("SOPS_AGE_KEY_FILE", key_file)
        .output()
        .map_err(|e| format!("failed to run {sops_bin}: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("sops decrypt failed: {}", stderr.trim()));
    }

    let plaintext = String::from_utf8(output.stdout)
        .map_err(|_| "sops decrypted output is not valid UTF-8".to_string())?;

    parse_yaml_map(&plaintext)
}

/// Write secrets to a temp file, encrypt, and atomically replace the target.
pub(crate) fn write_and_encrypt(
    sops_bin: &str,
    key_file: &Path,
    pubkey: &str,
    secrets_file: &Path,
    secrets: &BTreeMap<String, String>,
) -> Result<(), String> {
    let yaml = serialize_yaml_map(secrets);

    let parent = secrets_file.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("cannot create temp file: {e}"))?;

    tmp.write_all(yaml.as_bytes())
        .map_err(|e| format!("cannot write temp file: {e}"))?;
    tmp.flush()
        .map_err(|e| format!("cannot flush temp file: {e}"))?;

    set_file_mode_0600(tmp.path()).map_err(|e| format!("cannot set temp file permissions: {e}"))?;

    sops_encrypt_in_place(sops_bin, key_file, pubkey, tmp.path())?;

    tmp.persist(secrets_file)
        .map_err(|e| format!("cannot replace {}: {e}", secrets_file.display()))?;

    Ok(())
}

/// Set restrictive file permissions (0600) on Unix.
pub(crate) fn set_file_mode_0600(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
