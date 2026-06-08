//! Key-file I/O: permission checking and Ed25519 seed loading.
//!
//! SECURITY: fail-closed on all error paths. A key file with loose
//! permissions or wrong length is rejected at load time.

/// Check whether a key file has permissions wider than owner-only (0o600).
///
/// Returns `Ok(())` if permissions are acceptable (0o600 or stricter).
/// Returns `Err` if wider than expected or if metadata cannot be read.
///
/// SECURITY: fail-closed. A key with group/world-readable permissions is
/// rejected at load time — the process must not start with an exposed key.
#[cfg(unix)]
#[must_use = "discarding the result skips key file permission checks"]
pub fn check_key_file_permissions(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                Err(format!(
                    "SECURITY: key file {} has mode 0o{mode:03o} — \
                     group or world readable; expected 0o600 or stricter. \
                     Fix with: chmod 600 {}",
                    path.display(),
                    path.display(),
                ))
            } else {
                Ok(())
            }
        }
        Err(e) => Err(format!(
            "could not check key file permissions for {}: {e}",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
#[must_use]
pub fn check_key_file_permissions(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

/// Load and validate a 32-byte Ed25519 seed from disk.
///
///
/// `key_kind` is used in error messages (e.g. "grant", "receipt").
#[must_use = "discarding the result loses the loaded key material"]
pub fn load_ed25519_seed(path: &std::path::Path, key_kind: &str) -> Result<[u8; 32], String> {
    check_key_file_permissions(path)?;

    let bytes = std::fs::read(path)
        .map_err(|e| format!("{key_kind} key load failed ({}): {e}", path.display()))?;

    if bytes.len() != 32 {
        return Err(format!(
            "{key_kind} key file {} has wrong length: expected 32 bytes, got {}",
            path.display(),
            bytes.len()
        ));
    }

    bytes.try_into().map_err(|_| {
        format!(
            "{key_kind} key file {}: seed conversion failed",
            path.display()
        )
    })
}
