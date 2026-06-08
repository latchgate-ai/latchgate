//! Build script — git metadata.
//!
//! Sets cargo environment variables:
//!   - `GIT_SHA`     — short commit hash (or "unknown" outside a repo)
//!   - `BUILD_DATE`  — UTC date in YYYY-MM-DD format

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let sha = run("git", &["rev-parse", "--short=8", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let date = run("date", &["-u", "+%Y-%m-%d"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=GIT_SHA={sha}");
    println!("cargo:rustc-env=BUILD_DATE={date}");
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}
