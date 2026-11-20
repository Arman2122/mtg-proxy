//! Stamp semantic version, optional git commit/describe tag, and Linux target
//! triple into `mtg-proxy` at compile time (zero runtime overhead).

use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=MTG_BUILD_VERSION");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");

    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "2.0.0".to_owned());
    let target = env::var("TARGET").unwrap_or_else(|_| "linux".to_owned());

    let explicit = env::var("MTG_BUILD_VERSION")
        .ok()
        .map(|v| v.trim().trim_start_matches('v').to_owned())
        .filter(|v| !v.is_empty());

    let git_describe = git_output(&["describe", "--tags", "--always", "--dirty"]);
    let git_sha = git_output(&["rev-parse", "--short=7", "HEAD"]);

    let semver = explicit.unwrap_or_else(|| pkg_version.clone());
    let full_version = match git_sha {
        Some(sha) => {
            let dirty = git_describe
                .as_deref()
                .is_some_and(|d| d.ends_with("-dirty"));
            let suffix = if dirty { "-dirty" } else { "" };
            format!("{semver} ({target}, rev {sha}{suffix})")
        }
        None => format!("{semver} ({target})"),
    };

    println!("cargo:rustc-env=MTG_SEMVER={semver}");
    println!("cargo:rustc-env=MTG_FULL_VERSION={full_version}");
}

fn git_output(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}
