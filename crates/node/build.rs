#![allow(missing_docs)]

use std::{env, error::Error};

use vergen::{Build, Cargo, Emitter};
use vergen_git2::Git2;

fn main() -> Result<(), Box<dyn Error>> {
    let mut emitter = Emitter::default();

    let build_builder = Build::builder().build_timestamp(true).build();
    emitter.add_instructions(&build_builder)?;

    let cargo_builder = Cargo::builder().features(true).target_triple(true).build();
    emitter.add_instructions(&cargo_builder)?;

    let git_builder = Git2::builder()
        .describe(false, true, None)
        .dirty(true)
        .sha(false)
        .build();
    emitter.add_instructions(&git_builder)?;

    emitter.emit_and_set()?;
    let sha = env::var("VERGEN_GIT_SHA")
        .or_else(|_| env::var("SPHERE_GIT_SHA"))
        .unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=VERGEN_GIT_SHA={sha}");
    let sha_short = if sha.len() >= 7 {
        &sha[..7]
    } else {
        &sha
    };

    let is_dirty = env::var("VERGEN_GIT_DIRTY").is_ok_and(|dirty| dirty == "true");
    let not_on_tag = env::var("VERGEN_GIT_DESCRIBE")
        .map(|describe| describe.ends_with(&format!("-g{sha_short}")))
        .unwrap_or(true);
    let version_suffix = if is_dirty || not_on_tag { "-dev" } else { "" };
    println!("cargo:rustc-env=RETH_VERSION_SUFFIX={version_suffix}");

    let short_sha = if sha.len() >= 8 {
        &sha[..8]
    } else {
        &sha
    };

    // Emit the short SHA as its own env var
    println!("cargo:rustc-env=VERGEN_GIT_SHA_SHORT={}", short_sha);

    let out_dir = env::var("OUT_DIR")?;
    let profile = out_dir
        .rsplit(std::path::MAIN_SEPARATOR)
        .nth(3)
        .ok_or("build profile missing from OUT_DIR")?;
    println!("cargo:rustc-env=RETH_BUILD_PROFILE={profile}");

    let pkg_version = env!("CARGO_PKG_VERSION");
    println!("cargo:rustc-env=RETH_SHORT_VERSION={pkg_version}{version_suffix} ({sha_short})");
    println!("cargo:rustc-env=RETH_LONG_VERSION_0=Version: {pkg_version}{version_suffix}");
    println!("cargo:rustc-env=RETH_LONG_VERSION_1=Commit SHA: {sha}");
    println!(
        "cargo:rustc-env=RETH_LONG_VERSION_2=Build Timestamp: {}",
        env::var("VERGEN_BUILD_TIMESTAMP")?
    );
    println!(
        "cargo:rustc-env=RETH_LONG_VERSION_3=Build Features: {}",
        env::var("VERGEN_CARGO_FEATURES")?
    );
    println!("cargo:rustc-env=RETH_LONG_VERSION_4=Build Profile: {profile}");
    println!(
        "cargo:rustc-env=RETH_P2P_CLIENT_VERSION={}",
        format_args!(
            "arc-sphere/v{pkg_version}-{sha_short}/{}",
            env::var("VERGEN_CARGO_TARGET_TRIPLE")?
        )
    );

    Ok(())
}
