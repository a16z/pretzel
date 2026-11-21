//! Register the backend's private byte checks in the ordinary facade suite.
#![cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_endian = "little"
))]
#[test]
fn appendix_d_bytes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Separate target directory avoids the outer cargo test build lock. ISA
    // flags apply only to the backend unit image, as in native conformance.
    let target = std::env::temp_dir().join(format!("pretzel-spec-domains-{}", std::process::id()));
    let output = std::process::Command::new(env!("CARGO"))
        .current_dir(root)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env("RUSTFLAGS", "-C target-feature=+sha3,+dotprod")
        .env("CARGO_TARGET_DIR", &target)
        .args([
            "test",
            "--locked",
            "--release",
            "-p",
            "pretzel-4-4-core",
            "--lib",
            "spec_domains::",
            "--",
            "--test-threads=1",
            "--nocapture",
        ])
        .output()
        .expect("run backend byte conformance tests");
    let _ = std::fs::remove_dir_all(target);
    let stdout = String::from_utf8_lossy(&output.stdout);
    print!("{stdout}");
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("6 passed; 0 failed"),
        "missing conformance tests: {stdout}"
    );
    assert!(
        stdout.contains("LAMBDA_LO=0x"),
        "missing lambda lower endpoint: {stdout}"
    );
}
