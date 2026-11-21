use std::collections::BTreeSet;

fn check_configuration(
    arch: &str,
    os: &str,
    endian: &str,
    mut features: BTreeSet<String>,
) -> Result<(), &'static str> {
    if arch != "aarch64" || os != "macos" || endian != "little" {
        return Err("unsupported target: PRETZEL (4,4) requires little-endian macOS AArch64");
    }
    // The stack-range wipes are an option of every supported target.
    features.remove("STACK_WIPE");
    // Only dedicated Darwin replay executables link the fixture entropy hook.
    if os == "macos" {
        features.remove("CONFORMANCE");
    }
    if !features.is_empty() {
        return Err("PRETZEL (4,4) accepts no feature other than stack-wipe and conformance");
    }
    Ok(())
}

mod native {
    include!("native-build.rs");
    pub fn run() {
        main();
    }
}

fn main() {
    println!("cargo:rerun-if-changed=native-build.rs");
    let features = std::env::vars()
        .filter_map(|(key, _)| key.strip_prefix("CARGO_FEATURE_").map(str::to_owned))
        .collect();
    check_configuration(
        &std::env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo target architecture"),
        &std::env::var("CARGO_CFG_TARGET_OS").expect("Cargo target OS"),
        &std::env::var("CARGO_CFG_TARGET_ENDIAN").expect("Cargo target endianness"),
        features,
    )
    .unwrap_or_else(|reason| panic!("{reason}"));
    native::run();
}
