// Native tool selection only. The call sites choose the compiler flags.
fn native_tool(variable: &str, linux_default: &str, apple_tool: &str) -> std::process::Command {
    println!("cargo:rerun-if-env-changed={variable}");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    let apple = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos");
    let mut command = if let Some(tool) = std::env::var_os(variable) {
        std::process::Command::new(tool)
    } else if apple {
        let mut command = std::process::Command::new("xcrun");
        command.args(["--sdk", "macosx", apple_tool]);
        command
    } else {
        std::process::Command::new(linux_default)
    };
    if apple && variable == "CC" {
        command.args(["-target", "arm64-apple-macos15.2"]);
        let sdk = if let Some(sdk) = std::env::var_os("SDKROOT") {
            checked_sdk_root(std::path::PathBuf::from(sdk), "SDKROOT")
        } else {
            let output = std::process::Command::new("xcrun")
                .args(["--sdk", "macosx", "--show-sdk-path"])
                .output().expect("xcrun requires Xcode Command Line Tools");
            assert!(output.status.success(), "xcrun SDK discovery failed");
            let path = String::from_utf8(output.stdout).expect("xcrun SDK path is not UTF-8");
            checked_sdk_root(std::path::PathBuf::from(path.trim()), "xcrun --show-sdk-path")
        };
        command.arg("-isysroot").arg(sdk);
        // Apple targets keep the frame chain.
        command.arg("-fno-omit-frame-pointer");
    }
    command
}

// The SDK path is passed to the compiler as a single argument, never through a
// shell. Accept only an absolute path to an existing directory that cannot be
// read as an option.
fn checked_sdk_root(path: std::path::PathBuf, source: &str) -> std::path::PathBuf {
    let usable = path.is_absolute()
        && !path.as_os_str().as_encoded_bytes().starts_with(b"-")
        && path.is_dir();
    assert!(usable, "{source} must be an absolute path to an existing SDK directory, got {path:?}");
    path
}

// The native code executes the AArch64 dot-product instruction SDOT (FEAT_DotProd)
// and nothing tests for it at run time, so the build refuses a target that does
// not guarantee it. The compiler's Apple silicon target enables `dotprod` by
// default; another AArch64 target needs the flag named in the message.
fn require_dot_product() {
    let features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    assert!(
        features.split(',').any(|feature| feature == "dotprod"),
        "unsupported target: PRETZEL executes the AArch64 dot-product instruction SDOT \
         (FEAT_DotProd) with no run-time test; this target does not enable `dotprod`. \
         Build with RUSTFLAGS='-C target-feature=+dotprod', and only for processors that have it"
    );
}
