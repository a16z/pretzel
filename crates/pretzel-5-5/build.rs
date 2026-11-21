include!("../pretzel-4-4/core/native-tools.rs");
use std::{env, path::PathBuf};
fn supported_target(arch: &str, os: &str, endian: &str) -> bool {
    arch == "aarch64" && os == "macos" && endian == "little"
}

fn main() {
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/native-tools.rs");
    let target = env::var("TARGET").unwrap();
    assert!(
        supported_target(
            &env::var("CARGO_CFG_TARGET_ARCH").unwrap(),
            &env::var("CARGO_CFG_TARGET_OS").unwrap(),
            &env::var("CARGO_CFG_TARGET_ENDIAN").unwrap()
        ),
        "unsupported target: PRETZEL (5,5) requires macOS AArch64"
    );
    require_dot_product();
    println!("cargo:rerun-if-changed=src/interval-key256-table.h");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut cmd = native_tool("CC", "clang-19", "clang");
    cmd.args([
        "-O3",
        "-ffixed-x18",
        "-mno-red-zone",
        "-fno-stack-protector",
        "-fomit-frame-pointer",
        "-c",
        "src/interval-transport.c",
        "-o",
    ])
    .arg(out.join("interval-transport.o"));
    if target == "aarch64-apple-darwin" {
        cmd.arg("-fno-omit-frame-pointer");
    }
    assert!(cmd.status().unwrap().success());
    let mut wrap = native_tool("CC", "clang-19", "clang");
    wrap.args(["-c", "src/interval-erased-wrapper.S", "-o"])
        .arg(out.join("wrapper.o"));
    if target == "aarch64-apple-darwin" {
        wrap.arg("-fno-omit-frame-pointer");
    }
    assert!(wrap.status().unwrap().success());
    let mut c = native_tool("CC", "clang-19", "clang");
    c.args([
        "-O3",
        "-ffixed-x18",
        "-mno-red-zone",
        "-fno-stack-protector",
        "-fomit-frame-pointer",
        "-c",
        "src/reservoir-wrapper.S",
        "-o",
    ])
    .arg(out.join("reservoir-wrapper.o"));
    if target == "aarch64-apple-darwin" {
        c.arg("-fno-omit-frame-pointer");
    }
    assert!(c.status().unwrap().success());
    println!("cargo:rerun-if-changed=src/reservoir-wrapper.S");
    let mut archive = native_tool("AR", "llvm-ar-19", "ar");
    archive
        .arg("crs")
        .arg(out.join("libinterval_transport.a"))
        .arg(out.join("interval-transport.o"))
        .arg(out.join("wrapper.o"))
        .arg(out.join("reservoir-wrapper.o"));
    assert!(archive.status().unwrap().success());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=interval_transport");
    println!("cargo:rerun-if-changed=src/interval-erased-wrapper.S");
    println!("cargo:rerun-if-changed=src/interval-transport.c");
    println!("cargo:rerun-if-changed=src/interval-centered10-prepare.h");
    println!("cargo:rerun-if-changed=src/interval-geometric.c");
    println!("cargo:rerun-if-changed=src/normalize.h");
    println!("cargo:rerun-if-changed=src/interval-geometric-prepare.c");
}
