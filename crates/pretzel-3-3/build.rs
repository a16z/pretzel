include!("../pretzel-4-4/core/native-tools.rs");

use std::{env, path::PathBuf};
fn main() {
    // The public sponge is assembled by a `global_asm!` item of `shake2.rs`.
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/public_sponge_blocks.S");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/native-tools.rs");
    assert!(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64")
            && env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
            && env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple")
            && env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() == Ok("little")
            && env::var("CARGO_CFG_TARGET_POINTER_WIDTH").as_deref() == Ok("64"),
        "unsupported target: Pretzel-(3,3) requires AArch64 macOS (Apple silicon)"
    );
    require_dot_product();
    println!("cargo:rerun-if-changed=src/hint-context-cost.c");
    println!("cargo:rerun-if-changed=src/interval-key256-table.h");
    println!("cargo:rerun-if-changed=src/symbol-prefix.h");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/warm-gathers.S");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/hint-context-cost.c");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/reservoir-main.c");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/reservoir-mid-four.c");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/reservoir-tables.S");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/reservoir-wrapper.S");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/interval-erased-wrapper.S");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/warm-tail-wrapper.S");
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
    cmd.arg("-fno-omit-frame-pointer");
    cmd.arg("-DPRETZEL_NATIVE_TRANSPORT_BATCH");
    assert!(cmd.status().unwrap().success());
    let mut wrap = native_tool("CC", "clang-19", "clang");
    wrap.args(["-c", "src/interval-erased-wrapper.S", "-o"])
        .arg(out.join("wrapper.o"));
    wrap.arg("-fno-omit-frame-pointer");
    wrap.arg("-DPRETZEL_NATIVE_TRANSPORT_BATCH");
    assert!(wrap.status().unwrap().success());
    {
        let mut a = native_tool("CC", "clang-19", "clang");
        a.args([
            "-c",
            "src/transport-tables.S",
            "-march=armv8.2-a+dotprod",
            "-o",
        ])
        .arg(out.join("transport-tables.o"));
        a.arg("-fno-omit-frame-pointer");
        assert!(a.status().unwrap().success());
        println!("cargo:rerun-if-changed=src/transport-tables.S");
    }
    for (file, obj) in [
        ("src/reservoir-reference.c", "reservoir-reference.o"),
        ("src/warm-tail192.c", "warm-tail192.o"),
        ("src/warm-tail-wrapper.S", "warm-tail-wrapper425.o"),
        ("src/warm-gathers.S", "all-warm-gathers425.o"),
        ("src/reservoir.c", "reservoir.o"),
        ("src/reservoir-tables.S", "reservoir-tables.o"),
        ("src/reservoir-wrapper.S", "reservoir-wrapper.o"),
    ] {
        let mut c = native_tool("CC", "clang-19", "clang");
        c.args([
            "-O3",
            "-ffixed-x18",
            "-mno-red-zone",
            "-fno-stack-protector",
            "-fomit-frame-pointer",
            "-c",
            file,
            "-o",
        ])
        .arg(out.join(obj));
        c.arg("-fno-omit-frame-pointer");
        assert!(c.status().unwrap().success());
        println!("cargo:rerun-if-changed={}", file);
    }
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/warm-tail192.c");
    println!("cargo:rerun-if-changed=src/reservoir-mid-four.c");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/interval-queue-geometric-tile.h");
    println!("cargo:rerun-if-changed=src/interval-finish-pair.h");
    println!("cargo:rerun-if-changed=src/reservoir-main.c");
    println!("cargo:rerun-if-changed=src/reservoir-full.c");
    let mut archive = native_tool("AR", "llvm-ar-19", "ar");
    archive
        .arg("crs")
        .arg(out.join("libinterval_transport.a"))
        .arg(out.join("reservoir-reference.o"))
        .arg(out.join("interval-transport.o"))
        .arg(out.join("wrapper.o"))
        .arg(out.join("reservoir.o"))
        .arg(out.join("warm-tail192.o"))
        .arg(out.join("warm-tail-wrapper425.o"))
        .arg(out.join("all-warm-gathers425.o"))
        .arg(out.join("reservoir-tables.o"))
        .arg(out.join("reservoir-wrapper.o"));
    archive.arg(out.join("transport-tables.o"));
    assert!(archive.status().unwrap().success());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=interval_transport");
    println!("cargo:rerun-if-changed=src/interval-erased-wrapper.S");
    println!("cargo:rerun-if-changed=src/interval-transport.c");
    println!("cargo:rerun-if-changed=../pretzel-4-4/core/src/interval-centered7-prepare.h");
    println!("cargo:rerun-if-changed=src/interval-geometric.c");
    println!("cargo:rerun-if-changed=src/interval-geometric-prepare.c");
}
