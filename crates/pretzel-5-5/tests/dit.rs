//! Runs the timing lifetime tests of the library in a nested release build, with the feature
//! `stack-wipe` when this test has it, and requires each named test to have passed.
#![cfg(all(target_os = "macos", target_endian = "little"))]
#[test]
fn native_secret_lifetime_dit_boundaries() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // A separate target avoids the outer cargo lock. These ISA flags are only
    // for the backend unit image, matching the conformance runner.
    let target = std::env::temp_dir().join(format!("pretzel-level5-dit-{}", std::process::id()));
    // The library is tested in the configuration of this test: with the stack-range wipes when
    // the crate has the feature `stack-wipe`, without them otherwise.
    let library_features: &[&str] = if cfg!(feature = "stack-wipe") {
        &["--features", "stack-wipe"]
    } else {
        &[]
    };
    let output = std::process::Command::new(env!("CARGO"))
        .current_dir(root)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env("RUSTFLAGS", "-C target-feature=+sha3,+dotprod")
        .env("CARGO_TARGET_DIR", &target)
        .args([
            "test",
            "--offline",
            "--locked",
            "--release",
            "-p",
            "pretzel-5-5",
            "--lib",
            "timing_state::",
        ])
        .args(library_features)
        .args(["--", "--test-threads=1", "--nocapture"])
        .output()
        .expect("run native secret-lifetime DIT tests");
    let stdout = String::from_utf8_lossy(&output.stdout);
    print!("{stdout}");
    // The child has exited; release its separate build directory even on failure.
    // A child that fails before building leaves no directory to remove.
    if let Err(e) = std::fs::remove_dir_all(&target) {
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::NotFound,
            "remove finished DIT test target: {e}"
        );
    }
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for name in [
        "native_nested_error_and_unwind_restore",
        "both_entry_states_and_thread_handoffs_restore",
        "unsupported_fails_before_register_access",
        "panicking_parent_keeps_children_guarded_once_on_all_entry_modes",
        "real_constructor_unwind_and_post_parse_rejection_retire_temporaries",
        "hash_consistent_malformed_shell_key_observes_constructor_temporaries",
        "prepared_key_drop_and_caller_scratch_failure_cover_all_entry_modes",
        "erasure_runs_when_dit_entry_fails_capability_failure_class",
        "real_sign_unwind_erases_leases_scratch_and_prepared_key",
        "real_used_scratch_tls_teardown_observes_dit_and_restoration",
        "public_wrappers_fail_before_parse_and_restore_on_unwind",
        "public_keygen_and_callback_cover_every_draw_private_work_and_cleanup",
        "public_sign_outer_guard_covers_return_move_signing_and_drop",
        "caller_scoped_preparation_covers_owned_return_and_drop",
        "public_sign_malformed_keys_restore_without_entropy",
    ] {
        assert!(
            stdout.contains(&format!("::{name} ... ok")),
            "missing test: {name}\n{stdout}"
        );
    }
}
