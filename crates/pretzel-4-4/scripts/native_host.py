#!/usr/bin/env python3
"""Host and environment checks shared by the native runners.

Execution of native code requires Apple silicon macOS with SHA3,
DIT and dot-product support. Nothing is installed or provisioned here.
"""
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("cargo", "rustc", "xcrun")
REQUIRED_CPU_FEATURES = {"sha3", "dit", "asimddp"}


def reject_feature_shim(environment):
    """Cargo supplies package features itself; inherited feature variables are invalid."""
    injected = sorted(key for key in environment if key.startswith("CARGO_FEATURE_"))
    if injected:
        raise ValueError("Unset inherited Cargo feature variables: " + ", ".join(injected))


def host_errors(system, machine, endian, feature_sets):
    if system != "Darwin" or machine not in ("aarch64", "arm64") or endian != "little":
        return ["Execution requires Apple silicon macOS."]
    if not feature_sets:
        return ["No CPU feature records available."]
    common = set.intersection(*feature_sets)
    missing = sorted(REQUIRED_CPU_FEATURES - common)
    return ["Missing CPU features: " + ", ".join(missing)] if missing else []


def host_cpu_features():
    """Return host evidence and normalized required capabilities; never infer support."""
    if platform.system() != "Darwin":
        return "", []
    keys = {"dit": "FEAT_DIT", "sha3": "FEAT_SHA3", "asimddp": "FEAT_DotProd"}
    features, evidence = set(), []
    for feature, key in keys.items():
        result = subprocess.run(["sysctl", "-n", "hw.optional.arm." + key],
                                capture_output=True, text=True)
        evidence.append(key + "=" + result.stdout.strip())
        if result.returncode == 0 and result.stdout.strip() == "1":
            features.add(feature)
    version = subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
    evidence.append("macOS=" + version)
    if tuple(map(int, version.split(".")[:2])) < (15, 2):
        features.discard("dit")
    return "\n".join(evidence) + "\n", [features]
