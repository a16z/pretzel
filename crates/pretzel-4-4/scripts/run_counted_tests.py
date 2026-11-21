#!/usr/bin/env python3
"""Run a CI test command and reject success with no passing Rust tests."""
import re
import subprocess
import sys


def main():
    command = sys.argv[1:]
    if not command:
        raise SystemExit("test command required")
    result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, bufsize=1)
    passed = 0
    for line in result.stdout:
        print(line, end="", flush=True)
        match = re.search(r"test result: ok\. (\d+) passed; 0 failed;", line)
        if match:
            passed += int(match[1])
    code = result.wait()
    if code:
        raise SystemExit(code)
    if passed == 0:
        raise SystemExit("Test command reported no passing Rust tests")
    print(f"Nonzero test-count gate: {passed} passed")


if __name__ == "__main__":
    main()
