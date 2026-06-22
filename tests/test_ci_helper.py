import pytest
import os
import json
import shutil
from mutagen.ci_helper import main

def test_ci_helper_multi_language_patches():
    # Setup mock crashes and patches directory
    os.makedirs("crashes", exist_ok=True)
    os.makedirs("patches", exist_ok=True)

    # 1. Create mock crash report JSONs
    report_a = {
        "target": "target_rust",
        "crashes": [
            {
                "severity": "critical",
                "vuln_type": "buffer_overflow",
                "cwe": "CWE-120",
                "crash_type": "ACCESS_VIOLATION"
            }
        ]
    }
    report_b = {
        "target": "target_go",
        "crashes": [
            {
                "severity": "high",
                "vuln_type": "integer_overflow",
                "cwe": "CWE-190",
                "crash_type": "SIGSEGV"
            }
        ]
    }

    with open("crashes/crash_report_rust.json", "w", encoding="utf-8") as f:
        json.dump(report_a, f)
    with open("crashes/crash_report_go.json", "w", encoding="utf-8") as f:
        json.dump(report_b, f)

    # 2. Create mock patch files with extensions .rs and .go
    with open("patches/target_rust_FIXED.rs", "w", encoding="utf-8") as f:
        f.write("fn main() { /* Fixed Rust */ }")
    with open("patches/target_go_FIXED.go", "w", encoding="utf-8") as f:
        f.write("package main\n\nfunc main() { /* Fixed Go */ }")

    # Run ci_helper
    try:
        main()

        # Check comment.md was created
        assert os.path.exists("comment.md")

        with open("comment.md", "r", encoding="utf-8") as f:
            content = f.read()

        # Verify vulnerability summary contents
        assert "target_rust" in content
        assert "target_go" in content
        assert "CWE-120" in content
        assert "CWE-190" in content

        # Verify patch section language highlighting
        assert "```rust" in content
        assert "Fixed Rust" in content
        assert "```go" in content
        assert "Fixed Go" in content

    finally:
        # Clean up temporary mock files
        for filename in ["crashes/crash_report_rust.json", "crashes/crash_report_go.json"]:
            if os.path.exists(filename):
                os.remove(filename)
        for filename in ["patches/target_rust_FIXED.rs", "patches/target_go_FIXED.go"]:
            if os.path.exists(filename):
                os.remove(filename)
        if os.path.exists("comment.md"):
            os.remove(comment_filename := "comment.md")
