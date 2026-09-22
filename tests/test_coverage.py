import subprocess
from unittest.mock import patch

from mutagen.core import _augment_seed_queue_with_symbolic_seeds, mutate_input
from mutagen.executor import execute_payload
from mutagen.instrumenter import instrument_c_source


def test_instrument_c_source_simple():
    c_code = """
    #include <stdio.h>
    int main() {
        int x = 10;
        if (x > 5) {
            printf("High\\n");
        } else {
            printf("Low\\n");
        }
        return 0;
    }
    """
    instrumented, total_blocks = instrument_c_source(c_code)
    # Must have instrumented main, if, and else blocks (3 blocks)
    assert total_blocks >= 3
    assert "__mutagen_cov_trace(0);" in instrumented
    assert "__mutagen_cov_dump" in instrumented

def test_instrument_c_source_skip_non_executable():
    c_code = """
    struct Point {
        int x;
        int y;
    };
    enum Color { RED, GREEN, BLUE };
    int arr[] = { 1, 2, 3 };
    int main() {
        if (arr[0] == 1) {
            return 0;
        }
    }
    """
    instrumented, total_blocks = instrument_c_source(c_code)
    # Check that it did not place trace markers inside struct, enum or array initializers
    # Wait, the only executable block here is the main function and the if block (2 blocks)
    assert total_blocks == 2

    # Verify no trace markers are inserted in declarations/initializers
    struct_decl = re_find_trace(instrumented, "struct Point")
    assert struct_decl is False

    arr_init = re_find_trace(instrumented, "arr\\[\\]")
    assert arr_init is False

def re_find_trace(code: str, pattern: str) -> bool:
    import re
    # Check if there is a trace marker adjacent to the pattern
    # e.g., pattern followed by {__mutagen_cov_trace
    match = re.search(pattern + r"\s*\{__mutagen_cov_trace", code)
    return match is not None

def test_parse_coverage_stdout():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["target_exe"],
            returncode=0,
            stdout="Hello World\n__MUTAGEN_COV__:1,5,10,\nDone",
            stderr=""
        )
        res = execute_payload("target_exe", [], None, "stdin", 5, "none")
        # Verify coverage parsed
        assert res["coverage"] == [1, 5, 10]
        # Verify coverage line stripped from stdout
        assert "__MUTAGEN_COV__" not in res["stdout"]
        assert "Hello World" in res["stdout"]
        assert "Done" in res["stdout"]

def test_mutate_input_args():
    args = ["val1", "123"]
    for _ in range(20):
        new_args, input_data = mutate_input(args, "input", "args")
        assert input_data == "input"
        assert len(new_args) == len(args)
        if new_args != args:
            return
    assert False, "Failed to mutate arguments after 20 attempts"

def test_mutate_input_stdin():
    for _ in range(20):
        new_args, new_input = mutate_input(["arg"], "input_data", "stdin")
        assert new_args == ["arg"]
        if new_input != "input_data":
            return
    assert False, "Failed to mutate input after 20 attempts"


def test_augment_seed_queue_with_symbolic_seeds_adds_constraint_derived_seeds():
    """symbolic_solver.py implements real constraint extraction (magic hex, string
    comparisons, boundary integers) with its own passing tests, but was never wired
    into the actual coverage-guided mutation loop in core.py -- nothing ever called
    it, so the mutation fuzzer never benefited from seeds crafted to get past
    branch conditions like `if (val == 0xDEADBEEF)` or `strcmp(s, "MAGIC")`."""
    source_code = """
    int check(int val, const char *s) {
        if (val == 0xDEADBEEF) {
            return 1;
        }
        if (strcmp(s, "MAGIC") == 0) {
            return 2;
        }
        return 0;
    }
    """
    seed_queue = [{
        "args": [], "input_data": "seed_input", "vuln_type": "x", "cwe": "", "severity": "medium", "reason": "r",
    }]

    _augment_seed_queue_with_symbolic_seeds(seed_queue, source_code, "stdin")

    # Original seed preserved, new symbolic-derived seeds appended
    assert seed_queue[0]["input_data"] == "seed_input"
    assert len(seed_queue) > 1

    new_inputs = [s["input_data"] for s in seed_queue[1:]]
    assert any("MAGIC" in inp for inp in new_inputs)
    assert any("3735928559" in inp or "deadbeef" in inp.lower() for inp in new_inputs)
    for s in seed_queue[1:]:
        assert s["vuln_type"] == "symbolic_constraint_seed"


def test_augment_seed_queue_with_symbolic_seeds_respects_args_delivery_mode():
    source_code = 'if (strcmp(s, "TOKEN") == 0) { return 1; }'
    seed_queue = []

    _augment_seed_queue_with_symbolic_seeds(seed_queue, source_code, "args")

    assert seed_queue
    for s in seed_queue:
        assert s["input_data"] == ""
        assert s["args"]

