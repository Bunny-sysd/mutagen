from mutagen.core import deduplicate_payloads
from mutagen.dependency_resolver import parse_compilation_error


def test_parse_compilation_error_detects_math_library():
    stderr_output = """
    /usr/bin/ld: /tmp/ccXyPXne.o: undefined reference to symbol 'pow@@GLIBC_2.29'
    /usr/bin/ld: /lib/x86_64-linux-gnu/libm.so.6: error adding symbols: DSO missing from command line
    collect2: error: ld returned 1 exit status
    """
    flags = parse_compilation_error(stderr_output)
    assert "-lm" in flags


def test_deduplicate_payloads_preserves_distinct_raw_bytes_hex():
    """
    Regression test: for file delivery mode, the actual payload content lives
    in raw_bytes_hex (input_data is empty). The dedup key previously ignored
    raw_bytes_hex entirely -- so multiple payloads sharing the same declared
    filename and empty input_data (a common case: the AI often reuses a
    generic filename across genuinely different attempts) collapsed into a
    single test, silently dropping the rest before they ever ran.
    """
    payloads = [
        {"args": ["test_boundary.png"], "input_data": "", "raw_bytes_hex": "89504e47aaaaaaaaaa", "reason": "attempt 1"},
        {"args": ["test_boundary.png"], "input_data": "", "raw_bytes_hex": "89504e47bbbbbbbbbb", "reason": "attempt 2"},
        {"args": ["test_boundary.png"], "input_data": "", "raw_bytes_hex": "89504e47aaaaaaaaaa", "reason": "exact duplicate of attempt 1"},
    ]

    result = deduplicate_payloads(payloads)

    assert len(result) == 2
    assert {p["reason"] for p in result} == {"attempt 1", "attempt 2"}


def test_deduplicate_payloads_still_drops_exact_duplicates():
    payloads = [
        {"args": ["A"], "input_data": "x", "raw_bytes_hex": None},
        {"args": ["A"], "input_data": "x", "raw_bytes_hex": None},
        {"args": ["B"], "input_data": "x", "raw_bytes_hex": None},
    ]

    result = deduplicate_payloads(payloads)

    assert len(result) == 2
