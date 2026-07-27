import os
import tempfile

from mutagen.dependency_resolver import (
    detect_build_system,
    parse_compilation_error,
    resolve_header_dependencies,
)


def test_detect_build_system():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert detect_build_system(tmpdir) is None

        cmake_file = os.path.join(tmpdir, "CMakeLists.txt")
        with open(cmake_file, "w") as f:
            f.write("project(test)")
        assert detect_build_system(tmpdir) == "cmake"

def test_resolve_header_dependencies():
    with tempfile.TemporaryDirectory() as tmpdir:
        source_path = os.path.join(tmpdir, "test_curl.c")
        with open(source_path, "w") as f:
            f.write("#include <curl/curl.h>\n#include <zlib.h>\nint main() { return 0; }\n")

        flags = resolve_header_dependencies(source_path)
        assert "-lcurl" in flags
        assert "-lz" in flags

def test_parse_compilation_error():
    mock_stderr = """
    test.c:2:10: fatal error: curl/curl.h: No such file or directory
    test.c:10: undefined reference to `curl_easy_init'
    test.c:12: undefined reference to `pthread_create'
    """
    flags = parse_compilation_error(mock_stderr)
    assert "-lcurl" in flags
    assert "-pthread" in flags
