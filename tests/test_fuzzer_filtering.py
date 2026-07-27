from mutagen.dependency_resolver import parse_compilation_error


def test_parse_compilation_error_detects_math_library():
    stderr_output = """
    /usr/bin/ld: /tmp/ccXyPXne.o: undefined reference to symbol 'pow@@GLIBC_2.29'
    /usr/bin/ld: /lib/x86_64-linux-gnu/libm.so.6: error adding symbols: DSO missing from command line
    collect2: error: ld returned 1 exit status
    """
    flags = parse_compilation_error(stderr_output)
    assert "-lm" in flags
