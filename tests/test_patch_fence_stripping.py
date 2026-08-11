from mutagen.ast_validator import validate_c_source
from mutagen.engines.output_parser import strip_code_fences


def test_strip_code_fences_clean_code():
    raw = "int main() { return 0; }"
    assert strip_code_fences(raw) == "int main() { return 0; }"


def test_strip_code_fences_standard_c_fence():
    raw = "```c\n#include <stdio.h>\nint main() {\n    return 0;\n}\n```"
    expected = "#include <stdio.h>\nint main() {\n    return 0;\n}"
    assert strip_code_fences(raw) == expected


def test_strip_code_fences_with_preamble_and_postamble():
    raw = """Here is the secure patch to fix the vulnerability:

```c
#include <stdio.h>
int main() {
    printf("Fixed!");
    return 0;
}
```

Hope this helps!"""
    expected = """#include <stdio.h>
int main() {
    printf("Fixed!");
    return 0;
}"""
    assert strip_code_fences(raw) == expected


def test_strip_code_fences_unclosed():
    raw = "```c\n#include <stdio.h>\nint main() { return 0; }"
    expected = "#include <stdio.h>\nint main() { return 0; }"
    assert strip_code_fences(raw) == expected


def test_fenced_patch_ast_validation_pipeline():
    fenced_patch = """Here is the updated C code:

```c
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc > 1) {
        printf("Arg: %s\\n", argv[1]);
    }
    return 0;
}
```"""
    cleaned = strip_code_fences(fenced_patch)
    ast_result = validate_c_source(cleaned)
    assert ast_result.is_valid
    assert ast_result.has_main
    assert ast_result.functions_found == ["main"]
