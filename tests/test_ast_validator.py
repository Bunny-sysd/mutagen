"""
Tests for the Neuro-Symbolic AST Validation Layer (mutagen/ast_validator.py).

Verifies that tree-sitter-based pre-compilation validation correctly identifies
structural hallucinations in AI-generated C patches before they reach GCC.
"""


from mutagen.ast_validator import (
    ASTError,
    ASTValidationResult,
    format_validation_errors,
    validate_c_source,
)

# ---------------------------------------------------------------------------
# Valid C Code Tests
# ---------------------------------------------------------------------------

class TestValidCode:
    """Ensure structurally correct C code passes validation."""

    def test_simple_hello_world(self):
        code = """
#include <stdio.h>
int main() {
    printf("Hello, world!\\n");
    return 0;
}
"""
        result = validate_c_source(code)
        assert result.is_valid is True
        assert len(result.errors) == 0
        assert "main" in result.functions_found
        assert result.has_main is True
        assert result.node_count > 0

    def test_multi_function_program(self):
        code = """
int add(int a, int b) {
    return a + b;
}

int main() {
    int result = add(2, 3);
    return result;
}
"""
        result = validate_c_source(code)
        assert result.is_valid is True
        assert "add" in result.functions_found
        assert "main" in result.functions_found
        assert len(result.functions_found) == 2

    def test_code_with_structs_and_pointers(self):
        code = """
#include <stdlib.h>
#include <string.h>

struct Buffer {
    char *data;
    int size;
};

struct Buffer *create_buffer(int size) {
    struct Buffer *buf = malloc(sizeof(struct Buffer));
    if (buf) {
        buf->data = malloc(size);
        buf->size = size;
    }
    return buf;
}

void free_buffer(struct Buffer *buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

int main() {
    struct Buffer *b = create_buffer(256);
    if (b) {
        memset(b->data, 'A', b->size);
        free_buffer(b);
    }
    return 0;
}
"""
        result = validate_c_source(code)
        assert result.is_valid is True
        assert "create_buffer" in result.functions_found
        assert "free_buffer" in result.functions_found
        assert "main" in result.functions_found

    def test_code_with_control_flow(self):
        code = """
int classify(int x) {
    if (x > 0) {
        return 1;
    } else if (x < 0) {
        return -1;
    } else {
        return 0;
    }
}

int main() {
    return classify(42);
}
"""
        result = validate_c_source(code)
        assert result.is_valid is True
        assert result.has_main is True

    def test_code_with_switch_statement(self):
        code = """
int handle(int cmd) {
    switch (cmd) {
        case 1:
            return 10;
        case 2:
            return 20;
        default:
            return -1;
    }
}

int main() { return handle(1); }
"""
        result = validate_c_source(code)
        assert result.is_valid is True

    def test_code_with_for_loop(self):
        code = """
int sum(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += i;
    }
    return total;
}

int main() { return sum(10); }
"""
        result = validate_c_source(code)
        assert result.is_valid is True

    def test_code_with_preprocessor_directives(self):
        code = """
#include <stdio.h>
#include <stdlib.h>

#define MAX_SIZE 1024
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifdef _WIN32
#include <windows.h>
#endif

int main() {
    int x = MIN(5, MAX_SIZE);
    return x;
}
"""
        result = validate_c_source(code)
        assert result.is_valid is True


# ---------------------------------------------------------------------------
# Invalid C Code Tests (Hallucination Detection)
# ---------------------------------------------------------------------------

class TestInvalidCode:
    """Verify the validator catches common AI hallucinations."""

    def test_missing_closing_brace(self):
        code = """
int main() {
    int x = 5;
    return x;

"""
        result = validate_c_source(code)
        assert result.is_valid is False
        assert len(result.errors) > 0
        # Should detect the missing brace
        error_types = [e.node_type for e in result.errors]
        assert "ERROR" in error_types or "MISSING" in error_types

    def test_missing_semicolon(self):
        code = """
int main() {
    int x = 5
    return x;
}
"""
        result = validate_c_source(code)
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_completely_broken_syntax(self):
        code = """
int main( {
    {{{ return }}}
    if else while for
}
"""
        result = validate_c_source(code)
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_unmatched_parenthesis(self):
        code = """
int main() {
    int x = (5 + 3;
    return x;
}
"""
        result = validate_c_source(code)
        assert result.is_valid is False
        assert len(result.errors) > 0


# ---------------------------------------------------------------------------
# Edge Case Tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_string(self):
        result = validate_c_source("")
        assert result.is_valid is False
        assert len(result.errors) == 1
        assert result.errors[0].node_type == "EMPTY_INPUT"

    def test_whitespace_only(self):
        result = validate_c_source("   \n\n\t  ")
        assert result.is_valid is False
        assert result.errors[0].node_type == "EMPTY_INPUT"

    def test_none_input(self):
        result = validate_c_source(None)
        assert result.is_valid is False
        assert result.errors[0].node_type == "EMPTY_INPUT"

    def test_no_functions_just_declarations(self):
        """A file with only variable declarations and no functions."""
        code = """
int global_var = 42;
const char *name = "test";
"""
        result = validate_c_source(code)
        assert result.is_valid is False
        # Should flag the lack of function definitions
        error_types = [e.node_type for e in result.errors]
        assert "NO_FUNCTIONS" in error_types

    def test_single_line_function(self):
        code = "int main() { return 0; }"
        result = validate_c_source(code)
        assert result.is_valid is True
        assert result.has_main is True

    def test_void_function_no_main(self):
        code = """
void helper() {
    int x = 42;
}
"""
        result = validate_c_source(code)
        assert result.is_valid is True  # Structurally valid even without main
        assert result.has_main is False
        assert "helper" in result.functions_found


# ---------------------------------------------------------------------------
# Function Extraction Tests
# ---------------------------------------------------------------------------

class TestFunctionExtraction:
    """Verify correct extraction of function names from the AST."""

    def test_extracts_multiple_functions(self):
        code = """
void init() {}
int process(int data) { return data * 2; }
char *format(char *s) { return s; }
int main() { return 0; }
"""
        result = validate_c_source(code)
        assert result.is_valid is True
        assert set(result.functions_found) == {"init", "process", "format", "main"}

    def test_pointer_return_type_function(self):
        code = """
char *get_name() {
    return "mutagen";
}

int main() { return 0; }
"""
        result = validate_c_source(code)
        assert result.is_valid is True
        assert "get_name" in result.functions_found


# ---------------------------------------------------------------------------
# Error Formatting Tests
# ---------------------------------------------------------------------------

class TestFormatValidationErrors:
    """Verify format_validation_errors produces useful output for AI feedback."""

    def test_valid_result_message(self):
        result = ASTValidationResult(is_valid=True)
        msg = format_validation_errors(result)
        assert "passed" in msg.lower()
        assert "no structural errors" in msg.lower()

    def test_invalid_result_contains_errors(self):
        result = ASTValidationResult(
            is_valid=False,
            errors=[
                ASTError(line=3, column=5, message="Missing closing brace", node_type="MISSING", context="int main() {"),
                ASTError(line=7, column=0, message="Syntax error at end of file", node_type="ERROR"),
            ],
        )
        msg = format_validation_errors(result)
        assert "NEURO-SYMBOLIC PRE-COMPILATION VALIDATION FAILED" in msg
        assert "Missing closing brace" in msg
        assert "Syntax error at end of file" in msg
        assert "INSTRUCTIONS:" in msg
        assert "Errors detected: 2" in msg

    def test_error_format_includes_source_context(self):
        result = ASTValidationResult(
            is_valid=False,
            errors=[
                ASTError(line=5, column=10, message="Bad token", node_type="ERROR", context="    int x = ;"),
            ],
        )
        msg = format_validation_errors(result)
        assert "int x = ;" in msg
        assert "Source:" in msg

    def test_error_format_from_real_validation(self):
        """Run a real validation and format the errors."""
        code = """
int main() {
    int x = 5
    return x;
}
"""
        result = validate_c_source(code)
        assert result.is_valid is False
        msg = format_validation_errors(result)
        assert len(msg) > 0
        assert "NEURO-SYMBOLIC" in msg


# ---------------------------------------------------------------------------
# Node Count Tests
# ---------------------------------------------------------------------------

class TestNodeCounting:
    """Verify AST node counting works correctly."""

    def test_simple_program_has_nodes(self):
        code = "int main() { return 0; }"
        result = validate_c_source(code)
        assert result.node_count > 0

    def test_complex_program_has_more_nodes(self):
        simple = "int main() { return 0; }"
        complex_code = """
#include <stdio.h>
int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int main() {
    int x = add(1, 2);
    int y = sub(5, 3);
    printf("%d %d\\n", x, y);
    return 0;
}
"""
        simple_result = validate_c_source(simple)
        complex_result = validate_c_source(complex_code)
        assert complex_result.node_count > simple_result.node_count
