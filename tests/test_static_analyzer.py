import pytest
from mutagen.static_analyzer import (
    analyze_source,
    StaticFinding,
    PreTargetingResult,
    format_pretargeting_summary,
)
from mutagen.chunker import contains_dangerous_keywords


def test_empty_and_whitespace_input():
    # Empty
    res = analyze_source("")
    assert len(res.findings) == 0
    assert res.focused_code == ""
    assert res.reduction_percent == 0.0

    # Whitespace only
    res = analyze_source("   \n \n  ")
    assert len(res.findings) == 0
    assert res.focused_code == ""
    assert res.reduction_percent == 0.0


def test_no_dangerous_patterns():
    code = """#include <stdio.h>
int add(int a, int b) {
    return a + b;
}
int main() {
    printf("Result: %d\\n", add(5, 10));
    return 0;
}
"""
    res = analyze_source(code)
    # Since printf is a medium severity pattern, wait, let's verify:
    # Under DANGEROUS_CALLS in static_analyzer.py:
    # "printf": {"category": "format_string", "severity": "medium", "cwe": "CWE-134"}
    # Ah! printf is considered dangerous. Let's write a function with absolutely NO dangerous calls.
    safe_code = """#include <stdio.h>
int add(int a, int b) {
    return a + b;
}
int main() {
    int x = 5;
    int y = 10;
    int z = x + y;
    return z;
}
"""
    res = analyze_source(safe_code)
    assert len(res.findings) == 0
    assert res.focused_code == safe_code
    assert res.reduction_percent == 0.0


def test_dangerous_patterns_extraction():
    code = """#include <stdio.h>
#include <string.h>

struct Data {
    char buf[64];
};

void safe_func1() { int x = 1; }
void safe_func2() { int x = 2; }
void safe_func3() { int x = 3; }
void safe_func4() { int x = 4; }
void safe_func5() { int x = 5; }
void safe_func6() { int x = 6; }
void safe_func7() { int x = 7; }
void safe_func8() { int x = 8; }
void safe_func9() { int x = 9; }
void safe_func10() { int x = 10; }

void vuln_func(char *src) {
    char dest[10];
    strcpy(dest, src);
}

int main() {
    vuln_func("test");
    return 0;
}
"""
    res = analyze_source(code)
    # strcpy should be captured
    findings = [f for f in res.findings if f.call_name == "strcpy"]
    assert len(findings) == 1
    assert findings[0].function_name == "vuln_func"
    assert findings[0].pattern_type == "unsafe_copy"
    assert findings[0].severity == "critical"

    # vuln_func and main should be in focused functions, safe_funcs should not
    assert "vuln_func" in res.focused_functions
    assert "main" in res.focused_functions
    assert "safe_func1" not in res.focused_functions

    # Preamble should be preserved (includes, structs)
    assert "#include <stdio.h>" in res.focused_code
    assert "#include <string.h>" in res.focused_code
    assert "struct Data" in res.focused_code
    assert "safe_func1" not in res.focused_code
    assert "strcpy(dest, src);" in res.focused_code

    # Reduction should be positive
    assert res.reduction_percent > 0.0


def test_ast_awareness_ignores_comments_and_strings():
    code = """#include <stdio.h>
void func() {
    // We should not use strcpy here because it is bad
    const char *msg = "strcpy is unsafe";
    int strcpy_safe_var = 10;
}
"""
    res = analyze_source(code)
    # The occurrences are in comments/strings/identifiers but not call_expression
    assert len(res.findings) == 0
    assert res.focused_code == code


def test_multiple_vulnerabilities_same_function():
    code = """#include <stdio.h>
#include <stdlib.h>
void bad_func() {
    char *p = malloc(10);
    strcpy(p, "hello");
    free(p);
}
"""
    res = analyze_source(code)
    # findings should contain malloc, strcpy, and free
    calls = {f.call_name for f in res.findings}
    assert "malloc" in calls
    assert "strcpy" in calls
    assert "free" in calls
    
    # But bad_func should only be extracted once
    assert list(res.focused_functions.keys()) == ["bad_func"]


def test_format_pretargeting_summary():
    res = PreTargetingResult(
        original_line_count=100,
        focused_line_count=20,
        reduction_percent=80.0,
        findings=[
            StaticFinding(
                function_name="vuln",
                line=50,
                pattern_type="unsafe_copy",
                call_name="strcpy",
                severity="critical",
                cwe="CWE-120",
                context_snippet="strcpy(buf, input);"
            )
        ],
        focused_functions={"vuln": "void vuln() { ... }"}
    )
    summary = format_pretargeting_summary(res)
    assert "Sniper Mode" in summary
    assert "80%" in summary
    assert "strcpy" in summary


def test_chunker_ast_dangerous_keywords():
    # True because of call_expression
    assert contains_dangerous_keywords("void test() { strcpy(a, b); }") is True
    # False because it's only in a comment
    assert contains_dangerous_keywords("void test() { // strcpy is bad \n }") is False
    # False because it's only in a string literal
    assert contains_dangerous_keywords('void test() { const char *s = "strcpy"; }') is False
