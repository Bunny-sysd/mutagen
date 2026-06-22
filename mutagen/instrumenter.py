import re


def instrument_c_source(source_code: str) -> tuple[str, int]:
    """
    Instruments C/C++ source code to track basic block coverage.

    Returns a tuple of (instrumented_code, total_blocks).
    """
    # 1. Strip comments and string/char literals temporarily to avoid matching braces inside them
    # We replace them with unique placeholders, and restore them afterwards.
    placeholders = {}
    placeholder_counter = 0

    def get_placeholder(content: str, prefix: str) -> str:
        nonlocal placeholder_counter
        p = f"___MUTAGEN_{prefix}_{placeholder_counter}___"
        placeholders[p] = content
        placeholder_counter += 1
        return p

    # Save string literals
    def string_repl(match):
        return get_placeholder(match.group(0), "STR")
    # Match double quoted strings handling escaped quotes
    processed = re.sub(r'"(\\.|[^"\\])*"', string_repl, source_code)

    # Save char literals
    def char_repl(match):
        return get_placeholder(match.group(0), "CHAR")
    processed = re.sub(r"'(\\.|[^'\\])*'", char_repl, processed)

    # Save comments
    def comment_repl(match):
        return get_placeholder(match.group(0), "COMMENT")
    # Match block and line comments
    processed = re.sub(r'/\*.*?\*/|//.*?$', comment_repl, processed, flags=re.MULTILINE | re.DOTALL)

    # 2. Find and instrument executable braces
    # We scan for '{' and determine if it's a code block (functions, control statements)
    block_counter = 0
    instrumented_pieces = []
    last_idx = 0

    # Find all '{' in the processed code
    for match in re.finditer(r'\{', processed):
        brace_idx = match.start()

        # Determine if this brace should be instrumented
        # Scan backward to find preceding statement context
        idx = brace_idx - 1
        preceding = []

        while idx >= 0:
            char = processed[idx]
            # Stop if we hit a statement/block boundary
            if char in (';', '}', '{'):
                break
            preceding.append(char)
            idx -= 1

        preceding_str = "".join(reversed(preceding)).strip()

        # Normalize spaces
        normalized = " ".join(preceding_str.split())

        # Check if we should instrument this brace
        is_executable = True

        # Skip if preceded by struct/union/enum/class/namespace declaration
        skip_keywords = ["struct", "enum", "union", "class", "namespace", "typedef"]
        for kw in skip_keywords:
            if re.search(r'\b' + kw + r'\b', normalized):
                is_executable = False
                break

        # Skip if it is an initializer list (preceded by assignment but not comparison operators)
        if is_executable:
            if re.search(r'(?<![=!<>])=(?![=])', normalized):
                is_executable = False

        # Skip if it has nested commas indicating an initializer list or compound literal
        if is_executable:
            # If the preceding string contains commas and is not a function signature (e.g. no parentheses enclosing the commas)
            # a simple heuristic is: if it has a comma outside parens, it's likely an initializer list item.
            # Let's count parens balance
            paren_depth = 0
            has_comma_outside = False
            for c in normalized:
                if c == '(':
                    paren_depth += 1
                elif c == ')':
                    paren_depth -= 1
                elif c == ',' and paren_depth == 0:
                    has_comma_outside = True
                    break
            if has_comma_outside:
                is_executable = False

        if is_executable:
            block_id = block_counter
            block_counter += 1
            # Append code up to this brace, then the brace and the trace callback
            instrumented_pieces.append(processed[last_idx:brace_idx])
            instrumented_pieces.append(f"{{__mutagen_cov_trace({block_id});")
            last_idx = brace_idx + 1

    # Add the remaining piece of the code
    instrumented_pieces.append(processed[last_idx:])
    instrumented_code = "".join(instrumented_pieces)

    # 3. Restore comments and string/char literals
    # We must restore them in reverse order of insertion (innermost/last-inserted first)
    # to ensure nested replacements (like strings inside comments) resolve correctly.
    for placeholder, original in reversed(list(placeholders.items())):
        instrumented_code = instrumented_code.replace(placeholder, original)

    # 4. Inject the Mutagen coverage header at the top
    # We define the header with a destructor function to dump the coverage map to stdout at exit.
    # To support clean exit on Windows and Linux, we use __attribute__((destructor)) which runs
    # automatically at termination.
    header = """/* --- MUTAGEN COVERAGE INSTRUMENTATION HEADER --- */
#include <stdio.h>
#define __MUTAGEN_COV_MAX 4096
static unsigned char __mutagen_cov_map[__MUTAGEN_COV_MAX] = {0};
static void __mutagen_cov_trace(int block_id) {
    if (block_id >= 0 && block_id < __MUTAGEN_COV_MAX) {
        __mutagen_cov_map[block_id] = 1;
    }
}
static void __mutagen_cov_dump(void) {
    printf("\\n__MUTAGEN_COV__:");
    for (int i = 0; i < __MUTAGEN_COV_MAX; i++) {
        if (__mutagen_cov_map[i]) {
            printf("%d,", i);
        }
    }
    printf("\\n");
    fflush(stdout);
}
#ifdef _MSC_VER
#pragma section(".CRT$XCU", read)
static void __cdecl __mutagen_msc_exit(void) { __mutagen_cov_dump(); }
__declspec(allocate(".CRT$XCU")) static void (__cdecl *__mutagen_msc_reg)(void) = __mutagen_msc_exit;
#else
__attribute__((destructor)) static void __mutagen_cov_destructor(void) {
    __mutagen_cov_dump();
}
#endif
/* ------------------------------------------------ */
"""
    return header + instrumented_code, block_counter
