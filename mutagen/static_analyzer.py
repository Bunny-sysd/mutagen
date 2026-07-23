"""
Static Analysis Pre-Targeting Engine ("Sniper Mode") for Mutagen.

Uses tree-sitter AST queries to extract only the dangerous code regions from
large C source files before sending them to the LLM for analysis. This
dramatically reduces token costs, context window overload, and hallucination
risk by focusing the AI on the code that actually matters.

Architecture:
    10,000 lines → analyze_source() → PreTargetingResult
        ├── focused_code (200 lines of dangerous functions + preamble)
        └── reduction stats (95% context eliminated)

This is conceptually similar to what Semgrep does, but purpose-built for
Mutagen's pipeline: instead of reporting line-number findings, we extract
entire function bodies with surrounding context so the AI can reason about
data flow and generate correct payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Dangerous pattern registry
# ---------------------------------------------------------------------------

# Functions that are known sources of memory corruption, command injection,
# and other vulnerabilities. Organized by risk category.
DANGEROUS_CALLS: dict[str, dict] = {
    # --- Memory copy without bounds ---
    "strcpy":   {"category": "unsafe_copy",    "severity": "critical", "cwe": "CWE-120"},
    "strncpy":  {"category": "unsafe_copy",    "severity": "high",     "cwe": "CWE-120"},
    "strcat":   {"category": "unsafe_copy",    "severity": "critical", "cwe": "CWE-120"},
    "strncat":  {"category": "unsafe_copy",    "severity": "high",     "cwe": "CWE-120"},
    "memcpy":   {"category": "unsafe_copy",    "severity": "high",     "cwe": "CWE-120"},
    "memmove":  {"category": "unsafe_copy",    "severity": "high",     "cwe": "CWE-120"},
    "gets":     {"category": "unsafe_copy",    "severity": "critical", "cwe": "CWE-120"},
    "wcscpy":   {"category": "unsafe_copy",    "severity": "critical", "cwe": "CWE-120"},
    # --- Format string ---
    "sprintf":  {"category": "format_string",  "severity": "critical", "cwe": "CWE-134"},
    "vsprintf": {"category": "format_string",  "severity": "critical", "cwe": "CWE-134"},
    "snprintf": {"category": "format_string",  "severity": "medium",   "cwe": "CWE-134"},
    "fprintf":  {"category": "format_string",  "severity": "medium",   "cwe": "CWE-134"},
    "printf":   {"category": "format_string",  "severity": "medium",   "cwe": "CWE-134"},
    # --- Heap operations ---
    "malloc":   {"category": "heap_operation", "severity": "medium",   "cwe": "CWE-416"},
    "calloc":   {"category": "heap_operation", "severity": "medium",   "cwe": "CWE-416"},
    "realloc":  {"category": "heap_operation", "severity": "high",     "cwe": "CWE-416"},
    "free":     {"category": "heap_operation", "severity": "high",     "cwe": "CWE-415"},
    # --- User input sources (taint sources) ---
    "scanf":    {"category": "user_input",     "severity": "high",     "cwe": "CWE-120"},
    "fscanf":   {"category": "user_input",     "severity": "high",     "cwe": "CWE-120"},
    "sscanf":   {"category": "user_input",     "severity": "high",     "cwe": "CWE-120"},
    "fgets":    {"category": "user_input",     "severity": "medium",   "cwe": "CWE-120"},
    "read":     {"category": "user_input",     "severity": "medium",   "cwe": "CWE-120"},
    "recv":     {"category": "user_input",     "severity": "high",     "cwe": "CWE-120"},
    "recvfrom": {"category": "user_input",     "severity": "high",     "cwe": "CWE-120"},
    # --- Command execution ---
    "system":   {"category": "command_exec",   "severity": "critical", "cwe": "CWE-78"},
    "popen":    {"category": "command_exec",   "severity": "critical", "cwe": "CWE-78"},
    "exec":     {"category": "command_exec",   "severity": "critical", "cwe": "CWE-78"},
    "execve":   {"category": "command_exec",   "severity": "critical", "cwe": "CWE-78"},
    "execvp":   {"category": "command_exec",   "severity": "critical", "cwe": "CWE-78"},
    # --- Windows-specific ---
    "CreateProcess":      {"category": "command_exec",   "severity": "critical", "cwe": "CWE-78"},
    "VirtualAlloc":       {"category": "heap_operation", "severity": "high",     "cwe": "CWE-119"},
    "VirtualProtect":     {"category": "heap_operation", "severity": "high",     "cwe": "CWE-119"},
    "WriteProcessMemory": {"category": "command_exec",   "severity": "critical", "cwe": "CWE-123"},
    # --- Network ---
    "socket":   {"category": "network",        "severity": "medium",   "cwe": "CWE-200"},
    "connect":  {"category": "network",        "severity": "medium",   "cwe": "CWE-200"},
    "bind":     {"category": "network",        "severity": "medium",   "cwe": "CWE-200"},
    "listen":   {"category": "network",        "severity": "medium",   "cwe": "CWE-200"},
    "accept":   {"category": "network",        "severity": "medium",   "cwe": "CWE-200"},
    "send":     {"category": "network",        "severity": "medium",   "cwe": "CWE-200"},
    "sendto":   {"category": "network",        "severity": "medium",   "cwe": "CWE-200"},
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class StaticFinding:
    """A single dangerous pattern found in the source code via AST query."""
    function_name: str    # enclosing function name
    line: int             # 1-indexed line number in original source
    pattern_type: str     # category from DANGEROUS_CALLS (e.g., "unsafe_copy")
    call_name: str        # the specific function call (e.g., "strcpy")
    severity: str         # "critical", "high", "medium"
    cwe: str              # CWE identifier
    context_snippet: str  # the source line containing the call


@dataclass
class PreTargetingResult:
    """Result of the static analysis pre-targeting pass."""
    findings: list[StaticFinding] = field(default_factory=list)
    focused_functions: dict[str, str] = field(default_factory=dict)  # name → code
    focused_code: str = ""                  # reconstructed code for the AI
    original_line_count: int = 0
    focused_line_count: int = 0
    reduction_percent: float = 0.0


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _find_enclosing_function(node):
    """Walk up the AST from a node to find the enclosing function_definition."""
    current = node
    while current is not None:
        if current.type == "function_definition":
            return current
        current = current.parent
    return None


def _get_function_name(func_node) -> str:
    """Extract the function name from a function_definition AST node."""
    declarator = func_node.child_by_field_name("declarator")
    if declarator:
        return _drill_to_identifier(declarator)
    return "<unknown>"


def _drill_to_identifier(node) -> str:
    """Recursively find the identifier name inside a declarator node."""
    if node.type == "identifier":
        return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text)
    for child in node.children:
        name = _drill_to_identifier(child)
        if name:
            return name
    return ""


def _extract_preamble(root_node, source_bytes: bytes) -> str:
    """
    Extract the non-function preamble: #include directives, struct/typedef
    declarations, global variables, #define macros, and enum definitions.
    These are needed for the AI to understand the types used in the
    dangerous functions.
    """
    preamble_parts = []
    for child in root_node.children:
        if child.type in (
            "preproc_include", "preproc_def", "preproc_ifdef",
            "preproc_ifndef", "preproc_if", "preproc_function_def",
            "type_definition", "struct_specifier", "enum_specifier",
            "declaration",  # global variable declarations
        ):
            text = source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
            preamble_parts.append(text)
    return "\n".join(preamble_parts)


def _node_text(node, source_bytes: bytes) -> str:
    """Get the source text of an AST node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_source(code: str) -> PreTargetingResult:
    """
    Parse C source code and extract only the functions containing dangerous
    patterns. Returns a focused code context for LLM analysis.

    This is the "Sniper Mode" pre-targeting engine. Instead of sending
    the entire codebase to the AI, we use tree-sitter AST queries to
    identify dangerous function calls (strcpy, malloc, system, etc.)
    and extract only the enclosing functions + the preamble.

    Args:
        code: The full C source code string.

    Returns:
        PreTargetingResult with focused_code containing only dangerous regions.
    """
    result = PreTargetingResult()

    if not code or not code.strip():
        return result

    result.original_line_count = len(code.splitlines())

    # Import tree-sitter lazily for graceful degradation
    try:
        import tree_sitter_c as tsc
        from tree_sitter import Language, Parser
    except ImportError:
        # If tree-sitter isn't available, return full code (no reduction)
        result.focused_code = code
        result.focused_line_count = result.original_line_count
        result.reduction_percent = 0.0
        return result

    # Parse the source
    c_language = Language(tsc.language())
    parser = Parser(c_language)
    code_bytes = code.encode("utf-8")
    tree = parser.parse(code_bytes)
    root = tree.root_node

    source_lines = code.splitlines()

    # Build the set of dangerous function names for fast lookup
    dangerous_names = set(DANGEROUS_CALLS.keys())

    # Walk the entire AST to find call_expression nodes targeting dangerous functions
    findings: list[StaticFinding] = []
    dangerous_func_nodes: dict[str, object] = {}  # func_name → AST node (deduped)

    _walk_for_calls(root, code_bytes, source_lines, dangerous_names, findings, dangerous_func_nodes)

    result.findings = findings

    if not findings:
        # No dangerous patterns found — return full code
        result.focused_code = code
        result.focused_line_count = result.original_line_count
        result.reduction_percent = 0.0
        return result

    # Also include `main` if it exists (entry point is always relevant)
    _ensure_main_included(root, code_bytes, dangerous_func_nodes)

    # Extract preamble (includes, structs, typedefs, globals)
    preamble = _extract_preamble(root, code_bytes)

    # Build focused code
    focused_parts = []

    if preamble.strip():
        focused_parts.append("// ===== PREAMBLE (includes, types, globals) =====")
        focused_parts.append(preamble)
        focused_parts.append("")

    # Add a summary comment so the AI knows this is pre-filtered
    category_counts: dict[str, int] = {}
    for f in findings:
        category_counts[f.pattern_type] = category_counts.get(f.pattern_type, 0) + 1

    summary_items = [f"{count}x {cat}" for cat, count in sorted(category_counts.items())]
    focused_parts.append(
        f"// ===== SNIPER MODE: {len(findings)} dangerous patterns detected "
        f"({', '.join(summary_items)}) ====="
    )
    focused_parts.append(
        f"// Extracted {len(dangerous_func_nodes)} functions from "
        f"{result.original_line_count} total lines"
    )
    focused_parts.append("")

    # Add each dangerous function
    for func_name, func_node in dangerous_func_nodes.items():
        func_text = _node_text(func_node, code_bytes)
        # Annotate which dangerous calls are inside this function
        func_findings = [f for f in findings if f.function_name == func_name]
        if func_findings:
            calls_str = ", ".join(sorted(set(f.call_name for f in func_findings)))
            focused_parts.append(f"// [SNIPER] Function '{func_name}' contains: {calls_str}")

        focused_parts.append(func_text)
        focused_parts.append("")
        result.focused_functions[func_name] = func_text

    result.focused_code = "\n".join(focused_parts)
    result.focused_line_count = len(result.focused_code.splitlines())

    if result.original_line_count > 0:
        result.reduction_percent = (
            (1.0 - result.focused_line_count / result.original_line_count) * 100.0
        )
        # Clamp to 0 if focused is somehow larger (e.g., annotations added)
        result.reduction_percent = max(0.0, result.reduction_percent)

    return result


def _walk_for_calls(
    node,
    source_bytes: bytes,
    source_lines: list[str],
    dangerous_names: set[str],
    findings: list[StaticFinding],
    dangerous_func_nodes: dict[str, object],
) -> None:
    """Recursively walk the AST looking for call_expression nodes to dangerous functions."""
    if node.type == "call_expression":
        # Get the function being called
        func_child = node.child_by_field_name("function")
        if func_child and func_child.type == "identifier":
            call_name = func_child.text.decode("utf-8") if isinstance(func_child.text, bytes) else str(func_child.text)

            if call_name in dangerous_names:
                info = DANGEROUS_CALLS[call_name]
                line_num = node.start_point[0] + 1  # 1-indexed

                # Find the enclosing function
                enclosing = _find_enclosing_function(node)
                func_name = _get_function_name(enclosing) if enclosing else "<global>"

                context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""

                findings.append(StaticFinding(
                    function_name=func_name,
                    line=line_num,
                    pattern_type=info["category"],
                    call_name=call_name,
                    severity=info["severity"],
                    cwe=info["cwe"],
                    context_snippet=context.strip(),
                ))

                # Track the enclosing function node for extraction
                if enclosing and func_name not in dangerous_func_nodes:
                    dangerous_func_nodes[func_name] = enclosing

    for child in node.children:
        _walk_for_calls(child, source_bytes, source_lines, dangerous_names, findings, dangerous_func_nodes)


def _ensure_main_included(root, source_bytes: bytes, dangerous_func_nodes: dict[str, object]) -> None:
    """Make sure main() is included in the extracted functions (it's always relevant as the entry point)."""
    if "main" in dangerous_func_nodes:
        return
    for child in root.children:
        if child.type == "function_definition":
            name = _get_function_name(child)
            if name == "main":
                dangerous_func_nodes["main"] = child
                return


def format_pretargeting_summary(result: PreTargetingResult) -> str:
    """
    Format a human-readable summary of the pre-targeting results
    for console output.
    """
    if not result.findings:
        return "No dangerous patterns detected. Full source sent to AI."

    lines = [
        f"Sniper Mode: {result.original_line_count} lines → {result.focused_line_count} lines "
        f"({result.reduction_percent:.0f}% reduction)",
        f"Findings: {len(result.findings)} dangerous patterns in {len(result.focused_functions)} functions",
    ]

    # Group by category
    categories: dict[str, list[str]] = {}
    for f in result.findings:
        cat = f.pattern_type
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(f"{f.call_name} (line {f.line})")

    for cat, calls in sorted(categories.items()):
        lines.append(f"  {cat}: {', '.join(calls)}")

    return "\n".join(lines)
