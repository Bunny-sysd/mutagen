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
    # --- Format & Bit-Depth Transformations ---
    "png_image_finish_read":  {"category": "format_transformation", "severity": "high", "cwe": "CWE-681"},
    "png_set_IHDR":           {"category": "format_transformation", "severity": "medium", "cwe": "CWE-190"},
    "png_get_IHDR":           {"category": "format_transformation", "severity": "medium", "cwe": "CWE-190"},
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

def analyze_source(code: str, target_functions: list[str] = None) -> PreTargetingResult:
    """
    Parse C source code and extract only the functions containing dangerous
    patterns or matching specific target functions. Returns a focused code context for LLM analysis.

    This is the "Sniper Mode" pre-targeting engine. Instead of sending
    the entire codebase to the AI, we use tree-sitter AST queries to
    identify dangerous function calls (strcpy, malloc, system, etc.)
    or specific CVE target functions and extract only those enclosing functions + the preamble.

    Args:
        code: The full C source code string.
        target_functions: Optional list of target function names (e.g. from CVE metadata).

    Returns:
        PreTargetingResult with focused_code containing only dangerous/targeted regions.
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

    # Walk the entire AST to find dangerous semantic patterns and calls
    findings: list[StaticFinding] = []
    dangerous_func_nodes: dict[str, object] = {}  # func_name → AST node (deduped)
    seen_findings: set[tuple[int, str]] = set()

    _walk_for_calls(root, code_bytes, source_lines, dangerous_names, findings, dangerous_func_nodes, seen_findings)
    _ensure_main_included(root, code_bytes, dangerous_func_nodes)

    # Filter out invalid function identifiers/keywords (e.g. 'if', 'for')
    c_keywords = {"if", "for", "while", "switch", "return", "sizeof", "else", "case", "default", "do", "typedef", "struct", "enum", "union", "<unknown>"}
    dangerous_func_nodes = {k: v for k, v in dangerous_func_nodes.items() if k not in c_keywords}

    result.findings = [f for f in findings if f.function_name not in c_keywords]

    # Find all AST functions for target-guided search
    all_ast_funcs: dict[str, object] = {}
    def _collect_funcs(n):
        if n.type == "function_definition":
            fn = _get_function_name(n)
            if fn and fn not in c_keywords:
                all_ast_funcs[fn] = n
        for ch in n.children:
            _collect_funcs(ch)
    _collect_funcs(root)

    # Populate focused_functions map
    for func_name, func_node in dangerous_func_nodes.items():
        result.focused_functions[func_name] = _node_text(func_node, code_bytes)

    if result.original_line_count <= 20:
        # For small files (under 20 lines), preserve full source code.
        result.focused_code = code
        result.focused_line_count = result.original_line_count
        result.reduction_percent = 0.0
        return result

    # Extract preamble (includes, structs, typedefs, globals)
    preamble = _extract_preamble(root, code_bytes)

    # Determine which functions to focus on
    selected_funcs = []
    target_match_names = set()
    if target_functions:
        clean_targets = [tf.strip() for tf in target_functions if tf and tf.strip() not in ("target_function", "")]
        for tf in clean_targets:
            for fn, node in all_ast_funcs.items():
                fn_l = fn.lower()
                tf_l = tf.lower()
                # Strict exact match or strict underscore-delimited prefix match
                if fn_l == tf_l or fn_l.startswith(tf_l + "_") or tf_l.startswith(fn_l + "_"):
                    if fn not in target_match_names:
                        target_match_names.add(fn)
                        selected_funcs.append((fn, node))

    if not selected_funcs:
        # Fallback to dangerous function priority sorting
        def _func_priority(item: tuple[str, object]) -> int:
            fname, _ = item
            func_f = [f for f in result.findings if f.function_name == fname]
            score = 0
            for f in func_f:
                if any(c in f.cwe for c in ["787", "119", "120", "122", "125", "416", "415", "78"]):
                    score += 10
                elif "190" in f.cwe or "681" in f.cwe or "134" in f.cwe:
                    score += 5
                else:
                    score += 2
            # Prioritize standard entry points and harness test interfaces
            if fname.lower() in ("main", "target_function", "entry", "llvm_fuzzertestoneinput", "fuzz_target", "process_input", "parse_data"):
                score += 15
            return score

        sorted_funcs = sorted(dangerous_func_nodes.items(), key=_func_priority, reverse=True)
        # Cap to top 3 most critical functions to maintain true token efficiency
        selected_funcs = sorted_funcs[:3] if len(sorted_funcs) > 3 else sorted_funcs
    else:
        # Cap explicit target matches to top 3
        selected_funcs = selected_funcs[:3]

    # Build focused code
    focused_parts = []

    # Limit preamble lines to essential headers (max 35 lines)
    preamble_lines = preamble.splitlines()
    if len(preamble_lines) > 35:
        compact_preamble = [line for line in preamble_lines if any(line.strip().startswith(kw) for kw in ["#include", "typedef", "struct", "#define", "using", "import", "enum"])]
        preamble = "\n".join(compact_preamble[:35])

    if preamble.strip():
        focused_parts.append("// ===== PREAMBLE (includes, types, globals) =====")
        focused_parts.append(preamble)
        focused_parts.append("")

    # Add a summary comment
    if target_match_names:
        focused_parts.append(
            f"// ===== SNIPER MODE: Targeted {len(selected_funcs)} CVE-relevant function(s): {', '.join([f[0] for f in selected_funcs])} ====="
        )
    else:
        category_counts: dict[str, int] = {}
        for f in result.findings:
            category_counts[f.pattern_type] = category_counts.get(f.pattern_type, 0) + 1
        summary_items = [f"{count}x {cat}" for cat, count in sorted(category_counts.items())]
        focused_parts.append(
            f"// ===== SNIPER MODE: {len(result.findings)} dangerous patterns detected "
            f"({', '.join(summary_items)}) ====="
        )
    focused_parts.append(
        f"// Extracted {len(selected_funcs)} function(s) from "
        f"{result.original_line_count} total lines"
    )
    focused_parts.append("")

    # Add each selected function (with surgical slicing for massive functions > 150 lines)
    for func_name, func_node in selected_funcs:
        func_text = _node_text(func_node, code_bytes)
        f_lines = func_text.splitlines()
        start_line = (getattr(func_node, "start_point", (0, 0))[0] + 1) if hasattr(func_node, "start_point") else 1
        func_findings = [f for f in result.findings if f.function_name == func_name]

        if func_findings:
            calls_str = ", ".join(sorted(set(f.call_name for f in func_findings)))
            focused_parts.append(f"// [SNIPER - ORIGINAL SOURCE LINE {start_line}] Function '{func_name}' contains: {calls_str}")
        else:
            focused_parts.append(f"// [SNIPER - ORIGINAL SOURCE LINE {start_line}] Function '{func_name}'")

        if len(f_lines) > 150:
            # Preserve signature/declarations + key data-flow window to stay token-efficient
            sliced = f_lines[:30] + [f"    // ... [Sniper Mode: {len(f_lines)-80} internal lines trimmed for token efficiency] ..."] + f_lines[-50:]
            focused_func_code = "\n".join(sliced)
        else:
            focused_func_code = func_text

        focused_parts.append(focused_func_code)
        focused_parts.append("")
        result.focused_functions[func_name] = func_text

    result.focused_code = "\n".join(focused_parts)
    result.focused_line_count = len(result.focused_code.splitlines())

    if result.original_line_count > 0:
        result.reduction_percent = (
            (1.0 - result.focused_line_count / result.original_line_count) * 100.0
        )
        result.reduction_percent = max(0.0, result.reduction_percent)

    return result


def _walk_for_calls(
    node,
    source_bytes: bytes,
    source_lines: list[str],
    dangerous_names: set[str],
    findings: list[StaticFinding],
    dangerous_func_nodes: dict[str, object],
    seen_findings: set[tuple[int, str]] = None,
) -> None:
    """
    Recursively walk the AST looking for:
    1. Known dangerous function call expressions
    2. Dynamic buffer subscript writes (e.g. arr[i] = ...)
    3. Dynamic pointer dereference writes (e.g. *ptr = ...)
    4. Dynamic size & arithmetic calculations (*, <<, sizeof)
    5. Dynamic external input entry points & buffer parameters
    """
    if seen_findings is None:
        seen_findings = set()

    def _add_finding(f: StaticFinding, enclosing_node=None):
        key = (f.line, f.cwe)
        if key not in seen_findings:
            seen_findings.add(key)
            findings.append(f)
        if enclosing_node and f.function_name != "<global>" and f.function_name not in dangerous_func_nodes:
            dangerous_func_nodes[f.function_name] = enclosing_node

    # 1. Check call expressions
    if node.type == "call_expression":
        func_child = node.child_by_field_name("function")
        if func_child and func_child.type == "identifier":
            call_name = func_child.text.decode("utf-8") if isinstance(func_child.text, bytes) else str(func_child.text)

            if call_name in dangerous_names:
                info = DANGEROUS_CALLS[call_name]
                line_num = node.start_point[0] + 1
                enclosing = _find_enclosing_function(node)
                func_name = _get_function_name(enclosing) if enclosing else "<global>"
                context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""

                _add_finding(StaticFinding(
                    function_name=func_name,
                    line=line_num,
                    pattern_type=info["category"],
                    call_name=call_name,
                    severity=info["severity"],
                    cwe=info["cwe"],
                    context_snippet=context.strip(),
                ), enclosing)

            elif any(sub in call_name.lower() for sub in ["alloc", "malloc", "calloc", "realloc", "free", "quantize", "transform"]):
                line_num = node.start_point[0] + 1
                enclosing = _find_enclosing_function(node)
                func_name = _get_function_name(enclosing) if enclosing else "<global>"
                context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""

                _add_finding(StaticFinding(
                    function_name=func_name,
                    line=line_num,
                    pattern_type="heap_operation" if "alloc" in call_name.lower() or "free" in call_name.lower() else "format_transformation",
                    call_name=call_name,
                    severity="high",
                    cwe="CWE-416" if "free" in call_name.lower() else "CWE-119",
                    context_snippet=context.strip(),
                ), enclosing)
            else:
                # Dynamic AST heuristic: call passing pointer arithmetic or subscript expression
                has_ptr_op = any(child.type in ("pointer_expression", "subscript_expression") for child in node.children)
                if has_ptr_op and len(node.children) > 1:
                    enclosing = _find_enclosing_function(node)
                    func_name = _get_function_name(enclosing) if enclosing else "<global>"
                    line_num = node.start_point[0] + 1
                    context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""

                    _add_finding(StaticFinding(
                        function_name=func_name,
                        line=line_num,
                        pattern_type="custom_ptr_arithmetic",
                        call_name=call_name,
                        severity="medium",
                        cwe="CWE-119",
                        context_snippet=context.strip(),
                    ), enclosing)

    # 2. Check dynamic assignment expressions (buffer & pointer writes)
    elif node.type == "assignment_expression":
        left_child = node.child_by_field_name("left")
        if left_child:
            if left_child.type == "subscript_expression":
                # Dynamic array / buffer write: e.g. dest[i] = ... or row[x] = ...
                enclosing = _find_enclosing_function(node)
                func_name = _get_function_name(enclosing) if enclosing else "<global>"
                line_num = node.start_point[0] + 1
                context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""

                _add_finding(StaticFinding(
                    function_name=func_name,
                    line=line_num,
                    pattern_type="dynamic_buffer_write",
                    call_name="[subscript_write]",
                    severity="high",
                    cwe="CWE-787",
                    context_snippet=context.strip(),
                ), enclosing)

            elif left_child.type == "pointer_expression":
                # Dynamic pointer dereference write: e.g. *ptr = ...
                enclosing = _find_enclosing_function(node)
                func_name = _get_function_name(enclosing) if enclosing else "<global>"
                line_num = node.start_point[0] + 1
                context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""

                _add_finding(StaticFinding(
                    function_name=func_name,
                    line=line_num,
                    pattern_type="dynamic_ptr_deref_write",
                    call_name="*ptr=",
                    severity="high",
                    cwe="CWE-119",
                    context_snippet=context.strip(),
                ), enclosing)

    # 3. Check dynamic size arithmetic and bitwise quantization transforms
    elif node.type == "binary_expression":
        op_child = node.child_by_field_name("operator")
        op_str = op_child.text.decode("utf-8") if op_child and isinstance(op_child.text, bytes) else (str(op_child.text) if op_child else "")
        if op_str in ("<<", ">>"):
            # Bitwise transform or shift inside functions
            enclosing = _find_enclosing_function(node)
            if enclosing:
                func_name = _get_function_name(enclosing)
                line_num = node.start_point[0] + 1
                context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""
                _add_finding(StaticFinding(
                    function_name=func_name,
                    line=line_num,
                    pattern_type="dynamic_data_transformation",
                    call_name=f"shift_{op_str}",
                    severity="medium",
                    cwe="CWE-681",
                    context_snippet=context.strip(),
                ), enclosing)

    # 4. Check function parameters for dynamic buffer and taint entry points
    elif node.type == "function_definition":
        declarator = node.child_by_field_name("declarator")
        func_name = _get_function_name(node)
        if declarator and func_name not in dangerous_func_nodes:
            # Check if function takes pointer parameters or buffer lengths
            params = node.child_by_field_name("parameters")
            if not params:
                # Look for parameter_list inside declarator
                for child in node.children:
                    if child.type == "parameter_list":
                        params = child
                        break
            if params:
                param_text = _node_text(params, source_bytes)
                if "*" in param_text and any(k in param_text for k in ["len", "size", "count", "num", "bytes", "width", "height", "row"]):
                    line_num = node.start_point[0] + 1
                    context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""
                    _add_finding(StaticFinding(
                        function_name=func_name,
                        line=line_num,
                        pattern_type="dynamic_input_entry",
                        call_name="param_buffer_in",
                        severity="medium",
                        cwe="CWE-120",
                        context_snippet=context.strip(),
                    ), node)

    for child in node.children:
        _walk_for_calls(child, source_bytes, source_lines, dangerous_names, findings, dangerous_func_nodes, seen_findings)


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
