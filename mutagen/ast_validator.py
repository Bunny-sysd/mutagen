"""
Neuro-Symbolic AST Validation Layer for Mutagen.

Uses tree-sitter to parse AI-generated C patches into an Abstract Syntax Tree (AST)
before compilation. This catches structural hallucinations (missing braces, broken
syntax, impossible control flow) instantly — no GCC subprocess needed.

Architecture:
    AI patch_code → validate_c_source() → ASTValidationResult
        ├── VALID   → proceed to GCC compilation
        └── INVALID → feed structured errors back to AI, skip GCC entirely
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ASTError:
    """A single structural error detected in the AST."""
    line: int          # 1-indexed line number
    column: int        # 0-indexed column offset
    message: str       # Human-readable description
    node_type: str     # tree-sitter node type (e.g. "ERROR", "MISSING")
    context: str = ""  # The source line containing the error


@dataclass
class ASTValidationResult:
    """Result of neuro-symbolic AST validation."""
    is_valid: bool
    errors: list[ASTError] = field(default_factory=list)
    functions_found: list[str] = field(default_factory=list)
    has_main: bool = False
    node_count: int = 0


def _count_nodes(node) -> int:
    """Recursively count all nodes in the AST."""
    count = 1
    for child in node.children:
        count += _count_nodes(child)
    return count


def _collect_errors(node, source_lines: list[str], errors: list[ASTError]) -> None:
    """Walk the AST and collect all ERROR and MISSING nodes with context."""
    if node.type == "ERROR":
        line_num = node.start_point[0] + 1  # tree-sitter is 0-indexed
        col = node.start_point[1]
        context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""
        errors.append(ASTError(
            line=line_num,
            column=col,
            message=f"Syntax error: unexpected or malformed code at line {line_num}, column {col}",
            node_type="ERROR",
            context=context.rstrip(),
        ))
    elif node.is_missing:
        line_num = node.start_point[0] + 1
        col = node.start_point[1]
        context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""
        expected_type = node.type  # e.g. ";" or "}" or ")"
        errors.append(ASTError(
            line=line_num,
            column=col,
            message=f"Missing expected token '{expected_type}' at line {line_num}, column {col}",
            node_type="MISSING",
            context=context.rstrip(),
        ))

    for child in node.children:
        _collect_errors(child, source_lines, errors)


def _extract_functions(node) -> list[str]:
    """Extract all top-level function definition names from the AST."""
    functions = []
    for child in node.children:
        if child.type == "function_definition":
            # The function name is in the declarator
            declarator = child.child_by_field_name("declarator")
            if declarator:
                name = _extract_declarator_name(declarator)
                if name:
                    functions.append(name)
    return functions


def _extract_declarator_name(node) -> str | None:
    """Recursively drill into declarator nodes to find the function identifier name."""
    if node.type == "identifier":
        return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text)
    # For pointer declarators like *main, function_declarator like main(...)
    for child in node.children:
        name = _extract_declarator_name(child)
        if name:
            return name
    return None


def _check_orphaned_else(node, errors: list[ASTError], source_lines: list[str]) -> None:
    """
    Check for orphaned 'else' clauses that aren't children of an 'if_statement'.
    In a correct AST, 'else' is always inside an if_statement node.
    An orphaned else at the top level of a compound_statement indicates broken control flow.
    """
    if node.type == "else_clause":
        # An else_clause should always be a child of an if_statement
        parent = node.parent
        if parent and parent.type != "if_statement":
            line_num = node.start_point[0] + 1
            col = node.start_point[1]
            context = source_lines[node.start_point[0]] if node.start_point[0] < len(source_lines) else ""
            errors.append(ASTError(
                line=line_num,
                column=col,
                message=f"Orphaned 'else' clause at line {line_num} — not connected to any 'if' statement",
                node_type="CFG_ORPHAN",
                context=context.rstrip(),
            ))

    for child in node.children:
        _check_orphaned_else(child, errors, source_lines)


def validate_c_source(code: str) -> ASTValidationResult:
    """
    Parse C source code using tree-sitter and validate its structural integrity.

    This performs neuro-symbolic pre-compilation checks:
    1. Parse code into AST — detect ERROR/MISSING nodes (hallucinated syntax)
    2. Extract function definitions — verify at least one exists
    3. Basic CFG checks — orphaned else, function body integrity
    4. Return structured result for the self-healing loop

    Args:
        code: The C source code string to validate.

    Returns:
        ASTValidationResult with is_valid=True if no structural errors found.
    """
    # Handle empty/whitespace-only input
    if not code or not code.strip():
        return ASTValidationResult(
            is_valid=False,
            errors=[ASTError(
                line=1, column=0,
                message="Empty or whitespace-only source code",
                node_type="EMPTY_INPUT",
            )],
        )

    # Import tree-sitter lazily so the rest of mutagen works even if
    # tree-sitter isn't installed (graceful degradation)
    try:
        import tree_sitter_c as tsc
        from tree_sitter import Language, Parser
    except ImportError:
        # If tree-sitter is not installed, skip validation (don't block the pipeline)
        return ASTValidationResult(is_valid=True, node_count=0)

    # Parse the code
    c_language = Language(tsc.language())
    parser = Parser(c_language)

    code_bytes = code.encode("utf-8") if isinstance(code, str) else code
    tree = parser.parse(code_bytes)
    root = tree.root_node

    source_lines = code.split("\n")

    # 1. Count nodes
    node_count = _count_nodes(root)

    # 2. Collect all ERROR and MISSING nodes
    errors: list[ASTError] = []
    _collect_errors(root, source_lines, errors)

    # 3. Extract function definitions
    functions = _extract_functions(root)
    has_main = "main" in functions

    # 4. Check if there's at least one function definition
    #    (a valid C translation unit for our purposes must define at least one function)
    if not functions and not errors:
        # Only flag this if there are no other errors already (avoid noise)
        errors.append(ASTError(
            line=1, column=0,
            message="No function definitions found in translation unit",
            node_type="NO_FUNCTIONS",
        ))

    # 5. CFG integrity: check for orphaned else clauses
    _check_orphaned_else(root, errors, source_lines)

    is_valid = len(errors) == 0

    return ASTValidationResult(
        is_valid=is_valid,
        errors=errors,
        functions_found=functions,
        has_main=has_main,
        node_count=node_count,
    )


def format_validation_errors(result: ASTValidationResult) -> str:
    """
    Format AST validation errors into a human-readable string suitable
    for feeding back to the AI engine as self-healing context.

    This gives the AI precise, structured information about what went wrong
    so it can fix the hallucination on the next attempt.
    """
    if result.is_valid:
        return "AST validation passed. No structural errors detected."

    lines = [
        "NEURO-SYMBOLIC PRE-COMPILATION VALIDATION FAILED",
        f"Errors detected: {len(result.errors)}",
        f"Functions found: {result.functions_found or 'none'}",
        "",
    ]

    for i, err in enumerate(result.errors, 1):
        lines.append(f"  [{i}] {err.message}")
        if err.context:
            lines.append(f"      Source: {err.context}")
        lines.append("")

    lines.append(
        "INSTRUCTIONS: Fix the above structural errors in your C patch. "
        "Ensure all braces are matched, all statements end with semicolons, "
        "and the code forms a valid C translation unit with at least one function definition."
    )

    return "\n".join(lines)
