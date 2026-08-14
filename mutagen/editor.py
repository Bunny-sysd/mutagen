import difflib
import re
from typing import Optional

from rich.console import Console
from rich.syntax import Syntax

from mutagen.ast_validator import validate_c_source
from mutagen.reachability_checker import extract_vulnerable_function_scope

console = Console(force_terminal=True, force_jupyter=False)


class EditorScope:
    """Represents the isolated text buffer the agent is viewing and editing."""
    def __init__(self, name: str, body: str, start_line: int, end_line: int, scope_type: str = "function"):
        self.name = name
        self.body = body
        self.original_body = body
        self.start_line = start_line
        self.end_line = end_line
        self.scope_type = scope_type  # 'function' or 'window'

    @property
    def line_count(self) -> int:
        return len(self.body.splitlines())


class VirtualCodeEditor:
    """
    Virtual Code Editor & Scratchpad IDE for Mutagen Agents.
    
    Instead of monolithic full-file generation, this workspace isolates
    the vulnerable scope into an interactive text editor buffer where
    agents can make targeted modifications, review diffs, run AST pre-flight
    gates, and surgically commit verified changes back to the target file.
    """
    def __init__(self, source_code: str, language: str = "c", filename: str = "target.c"):
        self.source_code = source_code
        self.language = language.lower()
        self.filename = filename
        self.lines = source_code.splitlines()
        self.active_scope: Optional[EditorScope] = None
        self.history: list[str] = []

    def open_vulnerable_scope(self, target_line: int, window_padding: int = 30) -> EditorScope:
        """
        Extracts the enclosing function or adaptive window around target_line into the active editor buffer.
        """
        # 1. Try AST function-level extraction for C/C++
        if self.language == "c":
            scope_dict = extract_vulnerable_function_scope(self.source_code, target_line)
            if scope_dict and scope_dict.get("body"):
                self.active_scope = EditorScope(
                    name=scope_dict.get("name", "<unknown_function>"),
                    body=scope_dict["body"],
                    start_line=scope_dict["start_line"],
                    end_line=scope_dict["end_line"],
                    scope_type="function"
                )
                return self.active_scope

        # 2. Fallback: Adaptive Sliding Window centered on target_line
        total_lines = len(self.lines)
        if total_lines == 0:
            self.active_scope = EditorScope("whole_file", "", 1, 1, "window")
            return self.active_scope

        clamped_target = max(1, min(target_line, total_lines))
        start_idx = max(0, clamped_target - 1 - window_padding)
        end_idx = min(total_lines, clamped_target + window_padding)

        window_text = "\n".join(self.lines[start_idx:end_idx])
        self.active_scope = EditorScope(
            name=f"window_lines_{start_idx + 1}_{end_idx}",
            body=window_text,
            start_line=start_idx + 1,
            end_line=end_idx,
            scope_type="window"
        )
        return self.active_scope

    def apply_patch_candidate(self, new_code: str) -> bool:
        """
        Updates the active buffer with the agent's proposed fix.
        Strips code fences automatically.
        """
        if not self.active_scope or not new_code:
            return False

        from mutagen.engines.output_parser import strip_code_fences
        cleaned = strip_code_fences(new_code).strip()
        if not cleaned:
            return False

        self.history.append(self.active_scope.body)
        self.active_scope.body = cleaned
        return True

    def apply_search_replace(self, search_block: str, replace_block: str) -> bool:
        """
        Applies a precise search-and-replace within the active editor buffer.
        """
        if not self.active_scope:
            return False

        if search_block not in self.active_scope.body:
            # Try normalized whitespace match
            s_norm = re.sub(r'\s+', ' ', search_block.strip())
            curr_norm = re.sub(r'\s+', ' ', self.active_scope.body)
            if s_norm not in curr_norm:
                return False

        self.history.append(self.active_scope.body)
        self.active_scope.body = self.active_scope.body.replace(search_block, replace_block, 1)
        return True

    def run_pre_flight_check(self) -> tuple[bool, str]:
        """
        Runs Tree-sitter AST syntax and structure checks on the modified buffer.
        Returns: (is_valid: bool, error_message: str)
        """
        if not self.active_scope:
            return False, "No active editor scope open."

        if self.language != "c":
            return True, "Pre-flight skipped for non-C language."

        # Splice candidate into full codebase to validate AST in complete translation unit
        candidate_full_code = self.get_full_patched_code()
        ast_result = validate_c_source(candidate_full_code)
        if not ast_result.is_valid:
            err_msg = ", ".join(f"line {e.line}: {e.message}" for e in ast_result.errors)
            return False, err_msg

        return True, f"AST valid ({ast_result.node_count} nodes parsed)."

    def rollback(self) -> bool:
        """Reverts the active buffer to its previous state in history or original state."""
        if not self.active_scope:
            return False

        if self.history:
            self.active_scope.body = self.history.pop()
            return True
        else:
            self.active_scope.body = self.active_scope.original_body
            return True

    def get_full_patched_code(self) -> str:
        """
        Surgically splices the active editor buffer back into the original full file content.
        """
        if not self.active_scope:
            return self.source_code

        orig_lines = self.lines
        start_idx = self.active_scope.start_line - 1
        end_idx = self.active_scope.end_line

        # Splice the modified body lines
        patched_body_lines = self.active_scope.body.splitlines()
        full_lines = orig_lines[:start_idx] + patched_body_lines + orig_lines[end_idx:]
        return "\n".join(full_lines)

    def get_unified_diff(self) -> str:
        """
        Generates a unified diff comparing original source to the currently edited buffer.
        """
        full_patched = self.get_full_patched_code()
        orig_lines = self.source_code.splitlines(keepends=True)
        patched_lines = full_patched.splitlines(keepends=True)

        diff = list(difflib.unified_diff(
            orig_lines,
            patched_lines,
            fromfile=f"a/{self.filename}",
            tofile=f"b/{self.filename}",
            n=3
        ))
        return "".join(diff)

    def print_editor_status(self) -> None:
        """Prints a human-readable banner showing the active editor buffer and scope."""
        if not self.active_scope:
            return

        scope = self.active_scope
        console.print(f"[dim]╭── 📝 [VirtualCodeEditor] Active Buffer: {self.filename} ──────────────────────╮[/dim]")
        console.print(f"[dim]│ Scope: [bold cyan]{scope.name}[/bold cyan] ({scope.scope_type}) | Lines: {scope.start_line}-{scope.end_line} ({scope.line_count} lines)[/dim]")
        console.print("[dim]╰────────────────────────────────────────────────────────────────────────╯[/dim]")

    def print_diff_preview(self) -> None:
        """Prints a rich colorized diff preview of the modifications."""
        diff_str = self.get_unified_diff()
        if not diff_str:
            console.print("[dim]  [VirtualCodeEditor] No changes in editor buffer.[/dim]")
            return

        console.print("[bold green]  ✓ [VirtualCodeEditor] Generated Patch Diff Preview:[/bold green]")
        # Print first 20 lines of diff for terminal brevity
        diff_lines = diff_str.splitlines()
        preview = "\n".join(diff_lines[:25])
        if len(diff_lines) > 25:
            preview += f"\n... ({len(diff_lines) - 25} more diff lines)"

        syntax = Syntax(preview, "diff", theme="monokai", line_numbers=False)
        console.print(syntax)
