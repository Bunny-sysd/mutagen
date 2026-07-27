import os
import re
import subprocess

from rich.console import Console

console = Console(force_terminal=True, force_jupyter=False)

def scan_workspace_symbols(workspace_dir: str) -> dict:
    """Scans workspace source files and extracts function declarations, definitions, structs, and inclusions."""
    symbols = {
        "files": {},
        "functions": {},
        "structs": [],
        "includes": set(),
    }

    if not os.path.exists(workspace_dir):
        return symbols

    supported_exts = (".c", ".cpp", ".h", ".hpp", ".go", ".java", ".cs", ".rs", ".py")

    for root, _, files in os.walk(workspace_dir):
        for file in files:
            if file.endswith(supported_exts):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, workspace_dir)

                try:
                    with open(full_path, encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Extract C/C++ function definitions
                    func_matches = re.findall(r'(?:[a-zA-Z_]\w*\s+)+([a-zA-Z_]\w*)\s*\([^;{]*\)\s*\{', content)
                    for fn in func_matches:
                        if fn not in ("if", "while", "for", "switch", "return"):
                            symbols["functions"][fn] = rel_path

                    # Extract structs / classes
                    struct_matches = re.findall(r'(?:struct|class|enum|interface)\s+([a-zA-Z_]\w*)', content)
                    symbols["structs"].extend(struct_matches)

                    # Extract includes
                    inc_matches = re.findall(r'#include\s*[<"]([^>"]+)[>"]', content)
                    for inc in inc_matches:
                        symbols["includes"].add(inc)

                    symbols["files"][rel_path] = {
                        "lines": len(content.splitlines()),
                        "functions": [fn for fn in func_matches if fn not in ("if", "while", "for", "switch", "return")],
                    }
                except Exception:
                    pass

    symbols["includes"] = list(symbols["includes"])
    symbols["structs"] = list(set(symbols["structs"]))
    return symbols

def get_git_branch_diff(workspace_dir: str) -> dict:
    """Detects current git branch and list of modified files compared to master."""
    branch_info = {"current_branch": "unknown", "modified_files": []}
    if not os.path.exists(os.path.join(workspace_dir, ".git")):
        return branch_info

    try:
        res_branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, cwd=workspace_dir, timeout=5)
        if res_branch.returncode == 0:
            branch_info["current_branch"] = res_branch.stdout.strip()

        res_diff = subprocess.run(["git", "diff", "--name-only", "origin/master"], capture_output=True, text=True, cwd=workspace_dir, timeout=5)
        if res_diff.returncode == 0:
            branch_info["modified_files"] = [f.strip() for f in res_diff.stdout.splitlines() if f.strip()]
    except Exception:
        pass

    return branch_info

def build_call_graph(workspace_dir: str) -> dict:
    """Builds a project call graph and dependency structure summary."""
    symbols = scan_workspace_symbols(workspace_dir)
    git_info = get_git_branch_diff(workspace_dir)

    graph = {
        "workspace": workspace_dir,
        "total_files": len(symbols["files"]),
        "symbols": symbols,
        "git": git_info,
    }
    return graph

def summarize_project_graph(workspace_dir: str) -> str:
    """Produces a clean text summary of the project call graph for AI prompt context."""
    graph = build_call_graph(workspace_dir)
    if graph["total_files"] == 0:
        return "No multi-file workspace graph available."

    summary_lines = [
        f"Workspace Structure ({graph['total_files']} files):",
        f"Git Branch: {graph['git']['current_branch']}",
    ]
    if graph['git']['modified_files']:
        summary_lines.append(f"Modified Branch Files: {', '.join(graph['git']['modified_files'])}")

    summary_lines.append("Key Workspace Functions:")
    for fn, rel_file in list(graph['symbols']['functions'].items())[:15]:
        summary_lines.append(f"  - {fn}() defined in {rel_file}")

    return "\n".join(summary_lines)
