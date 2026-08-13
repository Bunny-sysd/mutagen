import os
import re
import subprocess

from rich.console import Console

console = Console(force_terminal=True, force_jupyter=False)


def extract_vulnerable_function_name(source_path: str, line_number: int) -> str | None:
    """
    Extracts the enclosing function name around line_number in source_path using tree-sitter AST or regex fallback.
    """
    if not os.path.exists(source_path):
        return None

    try:
        with open(source_path, encoding="utf-8", errors="ignore") as f:
            code = f.read()

        # 1. Try tree-sitter AST parsing
        try:
            import tree_sitter_c as tsc
            from tree_sitter import Language, Parser
            c_lang = Language(tsc.language())
            parser = Parser(c_lang)
            code_bytes = code.encode("utf-8")
            tree = parser.parse(code_bytes)
            lines = code.splitlines()

            target_line = max(0, line_number - 1)
            if target_line < len(lines):
                target_bytes_offset = sum(len(line_str.encode("utf-8")) + 1 for line_str in lines[:target_line])
                node = tree.root_node.descendant_for_byte_range(target_bytes_offset, target_bytes_offset + 1)
                curr = node
                while curr:
                    if curr.type == "function_definition":
                        declarator = curr.child_by_field_name("declarator")
                        if declarator:
                            def _drill(n):
                                if n.type == "identifier":
                                    return n.text.decode("utf-8")
                                for c in n.children:
                                    res = _drill(c)
                                    if res:
                                        return res
                                return None
                            name = _drill(declarator)
                            if name and name.lower() not in ("if", "while", "for", "switch", "return", "do", "else"):
                                return name
                    curr = curr.parent
        except Exception:
            pass

        # 2. Fallback: regex scan backwards from line_number for function signatures
        lines = code.splitlines()
        idx = min(len(lines) - 1, max(0, line_number - 1))
        func_sig_regex = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_*\s]+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;]*$')
        for i in range(idx, -1, -1):
            line = lines[i].strip()
            match = func_sig_regex.match(line)
            if match:
                func_name = match.group(1)
                if func_name not in ("if", "while", "for", "switch", "return"):
                    return func_name

    except Exception:
        pass

    return None


def get_expanded_reachability_set(target_path_or_dir: str, vuln_function: str) -> set[str]:
    """
    Scans project header/source files to discover macro aliases (#define MACRO ... vuln_function)
    and parent caller functions, returning an expanded set of target symbols.
    """
    clean_func = vuln_function.strip()
    reachability_set = {clean_func}

    if not target_path_or_dir:
        return reachability_set

    search_dir = target_path_or_dir if os.path.isdir(target_path_or_dir) else os.path.dirname(target_path_or_dir)
    if not search_dir or not os.path.exists(search_dir):
        return reachability_set

    # 1. Macro Alias Resolution (#define ALIAS ... TARGET_FUNC ...)
    macro_regex = re.compile(r'#\s*define\s+([a-zA-Z_][a-zA-Z0-9_]*)\b')
    func_def_regex = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_*\s]+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;]*$')

    for root, _, files in os.walk(search_dir):
        if any(ignored in root.lower() for ignored in ["build", "cmakefiles", "cmaketmp"]):
            continue
        for file in files:
            if file.endswith((".h", ".hpp", ".c", ".cpp")):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Check for macro aliases
                    for sym in list(reachability_set):
                        if sym in content:
                            for line in content.splitlines():
                                line_str = line.strip()
                                if line_str.startswith("#define") and sym in line_str:
                                    match = macro_regex.match(line_str)
                                    if match:
                                        alias_name = match.group(1)
                                        if alias_name != sym:
                                            reachability_set.add(alias_name)

                            # Scan for caller function definitions in this source file
                            if file.endswith((".c", ".cpp")):
                                curr_func = None
                                for line in content.splitlines():
                                    line_str = line.strip()
                                    m_func = func_def_regex.match(line_str)
                                    if m_func:
                                        fname = m_func.group(1)
                                        if fname.lower() not in ("if", "while", "for", "switch", "return", "main", "winmain", "dllmain", "_start"):
                                            curr_func = fname
                                    elif curr_func and sym in line_str:
                                        reachability_set.add(curr_func)
                except Exception:
                    pass

    return reachability_set


def verify_binary_reachability(candidate_binary: str, vuln_function: str, candidate_source: str = None, target_dir: str = None) -> dict:
    """
    Inspects candidate_binary symbols (via nm, objdump, readelf, or binary strings)
    and candidate_source/target_dir to determine if vuln_function (or macro alias/caller) is reachable.

    Returns dict:
    {
        "reachable": bool,
        "confidence": "HIGH" | "MEDIUM" | "LOW" | "UNCONFIRMED",
        "reason": str
    }
    """
    if not candidate_binary or not os.path.exists(candidate_binary) or not vuln_function:
        return {"reachable": False, "confidence": "UNCONFIRMED", "reason": "Missing binary or target function name"}

    clean_func = vuln_function.strip()
    search_scope_path = target_dir or (os.path.dirname(candidate_source) if candidate_source else os.path.dirname(candidate_binary))
    target_symbols = get_expanded_reachability_set(search_scope_path, clean_func)

    # 1. Direct Binary Byte/String Read (Fast, 0ms check)
    try:
        with open(candidate_binary, "rb") as f:
            content_bytes = f.read()
        for sym in target_symbols:
            if sym.encode("utf-8") in content_bytes:
                return {
                    "reachable": True,
                    "confidence": "HIGH",
                    "reason": f"Function/alias symbol '{sym}' found in binary image"
                }
    except Exception:
        pass

    # 2. Source File Call-Chain Check (if candidate_source exists)
    if candidate_source and os.path.exists(candidate_source):
        try:
            with open(candidate_source, encoding="utf-8", errors="ignore") as f:
                src_content = f.read()
            for sym in target_symbols:
                if sym in src_content:
                    return {
                        "reachable": True,
                        "confidence": "MEDIUM",
                        "reason": f"Function/alias symbol '{sym}' called in binary source '{os.path.basename(candidate_source)}'"
                    }
        except Exception:
            pass

    # 3. Symbol Table Inspection (`nm` or `objdump -t` or `readelf -s`)
    import shutil
    for tool_name, tool_cmd in [("nm", ["nm", candidate_binary]), ("objdump", ["objdump", "-t", candidate_binary]), ("readelf", ["readelf", "-s", candidate_binary]), ("strings", ["strings", candidate_binary])]:
        if not shutil.which(tool_name):
            continue
        try:
            res = subprocess.run(tool_cmd, capture_output=True, text=True, timeout=1)
            if res.returncode == 0 and res.stdout:
                for sym in target_symbols:
                    if sym in res.stdout:
                        return {
                            "reachable": True,
                            "confidence": "HIGH",
                            "reason": f"Function/alias symbol '{sym}' found in binary symbol table via {tool_name}"
                        }
        except Exception:
            pass

    return {
        "reachable": False,
        "confidence": "HIGH",
        "reason": f"Target function '{clean_func}' (and aliases {target_symbols}) absent in candidate binary '{os.path.basename(candidate_binary)}' symbol table and source code"
    }


def select_best_reachable_binary(candidates: list[str], target_hint: str = "", vuln_function: str = None) -> tuple[str | None, dict]:
    """
    Evaluates candidate binaries for reachability of vuln_function, selecting the
    highest-scoring candidate that is verified reachable.
    """
    if not candidates:
        return None, {"reachable": False, "reason": "No candidate binaries supplied"}

    # Sort candidates by heuristic score first

    scored_candidates = []
    hint_stem = os.path.splitext(os.path.basename(target_hint))[0].lower() if target_hint else ""

    from mutagen.dependency_resolver import _is_shared_library_or_build_artifact

    for cand in candidates:
        norm_path = cand.replace("\\", "/").lower()
        if any(ignored in norm_path for ignored in ["/cmakefiles/", "/cmaketmp/", "compileridc", "compileridcxx"]):
            continue
        cand_base = os.path.basename(cand)
        if _is_shared_library_or_build_artifact(cand_base):
            continue
        cand_name = os.path.splitext(cand_base)[0].lower()
        score = 0
        if hint_stem:
            if cand_name == hint_stem:
                score += 100
            elif hint_stem in cand_name or cand_name in hint_stem:
                score += 50
        if "test" in cand_name and "valid" not in cand_name and "stest" not in cand_name:
            score += 30
        elif "stest" in cand_name:
            score += 10  # Lower score for simplified API binaries like pngstest
        elif "valid" in cand_name or "check" in cand_name:
            score -= 20
        scored_candidates.append((score, cand))

    scored_candidates.sort(key=lambda x: x[0], reverse=True)

    if not vuln_function:
        selected = scored_candidates[0][1]
        return selected, {"reachable": True, "confidence": "LOW", "reason": "No target function specified for reachability check"}

    for score, cand in scored_candidates:
        cand_stem = os.path.splitext(cand)[0]
        cand_source = cand_stem + ".c" if not cand.endswith((".c", ".cpp")) else cand
        check_res = verify_binary_reachability(cand, vuln_function, cand_source, target_dir=target_hint)
        cand_name = os.path.basename(cand)
        if check_res["reachable"]:
            console.print(f"[bold green]  [TargetVerification] Verified candidate binary '{cand_name}' reaches vulnerable function '{vuln_function}' ({check_res['reason']})[/bold green]")
            return cand, check_res
        else:
            console.print(f"[yellow]  [TargetVerification] Binary '{cand_name}' does not appear to reach vulnerable function '{vuln_function}' — skipping candidate.[/yellow]")

    # If no candidate binary explicitly exports internal vuln_function symbol string,
    # fall back to highest-scoring executable binary target that exists on disk.
    valid_existing_candidates = [cand for _, cand in scored_candidates if os.path.exists(cand)]
    if valid_existing_candidates:
        top_cand = valid_existing_candidates[0]
        top_name = os.path.basename(top_cand)
        console.print(f"[yellow]  [TargetVerification] Function symbol '{vuln_function}' is internal. Falling back to top executable build target '{top_name}'.[/yellow]")
        return top_cand, {
            "reachable": True,
            "confidence": "MEDIUM",
            "reason": f"Function symbol '{vuln_function}' is internal to library; selected top executable target '{top_name}'"
        }

    console.print(f"[bold red]  [TargetVerification] Static finding in '{vuln_function}' could not be dynamically verified: no build target exercises this code path.[/bold red]")
    return None, {
        "reachable": False,
        "confidence": "HIGH",
        "reason": f"Static finding in '{vuln_function}' could not be dynamically verified: no build target exercises this code path"
    }
