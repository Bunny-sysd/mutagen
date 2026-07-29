import re
import struct

from rich.console import Console

console = Console(force_terminal=True, force_jupyter=False)

def extract_comparison_constraints(source_code: str) -> dict:
    """Scans target source code for comparison constraints, magic numbers, and string comparison targets using AST + regex."""
    constraints = {
        "magic_hex": [],
        "strings": [],
        "integers": [],
    }

    if not source_code:
        return constraints

    # Attempt tree-sitter AST extraction first for high precision
    try:
        import tree_sitter_c as tsc
        from tree_sitter import Language, Parser

        c_language = Language(tsc.language())
        parser = Parser(c_language)
        code_bytes = source_code.encode("utf-8")
        tree = parser.parse(code_bytes)

        def _traverse(node):
            if node.type == "string_literal":
                raw_str = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                clean = raw_str.strip('"').strip("'")
                if clean and len(clean) > 1 and clean not in constraints["strings"]:
                    constraints["strings"].append(clean)
            elif node.type == "number_literal":
                num_str = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                if num_str.startswith("0x") or num_str.startswith("0X"):
                    try:
                        val = int(num_str, 16)
                        if val not in constraints["magic_hex"]:
                            constraints["magic_hex"].append(val)
                    except ValueError:
                        pass
                else:
                    try:
                        val = int(num_str)
                        if val > 0 and val not in constraints["integers"]:
                            constraints["integers"].append(val)
                    except ValueError:
                        pass

            for child in node.children:
                _traverse(child)

        _traverse(tree.root_node)
    except Exception:
        pass

    # Regex fallback / secondary pass
    hex_matches = re.findall(r'0x[0-9a-fA-F]{4,8}', source_code)
    for hx in hex_matches:
        try:
            val = int(hx, 16)
            if val not in constraints["magic_hex"]:
                constraints["magic_hex"].append(val)
        except ValueError:
            pass

    str_matches = re.findall(r'(?:strcmp|strncmp|memcmp|stricmp|strcasecmp)\s*\(\s*(?:[^\,]+)\,\s*"([^"]+)"', source_code)
    str_matches2 = re.findall(r'(?:strcmp|strncmp|memcmp|stricmp|strcasecmp)\s*\(\s*"([^"]+)"\,\s*(?:[^\)]+)\)', source_code)
    for s in str_matches + str_matches2:
        if s and s not in constraints["strings"]:
            constraints["strings"].append(s)

    int_matches = re.findall(r'(?:==|!=|<|>|<=|>=)\s*([0-9]{2,10})', source_code)
    for num_str in int_matches:
        try:
            val = int(num_str)
            if val not in constraints["integers"] and val > 0:
                constraints["integers"].append(val)
        except ValueError:
            pass

    return constraints

def generate_constraint_seeds(constraints: dict) -> list[bytes]:
    """Generates binary and text payload seeds that satisfy parsed branch conditions."""
    seeds = []

    # 1. Generate text string seeds
    for s in constraints.get("strings", []):
        seeds.append(s.encode("utf-8", errors="ignore"))
        seeds.append((s + "\n").encode("utf-8", errors="ignore"))
        seeds.append((s + " AAAAAAAA\n").encode("utf-8", errors="ignore"))

    # 2. Generate magic integer seeds (little-endian & big-endian bytes)
    for hx in constraints.get("magic_hex", []):
        try:
            # 32-bit little endian and big endian
            seeds.append(struct.pack("<I", hx & 0xFFFFFFFF))
            seeds.append(struct.pack(">I", hx & 0xFFFFFFFF))
            # Text representation
            seeds.append(f"{hx}".encode())
            seeds.append(f"{hex(hx)}".encode())
        except Exception:
            pass

    # 3. Generate boundary integer string seeds
    for num in constraints.get("integers", []):
        seeds.append(f"{num}".encode())
        seeds.append(f"{num + 1}".encode())
        seeds.append(f"{num - 1}".encode())

    return seeds

def solve_and_inject_seeds(source_code: str, existing_seeds: list[bytes]) -> list[bytes]:
    """Solves path conditions from source code and injects constraint-solving seeds into the seed pool."""
    constraints = extract_comparison_constraints(source_code)
    new_seeds = generate_constraint_seeds(constraints)

    combined = list(existing_seeds)
    added_count = 0

    for ns in new_seeds:
        if ns not in combined:
            combined.append(ns)
            added_count += 1

    if added_count > 0:
        console.print(f"[cyan]  Symbolic Constraint Solver: Generated and injected {added_count} path-solving payload seeds.[/cyan]")

    return combined
