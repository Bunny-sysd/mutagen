import re

FUNCTION_HEADER_REGEX = re.compile(r'^// --- Function: (\w+) @ ([0-9a-fA-F]+) ---')

DANGEROUS_KEYWORDS = {
    "strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf", "memcpy", 
    "memmove", "gets", "scanf", "fscanf", "sscanf", "malloc", "calloc", "realloc", 
    "free", "system", "popen", "exec", "execve", "execvp", "CreateProcess", 
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "socket", "connect", 
    "bind", "listen", "accept", "send", "recv", "recvfrom", "sendto"
}

def split_functions(pseudo_code: str) -> tuple[str, list[dict]]:
    """
    Split decompiled pseudo-code into a meta-header and a list of functions.
    
    Returns:
        tuple: (meta_header, list of dicts [{"name": str, "address": str, "code": str}])
    """
    functions = []
    current_func = None
    current_lines = []
    meta_lines = []
    
    for line in pseudo_code.splitlines():
        match = FUNCTION_HEADER_REGEX.match(line)
        if match:
            if current_func:
                current_func["code"] = "\n".join(current_lines).strip()
                functions.append(current_func)
            current_func = {
                "name": match.group(1),
                "address": match.group(2),
                "code": ""
            }
            current_lines = []
        else:
            if current_func:
                current_lines.append(line)
            else:
                meta_lines.append(line)
                
    if current_func:
        current_func["code"] = "\n".join(current_lines).strip()
        functions.append(current_func)
        
    meta_header = "\n".join(meta_lines).strip()
    return meta_header, functions

def contains_dangerous_keywords(code: str) -> bool:
    """Check if the function's code contains any of the dangerous library call tokens."""
    code_lower = code.lower()
    for kw in DANGEROUS_KEYWORDS:
        if re.search(r'\b' + re.escape(kw.lower()) + r'\b', code_lower):
            return True
    return False

def filter_functions(functions: list[dict], preserve_names: list[str] = None) -> list[dict]:
    """Filter out functions that don't match entry points or dangerous keyword lists."""
    if preserve_names is None:
        preserve_names = ["main", "_main", "entry"]
    preserve_names_lower = [name.lower() for name in preserve_names]
    
    filtered = []
    for f in functions:
        name_lower = f["name"].lower()
        if any(p in name_lower for p in preserve_names_lower) or contains_dangerous_keywords(f["code"]):
            filtered.append(f)
    return filtered

def reconstruct_pseudo_code(meta_header: str, functions: list[dict]) -> str:
    """Reconstruct the C pseudo-code format from split components."""
    parts = []
    if meta_header.strip():
        parts.append(meta_header.strip())
        parts.append("")
    for f in functions:
        parts.append(f"// --- Function: {f['name']} @ {f['address']} ---")
        parts.append(f["code"])
        parts.append("")
    return "\n".join(parts)
