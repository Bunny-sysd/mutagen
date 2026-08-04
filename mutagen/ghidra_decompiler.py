"""
Mutagen Ghidra Decompiler Adapter (Legacy Compatibility)
=========================================================
Forwards decompilation calls to mutagen.decompiler.
"""

from mutagen.decompiler import (
    decompile_binary,
    find_ghidra,
)


def generate_decompile_headless_script(output_py_path: str, output_c_path: str):
    """Generates a Ghidra script to dump decompiled pseudo-C functions."""
    from mutagen.decompiler import _generate_ghidra_postscript
    content = _generate_ghidra_postscript(output_c_path, all_functions=True)
    with open(output_py_path, "w", encoding="utf-8") as f:
        f.write(content)


def decompile_with_ghidra_headless(binary_path: str, ghidra_home: str | None = None) -> str | None:
    """Executes Ghidra analyzeHeadless to decompile a binary target into pseudo-C source code."""
    try:
        ghidra_bin = find_ghidra(ghidra_home or "")
        res = decompile_binary(binary_path, ghidra_bin, all_functions=True)
        return res.pseudo_source if res else None
    except Exception:
        return None
