import os
import re
from dataclasses import dataclass


@dataclass
class TypeVerificationResult:
    verification_status: str       # "VERIFIED_SAFE" | "LIKELY_FALSE_POSITIVE" | "UNCONFIRMED_RISK" | "VERIFIED_RISK"
    confidence: str                # "HIGH" | "MEDIUM" | "LOW"
    annotation: str                # Human-readable explanation of static type findings
    is_false_positive_risk: bool   # True if widening casts or safe guards protect the operation


ARITHMETIC_CWES = {
    "CWE-190", "CWE-191", "CWE-680", "CWE-681", "CWE-128", "CWE-131",
    "INTEGER OVERFLOW", "INTEGER UNDERFLOW", "WRAPAROUND", "NUMERIC TRUNCATION"
}


def _is_arithmetic_cwe(cwe_str: str, vuln_type_str: str) -> bool:
    combined = f"{cwe_str} {vuln_type_str}".upper()
    return any(cwe in combined for cwe in ARITHMETIC_CWES)


def _resolve_macro_definitions(target_dir: str, macro_names: list[str]) -> dict[str, str]:
    """Scans header files in target_dir for #define MACRO ... definitions."""
    definitions = {}
    if not target_dir or not os.path.exists(target_dir):
        return definitions

    macro_pattern = re.compile(r'#\s*define\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(?[^)]*\)?\s+(.*)')

    for root, _, files in os.walk(target_dir):
        if any(ignored in root.lower() for ignored in ["build", "cmakefiles", "cmaketmp"]):
            continue
        for file in files:
            if file.endswith((".h", ".hpp", ".c", ".cpp", ".inc")):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line_str = line.strip()
                            if line_str.startswith("#define"):
                                m = macro_pattern.match(line_str)
                                if m:
                                    name, body = m.group(1), m.group(2)
                                    if name in macro_names:
                                        definitions[name] = body
                except Exception:
                    pass
    return definitions


def _verify_c_cpp(snippet: str, surrounding_code: str, target_dir: str = None) -> TypeVerificationResult:
    combined = f"{snippet}\n{surrounding_code}"

    # 1. Macro expansion check (e.g., PNG_ROWBYTES)
    macro_calls = re.findall(r'\b([A-Z0-9_]{3,})\s*\(', combined)
    if macro_calls and target_dir:
        macro_defs = _resolve_macro_definitions(target_dir, macro_calls)
        for m_name, m_body in macro_defs.items():
            if any(cast_type in m_body for cast_type in ["(png_size_t)", "(size_t)", "(uint64_t)", "(int64_t)", "(unsigned long)", "(uintmax_t)"]):
                return TypeVerificationResult(
                    verification_status="LIKELY_FALSE_POSITIVE",
                    confidence="LOW",
                    annotation=f"LIKELY FALSE POSITIVE: Macro '{m_name}' definition casts operands to wide type '{m_body.strip()}' before arithmetic",
                    is_false_positive_risk=True
                )

    # 2. Widening casts check (e.g. (size_t)a * b, (uint64_t)width, static_cast<size_t>)
    widening_cast_pattern = re.compile(
        r'\(\s*(png_size_t|size_t|uint64_t|int64_t|unsigned\s+long|uintmax_t)\s*\)|'
        r'static_cast\s*<\s*(size_t|uint64_t|int64_t|unsigned\s+long)\s*>'
    )
    if widening_cast_pattern.search(combined):
        return TypeVerificationResult(
            verification_status="LIKELY_FALSE_POSITIVE",
            confidence="LOW",
            annotation="LIKELY FALSE POSITIVE: Operands explicitly cast to wider 64-bit type (size_t/uint64_t) before operation",
            is_false_positive_risk=True
        )

    # 3. Checked arithmetic builtins/macros check (__builtin_mul_overflow, ckd_mul, SafeInt)
    checked_builtins = [
        "__builtin_mul_overflow", "__builtin_add_overflow", "__builtin_sub_overflow",
        "ckd_mul", "ckd_add", "ckd_sub", "SafeInt", "overflow_check"
    ]
    for builtin in checked_builtins:
        if builtin in combined:
            return TypeVerificationResult(
                verification_status="LIKELY_FALSE_POSITIVE",
                confidence="LOW",
                annotation=f"LIKELY FALSE POSITIVE: Operation protected by checked arithmetic interface '{builtin}'",
                is_false_positive_risk=True
            )

    return TypeVerificationResult(
        verification_status="UNCONFIRMED_RISK",
        confidence="MEDIUM",
        annotation="No explicit 64-bit widening cast or checked-arithmetic builtin detected in immediate scope",
        is_false_positive_risk=False
    )


def _verify_rust(snippet: str, surrounding_code: str) -> TypeVerificationResult:
    combined = f"{snippet}\n{surrounding_code}"

    # Checked / wrapping / saturating method calls
    safe_methods = ["checked_add", "checked_mul", "checked_sub", "wrapping_add", "wrapping_mul", "saturating_add", "saturating_mul"]
    for method in safe_methods:
        if method in combined:
            return TypeVerificationResult(
                verification_status="LIKELY_FALSE_POSITIVE",
                confidence="LOW",
                annotation=f"LIKELY FALSE POSITIVE: Rust operation uses explicit overflow-handling method '{method}'",
                is_false_positive_risk=True
            )

    # If raw operators in Rust release context
    return TypeVerificationResult(
        verification_status="UNCONFIRMED_RISK",
        confidence="MEDIUM",
        annotation="Raw Rust arithmetic operator without explicit checked_*/saturating_* handler (panics in debug, wraps in release)",
        is_false_positive_risk=False
    )


def _verify_python(snippet: str, surrounding_code: str) -> TypeVerificationResult:
    combined = f"{snippet}\n{surrounding_code}"

    # Check for fixed-width byte packing / C interop (ctypes, struct, numpy, cffi)
    fixed_width_indicators = ["struct.pack", "ctypes.", "np.", "numpy.", "cffi", "array('i'", "array('h'"]
    if any(ind in combined for ind in fixed_width_indicators):
        return TypeVerificationResult(
            verification_status="UNCONFIRMED_RISK",
            confidence="MEDIUM",
            annotation="Python arithmetic interacts with fixed-width interop types (struct/ctypes/numpy)",
            is_false_positive_risk=False
        )

    return TypeVerificationResult(
        verification_status="LIKELY_FALSE_POSITIVE",
        confidence="LOW",
        annotation="LIKELY FALSE POSITIVE: Python integers are arbitrary-precision by default; fixed-width integer overflow is invalid",
        is_false_positive_risk=True
    )


def _verify_go(snippet: str, surrounding_code: str) -> TypeVerificationResult:
    combined = f"{snippet}\n{surrounding_code}"

    if "math/bits" in combined or "bits.Mul" in combined or "bits.Add" in combined:
        return TypeVerificationResult(
            verification_status="LIKELY_FALSE_POSITIVE",
            confidence="LOW",
            annotation="LIKELY FALSE POSITIVE: Go operation uses checked math/bits package primitive",
            is_false_positive_risk=True
        )

    return TypeVerificationResult(
        verification_status="UNCONFIRMED_RISK",
        confidence="MEDIUM",
        annotation="Go integer operation without explicit math/bits package guards",
        is_false_positive_risk=False
    )


def _verify_javascript(snippet: str, surrounding_code: str) -> TypeVerificationResult:
    combined = f"{snippet}\n{surrounding_code}"

    typed_indicators = ["Int32Array", "Uint32Array", "Float64Array", "BigInt", "Buffer.alloc", "DataView", "Math.imul"]
    if any(ind in combined for ind in typed_indicators):
        return TypeVerificationResult(
            verification_status="UNCONFIRMED_RISK",
            confidence="MEDIUM",
            annotation="JavaScript operation utilizes explicit TypedArray/BigInt/Math.imul binary structures",
            is_false_positive_risk=False
        )

    return TypeVerificationResult(
        verification_status="LIKELY_FALSE_POSITIVE",
        confidence="LOW",
        annotation="LIKELY FALSE POSITIVE: JavaScript numbers are IEEE-754 float64 by default; classic 32-bit integer overflow does not apply",
        is_false_positive_risk=True
    )




def _extract_enclosing_function_scope(lines: list[str], target_idx: int) -> str:
    """Extracts lines corresponding to the enclosing function definition around target_idx."""
    if not lines or target_idx >= len(lines):
        return ""

    func_start_patterns = re.compile(
        r'^\s*(def\s+|fn\s+|func\s+|function\s+|[a-zA-Z_][a-zA-Z0-9_*\s]+\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\()'
    )

    # Scan backwards to find start of function
    start_idx = target_idx
    while start_idx > 0:
        if func_start_patterns.match(lines[start_idx]):
            break
        start_idx -= 1

    # Scan forwards to find end of function or max 15 lines from line
    end_idx = min(len(lines), target_idx + 15)
    for i in range(target_idx + 1, end_idx):
        if func_start_patterns.match(lines[i]) and i > start_idx:
            end_idx = i
            break

    return "\n".join(lines[start_idx:end_idx])


def verify_finding_type_safety(
    source_code: str,
    line_number: int,
    cwe: str,
    vuln_type: str,
    language: str = "c",
    target_path: str = None
) -> TypeVerificationResult:
    """
    Language-agnostic pre-finding verification pass for arithmetic and type-confusion findings.
    Traces operand types, macro expansions, widening casts, and checked arithmetic builtins.
    """
    if not _is_arithmetic_cwe(cwe, vuln_type):
        return TypeVerificationResult(
            verification_status="UNCONFIRMED_RISK",
            confidence="HIGH",
            annotation="Non-arithmetic vulnerability class; standard static verification applies",
            is_false_positive_risk=False
        )

    lines = (source_code or "").splitlines()
    target_idx = max(0, line_number - 1)
    snippet = lines[target_idx] if target_idx < len(lines) else ""

    surrounding_code = _extract_enclosing_function_scope(lines, target_idx)

    target_dir = os.path.dirname(os.path.abspath(target_path)) if target_path and os.path.exists(target_path) else None

    lang = (language or "c").lower()

    if lang in ("c", "cpp", "c++"):
        return _verify_c_cpp(snippet, surrounding_code, target_dir)
    elif lang == "rust":
        return _verify_rust(snippet, surrounding_code)
    elif lang in ("python", "py"):
        return _verify_python(snippet, surrounding_code)
    elif lang in ("go", "golang"):
        return _verify_go(snippet, surrounding_code)
    elif lang in ("javascript", "js", "typescript", "ts"):
        return _verify_javascript(snippet, surrounding_code)

    return _verify_c_cpp(snippet, surrounding_code, target_dir)
