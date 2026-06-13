"""
Traditional (non-AI) mutation strategies.

These kick in automatically when every LLM engine refuses to generate
payloads — ensuring the fuzzer NEVER returns empty-handed.

Strategies implemented:
  1. Buffer overflow — repeated character strings of escalating length
  2. Format string — classic printf exploitation patterns
  3. Integer boundary — INT_MAX, INT_MIN, 0, -1, huge values
  4. Null / special chars — embedded nulls, newlines, shell metacharacters
  5. Command injection — shell escape sequences
  6. Off-by-one — boundary-adjacent lengths
"""

import random
import string


def _rand_ascii(length: int) -> str:
    """Generate a random ASCII string of the given length."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


# ---------------------------------------------------------------------------
# Individual strategy generators
# ---------------------------------------------------------------------------

def _buffer_overflow_payloads(delivery_mode: str) -> list[dict]:
    """Classic buffer-overflow strings of escalating length."""
    payloads = []
    for length in [16, 64, 128, 256, 512, 1024]:
        data = "A" * length
        payloads.append({
            "args": [data] if delivery_mode == "args" else [],
            "input_data": data if delivery_mode != "args" else "",
            "vuln_type": "buffer_overflow",
            "reason": f"Traditional mutator: {length}-byte repeated 'A' string to overflow fixed-size buffers",
            "severity": "high",
            "cwe": "CWE-120",
        })
    return payloads


def _format_string_payloads(delivery_mode: str) -> list[dict]:
    """Classic printf format-string exploitation patterns."""
    patterns = [
        "%s%s%s%s%s%s%s%s%s%s",
        "%x.%x.%x.%x.%x.%x.%x.%x",
        "%n%n%n%n%n%n%n%n",
        "%08x." * 20,
        "AAAA" + "%08x." * 12 + "%n",
        "%p%p%p%p%p%p%p%p%p%p",
    ]
    payloads = []
    for pat in patterns:
        payloads.append({
            "args": [pat] if delivery_mode == "args" else [],
            "input_data": pat if delivery_mode != "args" else "",
            "vuln_type": "format_string",
            "reason": f"Traditional mutator: format-string pattern '{pat[:30]}...'",
            "severity": "critical",
            "cwe": "CWE-134",
        })
    return payloads


def _integer_boundary_payloads(delivery_mode: str) -> list[dict]:
    """Boundary integer values that trigger over/underflow."""
    values = [
        ("0", "zero value"),
        ("-1", "negative one / unsigned wrap"),
        ("2147483647", "INT32_MAX"),
        ("-2147483648", "INT32_MIN"),
        ("2147483648", "INT32_MAX + 1 (overflow)"),
        ("4294967295", "UINT32_MAX"),
        ("4294967296", "UINT32_MAX + 1"),
        ("9999999999999", "very large integer"),
        ("-9999999999999", "very large negative integer"),
    ]
    payloads = []
    for val, reason in values:
        payloads.append({
            "args": [val] if delivery_mode == "args" else [],
            "input_data": val if delivery_mode != "args" else "",
            "vuln_type": "integer_overflow",
            "reason": f"Traditional mutator: {reason}",
            "severity": "high",
            "cwe": "CWE-190",
        })
    return payloads


def _null_and_special_payloads(delivery_mode: str) -> list[dict]:
    """Null bytes, newlines, and other special characters."""
    specials = [
        ("\x00" * 16, "embedded null bytes"),
        ("A" * 50 + "\x00" + "B" * 50, "null byte in middle of string"),
        ("\n" * 100, "newline flood"),
        ("\r\n" * 50, "CRLF flood"),
        ("\t" * 100, "tab flood"),
        ("A" * 100 + "\xff" * 50, "non-ASCII high bytes"),
        ("", "empty string / missing input"),
    ]
    payloads = []
    for data, reason in specials:
        payloads.append({
            "args": [data] if delivery_mode == "args" else [],
            "input_data": data if delivery_mode != "args" else "",
            "vuln_type": "input_validation",
            "reason": f"Traditional mutator: {reason}",
            "severity": "medium",
            "cwe": "CWE-20",
        })
    return payloads


def _command_injection_payloads(delivery_mode: str) -> list[dict]:
    """Shell metacharacter injection strings."""
    injections = [
        ("; ls", "semicolon command chaining"),
        ("| cat /etc/passwd", "pipe injection"),
        ("$(whoami)", "command substitution"),
        ("`id`", "backtick command substitution"),
        ("&& echo pwned", "AND chaining"),
        ("|| echo pwned", "OR chaining"),
        ("'; DROP TABLE users; --", "SQL-style injection crossover"),
    ]
    payloads = []
    for data, reason in injections:
        payloads.append({
            "args": [data] if delivery_mode == "args" else [],
            "input_data": data if delivery_mode != "args" else "",
            "vuln_type": "command_injection",
            "reason": f"Traditional mutator: {reason}",
            "severity": "critical",
            "cwe": "CWE-78",
        })
    return payloads


def _off_by_one_payloads(delivery_mode: str) -> list[dict]:
    """Boundary-adjacent lengths targeting off-by-one errors."""
    payloads = []
    for boundary in [8, 16, 32, 64, 128, 255, 256, 512, 1024]:
        for offset in [-1, 0, 1]:
            length = boundary + offset
            if length <= 0:
                continue
            data = "X" * length
            payloads.append({
                "args": [data] if delivery_mode == "args" else [],
                "input_data": data if delivery_mode != "args" else "",
                "vuln_type": "off_by_one",
                "reason": f"Traditional mutator: {length}-byte string (boundary {boundary} {'+' if offset > 0 else ''}{offset})",
                "severity": "medium",
                "cwe": "CWE-193",
            })
    return payloads


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_fallback_payloads(max_payloads: int = 20, delivery_mode: str = "args") -> list[dict]:
    """
    Generate a diverse set of traditional mutation-based payloads.

    Called automatically when the AI engine returns zero payloads
    (due to refusal, rate-limiting, network error, etc.).

    Returns up to *max_payloads* payloads sampled across all strategies,
    ensuring at least one payload from each category is included.
    """
    # Collect all strategies
    strategies = [
        ("buffer_overflow", _buffer_overflow_payloads(delivery_mode)),
        ("format_string", _format_string_payloads(delivery_mode)),
        ("integer_boundary", _integer_boundary_payloads(delivery_mode)),
        ("null_special", _null_and_special_payloads(delivery_mode)),
        ("command_injection", _command_injection_payloads(delivery_mode)),
        ("off_by_one", _off_by_one_payloads(delivery_mode)),
    ]

    # Guarantee at least one from each category
    selected: list[dict] = []
    remaining: list[dict] = []

    for _name, payloads in strategies:
        if payloads:
            # Pick a representative from each category
            selected.append(random.choice(payloads))
            remaining.extend([p for p in payloads if p not in selected])

    # Fill the rest up to max_payloads from the remaining pool
    budget = max_payloads - len(selected)
    if budget > 0 and remaining:
        random.shuffle(remaining)
        selected.extend(remaining[:budget])

    return selected[:max_payloads]
