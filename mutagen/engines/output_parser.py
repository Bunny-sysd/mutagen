"""
Centralized structured output parser for LLM engine responses.

All engines return JSON arrays from their generate/refine methods.
This module provides shared extraction, validation, and fallback logic
instead of each engine duplicating its own ad-hoc parsing.
"""

from __future__ import annotations

import json
import re


def extract_json_array(raw: str) -> list[dict]:
    """
    Extract a JSON array from raw LLM output.

    Handles:
    - Pure JSON arrays: [...]
    - Markdown fenced JSON: ```json [...] ```
    - Wrapper dicts: {"payloads": [...]} or {"results": [...]}
    - Multiple extraction strategies with graceful fallback
    """
    if not raw or not raw.strip():
        return []

    text = raw.strip()

    # 1. Strip markdown code fences if present
    text = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.MULTILINE)
    text = re.sub(r'\n?```\s*$', '', text, flags=re.MULTILINE)
    text = text.strip()

    # 2. Try direct parse
    try:
        data = json.loads(text)
        return _unwrap_to_list(data)
    except json.JSONDecodeError:
        pass

    # 3. Try to find the largest JSON array in the text
    array_match = re.search(r'(\[[\s\S]*\])', text)
    if array_match:
        try:
            data = json.loads(array_match.group(1))
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]
        except json.JSONDecodeError:
            pass

    # 4. Try to find a JSON object that wraps an array
    obj_match = re.search(r'(\{[\s\S]*\})', text)
    if obj_match:
        try:
            data = json.loads(obj_match.group(1))
            return _unwrap_to_list(data)
        except json.JSONDecodeError:
            pass

    # 5. Try line-by-line JSON object extraction (some models output one per line)
    objects = []
    for line in text.splitlines():
        line = line.strip().rstrip(',')
        if line.startswith('{') and line.endswith('}'):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    objects.append(obj)
            except json.JSONDecodeError:
                continue
    if objects:
        return objects

    return []


def _unwrap_to_list(data) -> list[dict]:
    """Unwrap a parsed JSON value into a list of dicts."""
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        # Look for array values inside wrapper dicts
        for key in ("payloads", "results", "vulnerabilities", "items", "data", "exploits", "patches"):
            if key in data and isinstance(data[key], list):
                return [x for x in data[key] if isinstance(x, dict)]
        # If the dict itself has payload-like keys, treat it as a single-element list
        if any(k in data for k in ("args", "input_data", "vuln_type", "vulnerability")):
            return [data]
        # Last resort: try the first list-valued key
        for v in data.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return v
    return []


def validate_payload_list(items: list[dict]) -> list[dict]:
    """
    Filter a list of payload dicts, keeping only those with meaningful content.
    Does NOT enforce a fixed schema — the LLM can include any fields it wants.
    Only rejects entries that are completely empty or placeholder-like.
    """
    valid = []
    for item in items:
        if not isinstance(item, dict):
            continue
        # Must have at least some content — args, input_data, or raw_bytes_hex
        has_args = bool(item.get("args"))
        has_input = bool(item.get("input_data"))
        has_hex = bool(item.get("raw_bytes_hex"))
        has_vuln = bool(item.get("vuln_type") or item.get("vulnerability"))
        if has_args or has_input or has_hex or has_vuln:
            valid.append(item)
    return valid


def parse_payloads(raw: str) -> list[dict]:
    """
    Full pipeline: extract JSON array from raw LLM text, then validate.
    This is the primary entry point for all engines.
    """
    items = extract_json_array(raw)
    return validate_payload_list(items)


def strip_code_fences(raw: str) -> str:
    """
    Robustly strip markdown code fences, language identifiers, and preamble/postamble text
    from raw LLM code outputs.

    Handles:
    - Standard markdown fences: ```c ... ```, ```cpp ... ```, ```rust ... ```, ```python ... ```
    - Preamble text before ``` or postamble text after ```
    - Unclosed opening fences: ```c ... (end of string)
    - Indented code fences
    """
    if not raw or not raw.strip():
        return ""

    text = raw.strip()

    # Strategy 1: Match code inside triple backtick block with optional language specifier
    # e.g., optional preamble ... ```c\nCODE\n``` ... optional postamble
    fence_pattern = r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?([\s\S]*?)(?:```|$)"
    matches = list(re.finditer(fence_pattern, text))

    if matches:
        # Pick the largest code block if multiple exist
        best_code = max(matches, key=lambda m: len(m.group(1).strip())).group(1)
        cleaned = best_code.strip()
        if cleaned:
            return cleaned

    # Strategy 2: Line-by-line cleanup if no backtick matches (or fallback)
    lines = text.splitlines()
    filtered_lines = []
    in_fence = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        filtered_lines.append(line)

    result = "\n".join(filtered_lines).strip()

    # Final cleanup of any lingering isolated backticks
    if result.startswith("```"):
        result = re.sub(r"^```[a-zA-Z0-9_+-]*\s*\n?", "", result)
    return result.strip()


def repair_truncated_json(raw: str) -> dict | list | None:
    """
    Attempts to salvage valid JSON objects or arrays from truncated LLM output strings.
    Extracts complete inner JSON objects, strips incomplete trailing tokens,
    and balances quotes/brackets.
    """
    if not raw or not raw.strip():
        return None

    text = raw.strip()
    text = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.MULTILINE)
    text = re.sub(r'\n?```\s*$', '', text, flags=re.MULTILINE).strip()

    # 1. Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Extract all complete {"key": ...} objects using brace balance parser
    objects = []
    depth = 0
    start_idx = None
    in_string = False
    escape = False

    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == '\\':
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue

        if ch == '{':
            if depth == 0:
                start_idx = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start_idx is not None:
                candidate = text[start_idx:i+1]
                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict):
                        objects.append(obj)
                except Exception:
                    pass
                start_idx = None

    if objects:
        if len(objects) == 1 and any(k in objects[0] for k in ("vulnerabilities", "payloads", "items")):
            return objects[0]
        return objects

    # 3. Truncation repair: try closing open string quotes and closing braces
    for suffix in ['"}', '"}]}', '"]}', ']}', '}']:
        try:
            patched = text.rstrip(', \n\t') + suffix
            data = json.loads(patched)
            return data
        except Exception:
            pass

    return None

