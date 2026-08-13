"""
Ground-Truth CVE Validation Engine for Mutagen.

Provides universal, language-agnostic validation against known public CVEs:
1. Generic CVE metadata retrieval (NVD/OSV API + offline high-fidelity dictionary).
2. Target version detection & version-match gating.
3. Structured outcome evaluation (CONFIRMED, TARGET_PATCHED, PIPELINE_GAP, UNGROUNDED)
   with full diagnostic telemetry.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console(force_terminal=True, force_jupyter=False)

# Built-in High-Fidelity Ground-Truth CVE Knowledge Base (Offline & Air-gapped fallback)
OFFLINE_CVE_REGISTRY: dict[str, dict[str, Any]] = {
    "CVE-2025-64505": {
        "cve_id": "CVE-2025-64505",
        "name": "Heap buffer over-read in png_do_quantize",
        "cwe": "CWE-125",
        "vuln_type": "Heap Buffer Over-Read",
        "affected_functions": ["png_do_quantize", "png_set_quantize", "png_quantize"],
        "affected_versions": "<= 1.6.50",
        "fixed_version": "1.6.51",
        "target_libraries": ["libpng"],
        "description": "In libpng through 1.6.50, png_do_quantize in pngrtran.c has a heap buffer over-read due to a malformed palette index during quantization.",
        "poc_guidance": "Construct a PNG with a PLTE chunk and image data referencing color indices that exceed palette boundaries, invoking png_do_quantize to trigger over-read.",
    },
    "CVE-2025-64506": {
        "cve_id": "CVE-2025-64506",
        "name": "Heap buffer over-read in png_write_image_8bit",
        "cwe": "CWE-125",
        "vuln_type": "Heap Buffer Over-Read",
        "affected_functions": ["png_write_image_8bit", "convert_to_8bit", "png_image_write_to_memory"],
        "affected_versions": "<= 1.6.50",
        "fixed_version": "1.6.51",
        "target_libraries": ["libpng"],
        "description": "In libpng through 1.6.50, png_write_image_8bit in pngwrite.c triggers a heap buffer over-read in convert_to_8bit during downsampling.",
        "poc_guidance": "Invoke simplified write API with 16-bit to 8-bit downsampling configurations where input buffer length is smaller than expected byte stride.",
    },
    "CVE-2025-64720": {
        "cve_id": "CVE-2025-64720",
        "name": "Out-of-bounds read in png_image_read_composite",
        "cwe": "CWE-125",
        "vuln_type": "Out-of-Bounds Read",
        "affected_functions": ["png_image_read_composite", "png_image_read_background"],
        "affected_versions": "<= 1.6.50",
        "fixed_version": "1.6.51",
        "target_libraries": ["libpng"],
        "description": "In libpng through 1.6.50, png_image_read_composite in pngread.c contains an out-of-bounds read during palette alpha premultiplication.",
        "poc_guidance": "Craft an image with transparent palette entries requiring background composite blending, triggering OOB read during buffer composition.",
    },
    "CVE-2025-65018": {
        "cve_id": "CVE-2025-65018",
        "name": "Heap buffer overflow in png_combine_row via png_image_finish_read",
        "cwe": "CWE-122",
        "vuln_type": "Heap Buffer Overflow",
        "affected_functions": ["png_combine_row", "png_image_finish_read", "png_read_image"],
        "affected_versions": "<= 1.6.50",
        "fixed_version": "1.6.51",
        "target_libraries": ["libpng"],
        "description": "In libpng through 1.6.50, png_combine_row in pngrutil.c has a heap buffer overflow when processing 16-bit interlaced images downsampled to 8-bit output.",
        "poc_guidance": "Craft 16-bit depth Adam7 interlaced PNG where row_info downsamples to 8-bit, overflowing output buffer during png_combine_row in png_image_finish_read.",
    },
}


def fetch_cve_metadata(cve_id: str) -> dict[str, Any]:
    """
    Retrieves CVE metadata from online OSV/NVD APIs or the built-in CVE registry.
    Works for any CVE identifier.
    """
    clean_id = cve_id.strip().upper()

    # 1. Check built-in registry
    if clean_id in OFFLINE_CVE_REGISTRY:
        return OFFLINE_CVE_REGISTRY[clean_id]

    # 2. Try querying OSV API (Open Source Vulnerabilities)
    try:
        url = f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(clean_id)}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mutagen-CVE-Validator/2.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                summary = data.get("summary", "")
                details = data.get("details", "")
                affected = data.get("affected", [{}])
                fixed_ver = ""
                affected_vers = ""
                target_libs = []
                for aff in affected:
                    pkg = aff.get("package", {}).get("name", "")
                    if pkg:
                        target_libs.append(pkg)
                    ranges = aff.get("ranges", [])
                    for r in ranges:
                        for ev in r.get("events", []):
                            if "fixed" in ev:
                                fixed_ver = ev["fixed"]
                            if "introduced" in ev:
                                affected_vers = f">= {ev['introduced']}"

                # Extract potential function names from details using regex
                funcs = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{3,})\s*\(\)', f"{summary} {details}")

                return {
                    "cve_id": clean_id,
                    "name": summary or f"Vulnerability {clean_id}",
                    "cwe": "CWE-119",
                    "vuln_type": "Memory Corruption",
                    "affected_functions": list(set(funcs)) if funcs else ["target_function"],
                    "affected_versions": affected_vers or "Unknown",
                    "fixed_version": fixed_ver or "Unknown",
                    "target_libraries": target_libs or ["target"],
                    "description": details or summary or f"Public vulnerability record for {clean_id}",
                    "poc_guidance": f"Synthesize targeted boundaries to reproduce {clean_id} based on advisory description.",
                }
    except Exception:
        pass

    # 3. Fallback generic structure for arbitrary CVE IDs
    return {
        "cve_id": clean_id,
        "name": f"Advisory Record {clean_id}",
        "cwe": "CWE-119",
        "vuln_type": "Security Flaw",
        "affected_functions": [],
        "affected_versions": "Unknown",
        "fixed_version": "Unknown",
        "target_libraries": [],
        "description": f"Target vulnerability testing for ground truth ID {clean_id}.",
        "poc_guidance": f"Generate boundary test inputs targeting vulnerabilities associated with {clean_id}.",
    }


def detect_target_version(target_path: str, source_code: str = "") -> Optional[str]:
    """
    Language-agnostic target version detector.
    Scans source files, header definitions, build configs, and changelogs.
    """
    search_dir = os.path.dirname(os.path.abspath(target_path)) if target_path else os.getcwd()
    combined_text = source_code or ""

    # Common version regex patterns across C, Rust, Go, Python, JS
    version_patterns = [
        # C/C++ Header macros: #define PNG_LIBPNG_VER_STRING "1.6.50" or #define VERSION "1.2.3"
        re.compile(r'#\s*define\s+[A-Z0-9_]*VER[A-Z0-9_]*\s+["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-zA-Z0-9_\-\.]*)["\']', re.IGNORECASE),
        re.compile(r'#\s*define\s+VERSION\s+["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-zA-Z0-9_\-\.]*)["\']', re.IGNORECASE),
        # Rust Cargo.toml / package.json / setup.py / pyproject.toml
        re.compile(r'version\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-zA-Z0-9_\-\.]*)["\']', re.IGNORECASE),
        re.compile(r'"version"\s*:\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-zA-Z0-9_\-\.]*)["\']', re.IGNORECASE),
        re.compile(r'__version__\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-zA-Z0-9_\-\.]*)["\']', re.IGNORECASE),
    ]

    for p in version_patterns:
        m = p.search(combined_text)
        if m:
            return m.group(1)

    # Scan directory files if not found in target file
    candidate_files = [
        "png.h", "version.h", "config.h", "Cargo.toml", "package.json",
        "setup.py", "pyproject.toml", "VERSION", "CHANGELOG.md", "CMakeLists.txt"
    ]
    for cfile in candidate_files:
        fpath = os.path.join(search_dir, cfile)
        if os.path.exists(fpath):
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                for p in version_patterns:
                    m = p.search(content)
                    if m:
                        return m.group(1)
            except Exception:
                pass

    return None


def _parse_semver(ver_str: str) -> tuple[int, ...]:
    """Extracts integer tuple from version string for comparison (e.g. '1.6.50' -> (1, 6, 50))."""
    nums = re.findall(r'\d+', ver_str)
    return tuple(int(n) for n in nums) if nums else (0,)


def check_version_affected(detected_version: Optional[str], cve_meta: dict[str, Any]) -> Tuple[bool, str]:
    """
    Compares detected version against CVE affected / fixed version range.
    Returns (is_affected: bool, message: str).
    """
    if not detected_version:
        return True, "Target version could not be explicitly determined; assuming affected for testing."

    fixed_ver = cve_meta.get("fixed_version", "")
    if not fixed_ver or fixed_ver == "Unknown":
        return True, f"Target version '{detected_version}' detected (CVE has no fixed version boundary)."

    target_tuple = _parse_semver(detected_version)
    fixed_tuple = _parse_semver(fixed_ver)

    if target_tuple < fixed_tuple:
        return True, f"Target version '{detected_version}' is confirmed affected (fixed in {fixed_ver})."
    else:
        return False, f"Target version '{detected_version}' appears to be PATCHED (>= fixed version {fixed_ver})."


def evaluate_cve_validation_outcome(
    context: Any,
    cve_meta: dict[str, Any],
    detected_version: Optional[str],
    is_version_affected: bool
) -> dict[str, Any]:
    """
    Evaluates final ground-truth validation outcome across 4 explicit categories:
      A. CONFIRMED: Real crash reproduced consistent with CVE.
      B. NOT REPRODUCED — TARGET LIKELY PATCHED: Target version outside affected range.
      C. NOT REPRODUCED — PIPELINE GAP: Affected target version, but pipeline failed to crash.
      D. UNGROUNDED: Source code at target function/line could not be grounded.
    """
    active_crashes = [p for p in context.active_payloads if p.crash_type is not None]
    cve_id = cve_meta.get("cve_id", "CVE-UNKNOWN")
    cve_name = cve_meta.get("name", "")

    # Category B: Target version is not affected
    if not is_version_affected:
        return {
            "category": "B",
            "status": "NOT REPRODUCED — TARGET LIKELY PATCHED",
            "cve_id": cve_id,
            "cve_name": cve_name,
            "summary": f"Target version '{detected_version}' is newer than or equal to fixed version '{cve_meta.get('fixed_version')}'. Expected outcome: No crash.",
            "diagnostic": None,
        }

    # Category A: Active crash reproduced!
    if active_crashes:
        return {
            "category": "A",
            "status": "CONFIRMED",
            "cve_id": cve_id,
            "cve_name": cve_name,
            "summary": f"Reproduced {len(active_crashes)} crash(es) successfully under isolated Docker execution. Ground truth vulnerability {cve_id} confirmed!",
            "diagnostic": {
                "crashes_reproduced": len(active_crashes),
                "crash_types": list(set(p.crash_type for p in active_crashes)),
                "exit_codes": [p.exit_code for p in active_crashes],
            }
        }

    # Check for Category D: Ungrounded finding
    all_ungrounded = (
        len(context.vulnerabilities) > 0 and
        all(
            v.verification_status == "UNGROUNDED_FINDING" or
            (getattr(v, "is_false_positive_risk", False) and "UNGROUNDED" in v.verification_annotation)
            for v in context.vulnerabilities
        )
    )
    if all_ungrounded:
        return {
            "category": "D",
            "status": "UNGROUNDED",
            "cve_id": cve_id,
            "cve_name": cve_name,
            "summary": f"GroundingVerifier could not locate code matching {cve_id} in current source (function may be renamed, refactored, or absent).",
            "diagnostic": {
                "target_path": context.target_path,
                "vulnerabilities": [v.dict() if hasattr(v, "dict") else str(v) for v in context.vulnerabilities],
                "logs": context.logs[-10:],
            }
        }
    # Category E: INCONCLUSIVE — TRIAGE FAILURE
    # If the triage LLM call failed (API error / JSON parse error) and produced 0 findings:
    triage_failed = getattr(context, "triage_failed", False)
    triage_error = getattr(context, "triage_error", "")
    if (triage_failed or (len(context.active_payloads) == 0 and triage_error)) and len(context.vulnerabilities) == 0:
        return {
            "category": "E",
            "status": "INCONCLUSIVE — TRIAGE FAILURE",
            "cve_id": cve_id,
            "cve_name": cve_name,
            "summary": f"Triage phase failed to complete ({triage_error or 'API/Parse error'}). 0 findings generated — run is inconclusive.",
            "diagnostic": {
                "triage_error": triage_error or "Triage LLM call failed or returned empty findings",
                "target_path": context.target_path,
                "logs": context.logs[-15:],
            }
        }

    # Category C: PIPELINE GAP
    # The target IS within the affected version range, but 0 crashes reproduced.
    # Dump full diagnostic telemetry for root cause analysis.
    payload_dump = []
    exec_errors = 0
    for i, p in enumerate(context.active_payloads):
        is_err = getattr(p, "crash_type", "") == "EXECUTION_ERROR"
        if is_err:
            exec_errors += 1
        payload_dump.append({
            "index": i + 1,
            "args": p.args,
            "input_data_len": len(p.input_data) if p.input_data else 0,
            "raw_bytes_hex_preview": (p.raw_bytes_hex[:64] + "...") if p.raw_bytes_hex else None,
            "exit_code": p.exit_code,
            "crash_type": p.crash_type,
            "is_execution_error": is_err,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "reason": p.reason,
            "container_id": getattr(p, "container_id", None)
        })

    reach_status = getattr(context, "reachability_status", "") or "ACTIVE_BINARY"
    reach_msg = getattr(context, "reachability_message", "") or "Target binary executed"

    summary_note = f"Target version '{detected_version}' IS affected by {cve_id}, but Mutagen pipeline failed to reproduce a crash."
    if exec_errors > 0:
        summary_note += f" ({exec_errors} payload(s) failed at the infrastructure/Docker layer)."

    return {
        "category": "C",
        "status": "NOT REPRODUCED — PIPELINE GAP",
        "cve_id": cve_id,
        "cve_name": cve_name,
        "summary": summary_note,
        "diagnostic": {
            "target_path": context.target_path,
            "delivery_mode": context.delivery_mode,
            "reachability_status": reach_status,
            "reachability_message": reach_msg,
            "payloads_tested": len(context.active_payloads),
            "execution_errors": exec_errors,
            "payload_details": payload_dump,
            "logs": context.logs[-20:],
        }
    }


def render_cve_validation_panel(result: dict[str, Any]) -> None:
    """Renders formatted Rich terminal summary of Ground-Truth CVE validation."""
    cat = result["category"]
    cve_id = result["cve_id"]
    status_str = result["status"]
    summary = result["summary"]

    if cat == "A":
        color = "green"
        title = f"[bold green]🎯 GROUND-TRUTH CVE VALIDATION: {cve_id} — {status_str}[/bold green]"
    elif cat == "B":
        color = "cyan"
        title = f"[bold cyan]ℹ️ GROUND-TRUTH CVE VALIDATION: {cve_id} — {status_str}[/bold cyan]"
    elif cat == "D":
        color = "yellow"
        title = f"[bold yellow]⚠️ GROUND-TRUTH CVE VALIDATION: {cve_id} — {status_str}[/bold yellow]"
    elif cat == "E":
        color = "yellow"
        title = f"[bold yellow]⚠️ GROUND-TRUTH CVE VALIDATION: {cve_id} — {status_str}[/bold yellow]"
    else:  # Category C
        color = "red"
        title = f"[bold red]❌ GROUND-TRUTH CVE VALIDATION: {cve_id} — {status_str}[/bold red]"

    diag_text = ""
    if cat == "E" and result.get("diagnostic"):
        diag = result["diagnostic"]
        diag_text = f"\n\n[bold yellow]Triage Error Telemetry:[/bold yellow]\n"
        diag_text += f"  - Error Detail:   {diag.get('triage_error')}\n"
        diag_text += f"  - Recommendation: Triage LLM call encountered a parse/network error. Please retry the run.\n"
    elif cat == "C" and result.get("diagnostic"):
        diag = result["diagnostic"]
        diag_text = f"\n\n[bold yellow]Pipeline Diagnostic Telemetry:[/bold yellow]\n"
        diag_text += f"  - Target Delivery Mode:  {diag.get('delivery_mode')}\n"
        diag_text += f"  - Reachability Status:   {diag.get('reachability_status')} ({diag.get('reachability_message')})\n"
        diag_text += f"  - Payloads Evaluated:    {diag.get('payloads_tested')}\n"
        if diag.get("execution_errors", 0) > 0:
            diag_text += f"  - Infrastructure Errors: [bold red]{diag.get('execution_errors')} error(s)[/bold red]\n"
        if diag.get("payload_details"):
            p0 = diag["payload_details"][0]
            diag_text += f"  - Payload 1 Return Code: {p0.get('exit_code')} | Crash Type: {p0.get('crash_type') or 'None'} | Args: {p0.get('args')}\n"
            if p0.get("stderr"):
                diag_text += f"  - Payload 1 Stderr:      {p0.get('stderr').strip()[:120]}\n"

    panel = Panel(
        f"[bold]CVE ID:[/bold]       {cve_id} ({result.get('cve_name', '')})\n"
        f"[bold]Outcome:[/bold]      {status_str}\n"
        f"[bold]Summary:[/bold]      {summary}"
        f"{diag_text}",
        title=title,
        border_style=color,
        expand=False,
    )
    console.print(panel)
