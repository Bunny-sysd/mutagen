import datetime
import html
import json
import os

from mutagen.compliance import map_cwe_to_compliance

VULN_CAPABILITIES = {
    "buffer_overflow": {
        "name": "Memory Corruption / Buffer Overflow",
        "description": "The program writes data past the end of an allocated buffer, enabling stack or heap memory corruption, control flow hijacking, or remote code execution."
    },
    "format_string": {
        "name": "Format String Injection",
        "description": "Insecure evaluation of user-supplied input as a format string in printf-family functions, allowing unauthorized memory disclosure or memory writes."
    },
    "integer_overflow": {
        "name": "Arithmetic Wrap / Integer Overflow",
        "description": "Numeric values exceed minimum/maximum boundary limits, wrapping around to unexpected values and bypassing subsequent safety checks or array bounds checks."
    },
    "command_injection": {
        "name": "Arbitrary Command Execution",
        "description": "Inadequate sanitization of shell metacharacters in system calls, enabling command chaining and execution of unauthorized operating system commands."
    },
    "input_validation": {
        "name": "Improper Input Validation",
        "description": "Failure to validate data structures, null characters, or control character sequences, causing unexpected application states or parser crashes."
    },
    "use_after_free": {
        "name": "Use After Free (UAF)",
        "description": "Referencing memory after it has been deallocated, which can lead to memory corruption, arbitrary code execution, or information disclosure."
    },
    "off_by_one": {
        "name": "Off-by-One Boundary Overwrite",
        "description": "A loop or copy boundary is miscalculated by exactly one byte, causing adjacent variables or control structure contamination."
    },
    "backdoor": {
        "name": "Hidden Backdoor Access",
        "description": "Undocumented command structures or hidden execution paths designed to bypass standard authentication controls."
    },
    "credential_leak": {
        "name": "Hardcoded Credential Exposure",
        "description": "Embedded passwords, private keys, API secrets, or certificates located directly within the binary or source code structure."
    },
    "malware_persistence": {
        "name": "Malware Persistence Mechanism",
        "description": "Actions that attempt to register automatic execution hooks via registry keys, startup folders, or system tasks to maintain access."
    },
    "ransomware_encryption": {
        "name": "Unauthorized Cryptographic Activity",
        "description": "Suspicious execution of high-entropy cryptographic algorithms designed to lock or encrypt files without explicit user consent."
    },
    "keylogger_module": {
        "name": "Keyboard Input Monitoring",
        "description": "Registration of global key hooks or polling interfaces aimed at intercepting and recording keystrokes."
    },
    "basic_input": {
        "name": "Standard Input Parsing Capability",
        "description": "The binary accepts and processes standard data input parameters to verify normal operational functionality."
    }
}

def save_crash_report(crashes: list[dict], target_name: str, total_tested: int, patch_code: str = "", exploit_code: str = "", language: str = "c", binary_mode: bool = False, decompilation_info=None, profile: str = "legacy-audit", static_only: bool = False, raw_decompiled_code: str = "", clean_source_code: str = "", webhook_url: str = ""):
    """Save all crash-causing payloads to a JSON report file and generate a premium HTML dashboard."""
    os.makedirs("crashes", exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"crashes/crash_report_{target_name}_{timestamp}.json"

    report = {
        "tool": "Mutagen v2.0",
        "target": target_name,
        "analysis_mode": "binary_decompilation" if binary_mode else "source_code",
        "profile": profile,
        "static_only": static_only,
        "timestamp": timestamp,
        "total_payloads_tested": total_tested,
        "total_crashes_found": len(crashes),
        "crash_rate": f"{(len(crashes)/total_tested*100):.1f}%" if total_tested else "0%",
        "unique_vuln_types": list(set(c.get("vuln_type", "") for c in crashes)),
        "unique_cwes": list(set(c.get("cwe", "") for c in crashes if c.get("cwe"))),
        "crashes": crashes,
    }

    if binary_mode:
        report["decompiled_source_raw"] = raw_decompiled_code
        report["decompiled_source_deobfuscated"] = clean_source_code
        if decompilation_info:
            report["decompilation"] = {
                "decompiler": decompilation_info.decompiler_used,
                "architecture": decompilation_info.architecture,
                "binary_format": decompilation_info.binary_format,
                "functions_decompiled": decompilation_info.functions_found,
                "binary_path": decompilation_info.binary_path,
            }

    with open(json_file, "w") as f:
        json.dump(report, f, indent=2)

    # --- HTML REPORT ---------------------------------------------------
    html_file = f"crashes/report_{target_name}_{timestamp}.html"

    crash_rows = ""
    crashes_sorted = sorted(crashes, key=lambda x: x.get("confidence_score", 5), reverse=True)
    for i, c in enumerate(crashes_sorted):
        args_display = ", ".join(c.get("args", [c.get("payload", "N/A")]))
        if len(args_display) > 60:
            args_display = args_display[:57] + "..."
        severity = c.get("severity", "unknown")
        sev_class = severity if severity in ("critical", "high", "medium", "low") else "low"

        # Security: Prevent XSS by HTML-escaping all untrusted input
        safe_args = html.escape(args_display)
        safe_vuln = html.escape(c.get("vuln_type", "unknown"))
        safe_cwe = html.escape(c.get("cwe", "N/A"))
        safe_crash = html.escape(c.get("crash_type", ""))
        safe_reason = html.escape(c.get("reason", ""))
        safe_sev = html.escape(severity.upper())
        safe_class = html.escape(sev_class)

        # Get confidence score
        conf_val = c.get("confidence_score", 5)
        if conf_val >= 8:
            conf_color = "#ff4d4d"
        elif conf_val >= 5:
            conf_color = "#ffb84d"
        else:
            conf_color = "#00ff88"

        # Format mitigations
        mitigations = c.get("mitigations_detected", [])
        safe_mitigations = ", ".join(html.escape(m) for m in mitigations) if mitigations else "None"

        # Format Data Flow as a visual chain
        data_flow = c.get("data_flow", [])
        if data_flow:
            safe_flow = " &rarr; ".join(f"<code style='color: #00ccff; border: none; background: rgba(0, 204, 255, 0.05); padding: 0.1rem 0.3rem;'>{html.escape(f)}</code>" for f in data_flow)
        else:
            safe_flow = "<span style='color: #64748b;'>None</span>"

        # Get compliance mappings
        comp = map_cwe_to_compliance(safe_cwe)
        safe_pci = html.escape(comp.get("PCI-DSS", ""))
        safe_soc2 = html.escape(comp.get("SOC2", ""))

        crash_rows += f"""
        <tr>
            <td>{i+1}</td>
            <td><span class="badge {safe_class}">{safe_sev}</span></td>
            <td>{safe_vuln}</td>
            <td>{safe_cwe}</td>
            <td><strong style="color: {conf_color}; font-family: 'JetBrains Mono', monospace;">{conf_val}/10</strong></td>
            <td><code>{safe_args}</code></td>
            <td>{safe_flow}</td>
            <td>{safe_crash}</td>
            <td class="reason">
                <div>{safe_reason}</div>
                <div style="margin-top: 0.5rem; font-size: 0.8rem; color: #94a3b8;"><strong>Mitigations:</strong> {safe_mitigations}</div>
                <div style="margin-top: 0.3rem; font-size: 0.8rem; color: #f59e0b;"><strong>Compliance:</strong> PCI-DSS: <em>{safe_pci}</em> &bull; SOC2: <em>{safe_soc2}</em></div>
            </td>
        </tr>"""

    crash_rate = (len(crashes)/total_tested*100) if total_tested else 0
    vuln_types = list(set(c.get("vuln_type", "") for c in crashes))

    # --- PARSE SECURITY TELEMETRY (IoCs & Capabilities) ---------------------
    ioc_rows = ""
    capability_rows = ""
    ioc_panel_html = ""
    capability_panel_html = ""

    if profile == "malware-triage" or static_only:
        # Extract capabilities
        caps_found = {}
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        for c in crashes:
            vt = c.get("vuln_type", "unknown")
            sev = c.get("severity", "unknown").lower()
            if vt not in caps_found:
                caps_found[vt] = {
                    "count": 0,
                    "severity": sev,
                }
            caps_found[vt]["count"] += 1
            if severity_rank.get(sev, 0) > severity_rank.get(caps_found[vt]["severity"], 0):
                caps_found[vt]["severity"] = sev

        # Build capability matrix rows
        for i, (vt, details) in enumerate(caps_found.items()):
            vt_norm = vt.lower().strip().replace(" ", "_").replace("-", "_")

            # Lookup capability details
            cap_info = VULN_CAPABILITIES.get(vt_norm)
            if cap_info:
                cap_name = cap_info["name"]
                cap_desc = cap_info["description"]
            else:
                # Fallback for custom or dynamically generated types
                cap_name = vt.replace("_", " ").title()
                cap_desc = "Custom security vulnerability signature identified during static triage."

            count = details["count"]
            occurrences_str = f"Detected {count} crash-causing payload context{'s' if count > 1 else ''}."
            details_text = f"{cap_desc} ({occurrences_str})"

            sev = details["severity"].upper()
            sev_class = details["severity"].lower() if details["severity"].lower() in ("critical", "high", "medium", "low") else "low"
            capability_rows += f"""
            <tr>
                <td>{i+1}</td>
                <td><span class="badge {sev_class}">{sev}</span></td>
                <td><strong>{html.escape(cap_name)}</strong></td>
                <td>{html.escape(details_text)}</td>
            </tr>"""

        # Extract IoCs using simple regexes/rules
        import re
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        domain_pattern = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        registry_pattern = re.compile(r'\b(?:HKLM|HKCU|SOFTWARE|Registry|System)\\[a-zA-Z0-9._\-\\]+\b', re.IGNORECASE)
        file_pattern = re.compile(r'\b[a-zA-Z0-9._-]+\.(?:exe|dll|sys|bat|sh|bin|conf|ini|key)\b', re.IGNORECASE)

        extracted_ips = set()
        extracted_domains = set()
        extracted_files = set()
        extracted_registry = set()

        for c in crashes:
            text_to_scan = f"{c.get('vuln_type', '')} {c.get('reason', '')} {' '.join(c.get('args', []))} {c.get('input_data', '')}"
            for ip in ip_pattern.findall(text_to_scan):
                if ip not in ("127.0.0.1", "0.0.0.0"):
                    extracted_ips.add(ip)
            for d in domain_pattern.findall(text_to_scan):
                if not d[0].isdigit() and "." in d and len(d) > 4:
                    if d.lower() not in ("example.com", "mutagen.exe", "localhost"):
                        extracted_domains.add(d.lower())
            for reg in registry_pattern.findall(text_to_scan):
                extracted_registry.add(reg)
            for f in file_pattern.findall(text_to_scan):
                if f.lower() not in ("mutagen.exe", "gcc.exe", "rustc.exe"):
                    extracted_files.add(f)

        # Build IoC rows
        ioc_count = 1
        for ip in sorted(extracted_ips):
            ioc_rows += f"<tr><td>{ioc_count}</td><td><span class='badge critical'>IP ADDRESS</span></td><td><code>{html.escape(ip)}</code></td><td>External Command & Control (C2) endpoint candidate</td></tr>"
            ioc_count += 1
        for d in sorted(extracted_domains):
            ioc_rows += f"<tr><td>{ioc_count}</td><td><span class='badge high'>DOMAIN</span></td><td><code>{html.escape(d)}</code></td><td>External domain referenced in binary stubs</td></tr>"
            ioc_count += 1
        for r in sorted(extracted_registry):
            ioc_rows += f"<tr><td>{ioc_count}</td><td><span class='badge medium'>REGISTRY KEY</span></td><td><code>{html.escape(r)}</code></td><td>Persistence or system config registry access pointer</td></tr>"
            ioc_count += 1
        for f in sorted(extracted_files):
            ioc_rows += f"<tr><td>{ioc_count}</td><td><span class='badge low'>FILE SYSTEM</span></td><td><code>{html.escape(f)}</code></td><td>Indicator of file creation, dropped payload, or DLL sideloading</td></tr>"
            ioc_count += 1

        if not ioc_rows:
            ioc_rows = "<tr><td colspan='4' style='text-align: center; color: #64748b;'>No network or filesystem indicators of compromise (IoCs) extracted from signatures.</td></tr>"
        if not capability_rows:
            capability_rows = "<tr><td colspan='4' style='text-align: center; color: #64748b;'>No capabilities identified.</td></tr>"

        capability_panel_html = f"""
        <div class="table-container" style="margin-top: 2rem;">
          <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.5rem; margin: 1.5rem 0 1rem 0; color: #fbbf24;">⚡ Threat Capability Matrix</h2>
          <table>
            <thead><tr><th style="width: 50px;">#</th><th style="width: 120px;">Threat Level</th><th style="width: 220px;">Identified Capability</th><th>Behavioral Details</th></tr></thead>
            <tbody>{capability_rows}</tbody>
          </table>
        </div>"""

        ioc_panel_html = f"""
        <div class="table-container" style="margin-top: 2rem;">
          <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.5rem; margin: 1.5rem 0 1rem 0; color: #ff6b6b;">🔬 Extracted Indicators of Compromise (IoCs)</h2>
          <table>
            <thead><tr><th style="width: 50px;">#</th><th style="width: 150px;">Indicator Type</th><th style="width: 250px;">IOC Value</th><th>Description / Context</th></tr></thead>
            <tbody>{ioc_rows}</tbody>
          </table>
        </div>"""

    # Escape patch and exploit code for injection into HTML code blocks
    if binary_mode:
        safe_patch_code = html.escape("// Auto-patch unavailable for binary targets.\n// Source code is required for patch generation.\n// Manual remediation is required based on the vulnerability findings above.")
    else:
        safe_patch_code = html.escape(patch_code or "// No patch code was generated.")
    safe_exploit_code = html.escape(exploit_code or "# No regression exploit script was generated.")

    # Dynamic Tab buttons
    patch_tab_btn = ""
    exploit_tab_btn = ""
    deobfuscated_tab_btn = ""
    raw_decompiled_tab_btn = ""

    if clean_source_code and binary_mode:
        deobfuscated_tab_btn = '<button class="tab-btn" onclick="showTab(\'deobfuscated-tab\')">✨ Deobfuscated Code</button>'
    if raw_decompiled_code and binary_mode:
        raw_decompiled_tab_btn = '<button class="tab-btn" onclick="showTab(\'raw-decompiled-tab\')">🔍 Raw Decompiled</button>'

    if patch_code or binary_mode:
        patch_label = "Remediation Notes" if binary_mode else "Patched Code"
        patch_tab_btn = f'<button class="tab-btn" onclick="showTab(\'patch-tab\')">{patch_label}</button>'
    if exploit_code and not static_only:
        exploit_tab_btn = '<button class="tab-btn" onclick="showTab(\'exploit-tab\')">Exploit Script</button>'

    # Build the code viewer panels if code is present
    deobfuscated_tab_html = ""
    raw_decompiled_tab_html = ""

    if clean_source_code and binary_mode:
        deobfuscated_tab_html = f"""
    <!-- DEOBFUSCATED CODE VIEW -->
    <div id="deobfuscated-tab" class="tab-content">
      <div class="code-viewer">
        <pre><code class="language-c">{html.escape(clean_source_code)}</code></pre>
      </div>
    </div>"""

    if raw_decompiled_code and binary_mode:
        raw_decompiled_tab_html = f"""
    <!-- RAW DECOMPILED VIEW -->
    <div id="raw-decompiled-tab" class="tab-content">
      <div class="code-viewer">
        <pre><code class="language-c">{html.escape(raw_decompiled_code)}</code></pre>
      </div>
    </div>"""

    # Build subtitle based on analysis mode (computed BEFORE the f-string)
    if binary_mode:
        arch_info = ""
        if decompilation_info:
            arch_info = f" | Arch: {html.escape(decompilation_info.architecture)} | Functions: {html.escape(str(decompilation_info.functions_found))}"
        analysis_label = "STATIC TRIAGE" if static_only else "BINARY DECOMPILATION"
        subtitle_line = f'Target: <strong style="color: #ffffff;">{target_name}</strong> | Mode: <code style="color: #ff6b6b; font-size: 0.85rem; padding: 0.2rem 0.4rem;">{analysis_label}</code>{arch_info} | {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
        report_subtitle = f"Binary Analysis Report — {profile.upper()} Profile"
    else:
        analysis_label = "STATIC SCAN" if static_only else "AI-Powered Zero-Day Fuzzer &amp; Auto-Patcher"
        subtitle_line = f'Target: <strong style="color: #ffffff;">{target_name}.{language}</strong> &nbsp;&bull;&nbsp; Mode: <code style="color: #00ccff; font-size: 0.85rem; padding: 0.2rem 0.4rem;">{analysis_label}</code> &nbsp;&bull;&nbsp; {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
        report_subtitle = f"Source Code Audit — {profile.upper()} Profile"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mutagen Report: {target_name}</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<!-- Prism Syntax Highlighting Themes -->
<link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Inter', system-ui, sans-serif;
    background: radial-gradient(circle at 50% 0%, #151528 0%, #080810 100%);
    color: #e2e8f0;
    padding: 3rem;
    min-height: 100vh;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{ text-align: center; margin-bottom: 3rem; }}
  .header h1 {{
    font-family: 'Outfit', sans-serif;
    font-size: 3.8rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    background: linear-gradient(135deg, #00ff88, #00ccff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 0 30px rgba(0, 255, 136, 0.25));
  }}
  .header .subtitle {{ color: #94a3b8; margin-top: 0.5rem; font-size: 1.1rem; }}

  /* Tabs Layout */
  .tabs {{
    display: flex;
    gap: 0.75rem;
    margin-bottom: 2rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    padding-bottom: 0.75rem;
  }}
  .tab-btn {{
    background: none;
    border: none;
    color: #94a3b8;
    font-family: 'Outfit', sans-serif;
    font-size: 1rem;
    font-weight: 600;
    padding: 0.75rem 1.5rem;
    cursor: pointer;
    transition: all 0.25s ease-in-out;
    border-radius: 8px;
    border: 1px solid transparent;
  }}
  .tab-btn:hover {{
    color: #ffffff;
    background: rgba(255, 255, 255, 0.03);
  }}
  .tab-btn.active {{
    color: #00ff88;
    background: rgba(0, 255, 136, 0.07);
    border: 1px solid rgba(0, 255, 136, 0.2);
    box-shadow: 0 0 15px rgba(0, 255, 136, 0.05);
  }}
  .tab-content {{
    display: none;
  }}
  .tab-content.active {{
    display: block;
    animation: fadeIn 0.4s ease-out forwards;
  }}

  /* Stats cards */
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 3rem; }}
  .stat-card {{
    background: rgba(15, 15, 25, 0.5);
    border: 1px solid rgba(255, 255, 255, 0.04);
    border-radius: 16px;
    padding: 2rem;
    text-align: center;
    backdrop-filter: blur(16px);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }}
  .stat-card:hover {{
    transform: translateY(-4px);
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.6);
    border-color: rgba(255, 255, 255, 0.08);
  }}
  .stat-card .value {{ font-size: 2.8rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; }}
  .stat-card .label {{ color: #94a3b8; font-size: 0.85rem; margin-top: 0.5rem; text-transform: uppercase; letter-spacing: 0.12em; font-weight: 600; }}
  .stat-card.danger .value {{ color: #ff4d4d; text-shadow: 0 0 20px rgba(255, 77, 77, 0.25); }}
  .stat-card.success .value {{ color: #00ff88; text-shadow: 0 0 20px rgba(0, 255, 136, 0.25); }}
  .stat-card.info .value {{ color: #00ccff; text-shadow: 0 0 20px rgba(0, 204, 255, 0.25); }}
  .stat-card.warn .value {{ color: #ffb84d; text-shadow: 0 0 20px rgba(255, 184, 77, 0.25); }}

  /* Table styling */
  .table-container {{
    background: rgba(15, 15, 25, 0.5);
    border: 1px solid rgba(255, 255, 255, 0.04);
    border-radius: 16px;
    backdrop-filter: blur(16px);
    overflow-x: auto;
    box-shadow: 0 20px 40px rgba(0,0,0,0.5);
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    background: rgba(20, 20, 35, 0.8);
    padding: 1.2rem 1.5rem;
    text-align: left;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #00ccff;
    border-bottom: 2px solid rgba(0, 204, 255, 0.15);
  }}
  td {{ padding: 1.2rem 1.5rem; border-bottom: 1px solid rgba(255, 255, 255, 0.04); font-size: 0.95rem; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255, 255, 255, 0.01); }}
  code {{
    background: rgba(0, 0, 0, 0.4);
    padding: 0.4rem 0.6rem;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    color: #00ff88;
    word-break: break-all;
    border: 1px solid rgba(0, 255, 136, 0.08);
  }}

  /* Badges */
  .badge {{
    padding: 0.4rem 0.8rem;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    display: inline-block;
  }}
  .badge.critical {{ background: rgba(255, 77, 77, 0.12); color: #ff4d4d; border: 1px solid rgba(255, 77, 77, 0.25); }}
  .badge.high {{ background: rgba(255, 136, 68, 0.12); color: #ff8844; border: 1px solid rgba(255, 136, 68, 0.25); }}
  .badge.medium {{ background: rgba(255, 184, 77, 0.12); color: #ffb84d; border: 1px solid rgba(255, 184, 77, 0.25); }}
  .badge.low {{ background: rgba(0, 255, 136, 0.12); color: #00ff88; border: 1px solid rgba(0, 255, 136, 0.25); }}
  .reason {{ font-size: 0.9rem; color: #cbd5e1; line-height: 1.55; }}

  /* Code tab viewports */
  .code-viewer {{
    background: rgba(10, 10, 20, 0.6);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 16px;
    padding: 1.5rem;
    backdrop-filter: blur(16px);
    box-shadow: 0 20px 45px rgba(0, 0, 0, 0.6);
  }}
  pre[class*="language-"] {{
    margin: 0 !important;
    background: none !important;
    border-radius: 0 !important;
    padding: 0 !important;
  }}

  .footer {{ text-align: center; margin-top: 5rem; color: #64748b; font-size: 0.8rem; letter-spacing: 0.08em; font-weight: 600; }}

  @keyframes fadeIn {{
    from {{ opacity: 0; transform: translateY(15px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}
  tr {{ animation: fadeIn 0.4s ease-out forwards; opacity: 0; }}
  tr:nth-child(1) {{ animation-delay: 0.05s; }}
  tr:nth-child(2) {{ animation-delay: 0.1s; }}
  tr:nth-child(3) {{ animation-delay: 0.15s; }}
  tr:nth-child(4) {{ animation-delay: 0.2s; }}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>MUTAGEN</h1>
      <p class="subtitle">{report_subtitle}</p>
      <p class="subtitle" style="margin-top: 1rem; font-size: 0.95rem;">{subtitle_line}</p>
    </div>

    <div class="tabs">
      <button class="tab-btn active" onclick="showTab('dashboard-tab')">📊 Overview</button>
      {deobfuscated_tab_btn}
      {raw_decompiled_tab_btn}
      {patch_tab_btn}
      {exploit_tab_btn}
    </div>

    <!-- DASHBOARD VIEW -->
    <div id="dashboard-tab" class="tab-content active">
      <div class="stats">
        <div class="stat-card info"><div class="value">{total_tested}</div><div class="label">Payloads Tested</div></div>
        <div class="stat-card danger"><div class="value">{len(crashes)}</div><div class="label">Crashes Found</div></div>
        <div class="stat-card warn"><div class="value">{crash_rate:.0f}%</div><div class="label">Crash Rate</div></div>
        <div class="stat-card success"><div class="value">{len(vuln_types)}</div><div class="label">Vuln Types</div></div>
      </div>
      <div class="table-container">
        <table>
          <thead><tr><th>#</th><th>Severity</th><th>Vuln Type</th><th>CWE</th><th>Confidence</th><th>Payload</th><th>Data Flow (Source &rarr; Sink)</th><th>Crash Type</th><th>Reason &amp; Mitigations</th></tr></thead>
          <tbody>{crash_rows}</tbody>
        </table>
      </div>
      {capability_panel_html}
      {ioc_panel_html}
    </div>

    {deobfuscated_tab_html}
    {raw_decompiled_tab_html}

    <!-- CODE PATCH VIEW -->
    <div id="patch-tab" class="tab-content">
      <div class="code-viewer">
        <pre><code class="language-{language}">{safe_patch_code}</code></pre>
      </div>
    </div>

    <!-- REGRESSION EXPLOIT VIEW -->
    <div id="exploit-tab" class="tab-content">
      <div class="code-viewer">
        <pre><code class="language-python">{safe_exploit_code}</code></pre>
      </div>
    </div>

    <div class="footer">GENERATED BY MUTAGEN V2.0 &bull; BUILT BY BUNNY-SYSD</div>
  </div>

  <!-- Prism.js Script for syntax highlighting -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-core.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/autoloader/prism-autoloader.min.js"></script>
  <script>
    function showTab(tabId) {{
        // Hide all contents and remove active class from all buttons
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

        // Show selected tab content and activate target button
        document.getElementById(tabId).classList.add('active');
        event.currentTarget.classList.add('active');
    }}
  </script>
</body>
</html>"""

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Fire webhook if configured
    if webhook_url:
        import requests
        try:
            requests.post(webhook_url, json=report, headers={"Content-Type": "application/json"}, timeout=10)
        except Exception:
            pass

    return json_file, html_file
