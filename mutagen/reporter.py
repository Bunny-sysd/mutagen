import os
import json
import datetime
import html

def save_crash_report(crashes: list[dict], target_name: str, total_tested: int, patch_code: str = "", exploit_code: str = ""):
    """Save all crash-causing payloads to a JSON report file and generate a premium HTML dashboard."""
    os.makedirs("crashes", exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"crashes/crash_report_{target_name}_{timestamp}.json"

    report = {
        "tool": "Mutagen v2.0",
        "target": target_name,
        "timestamp": timestamp,
        "total_payloads_tested": total_tested,
        "total_crashes_found": len(crashes),
        "crash_rate": f"{(len(crashes)/total_tested*100):.1f}%" if total_tested else "0%",
        "unique_vuln_types": list(set(c.get("vuln_type", "") for c in crashes)),
        "unique_cwes": list(set(c.get("cwe", "") for c in crashes if c.get("cwe"))),
        "crashes": crashes,
    }

    with open(json_file, "w") as f:
        json.dump(report, f, indent=2)

    # --- HTML REPORT ---------------------------------------------------
    html_file = f"crashes/report_{target_name}_{timestamp}.html"
    
    crash_rows = ""
    for i, c in enumerate(crashes):
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

        crash_rows += f"""
        <tr>
            <td>{i+1}</td>
            <td><span class="badge {safe_class}">{safe_sev}</span></td>
            <td>{safe_vuln}</td>
            <td>{safe_cwe}</td>
            <td><code>{safe_args}</code></td>
            <td>{safe_crash}</td>
            <td class="reason">{safe_reason}</td>
        </tr>"""

    crash_rate = (len(crashes)/total_tested*100) if total_tested else 0
    vuln_types = list(set(c.get("vuln_type", "") for c in crashes))
    
    # Escape patch and exploit code for injection into HTML code blocks
    safe_patch_code = html.escape(patch_code or "// No patch code was generated.")
    safe_exploit_code = html.escape(exploit_code or "# No regression exploit script was generated.")
    
    # Dynamic Tab buttons
    patch_tab_btn = ""
    exploit_tab_btn = ""
    if patch_code:
        patch_tab_btn = '<button class="tab-btn" onclick="showTab(\'patch-tab\')">🩹 Patched Code</button>'
    if exploit_code:
        exploit_tab_btn = '<button class="tab-btn" onclick="showTab(\'exploit-tab\')">💀 Exploit Script</button>'

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
      <h1>🧬 MUTAGEN</h1>
      <p class="subtitle">AI-Powered Zero-Day Fuzzer & Auto-Patcher</p>
      <p class="subtitle" style="margin-top: 1rem; font-size: 0.95rem;">Target: <strong style="color: #ffffff;">{target_name}.c</strong> &nbsp;&bull;&nbsp; Compiled: <code style="color: #00ccff; font-size: 0.85rem; padding: 0.2rem 0.4rem;">{target_name}.exe</code> &nbsp;&bull;&nbsp; {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="tabs">
      <button class="tab-btn active" onclick="showTab('dashboard-tab')">📊 Overview</button>
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
          <thead><tr><th>#</th><th>Severity</th><th>Vuln Type</th><th>CWE</th><th>Payload</th><th>Crash Type</th><th>Reason</th></tr></thead>
          <tbody>{crash_rows}</tbody>
        </table>
      </div>
    </div>

    <!-- CODE PATCH VIEW -->
    <div id="patch-tab" class="tab-content">
      <div class="code-viewer">
        <pre><code class="language-c">{safe_patch_code}</code></pre>
      </div>
    </div>

    <!-- REGRESSION EXPLOIT VIEW -->
    <div id="exploit-tab" class="tab-content">
      <div class="code-viewer">
        <pre><code class="language-python">{safe_exploit_code}</code></pre>
      </div>
    </div>

    <div class="footer">GENERATED BY MUTAGEN V2.0 &bull; BUILT BY AARON ALVA</div>
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

    return json_file, html_file
