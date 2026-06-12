import os
import json
import datetime
import html

def save_crash_report(crashes: list[dict], target_name: str, total_tested: int):
    """Save all crash-causing payloads to a JSON report file."""
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
    # Generate a beautiful HTML report that can be opened in a browser.
    # This is WAY more impressive than raw JSON when showing people.
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
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mutagen Report: {target_name}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ 
    font-family: 'Inter', system-ui, sans-serif; 
    background: radial-gradient(circle at 50% 0%, #1a1a2e 0%, #0a0a0f 100%);
    color: #e0e0e0; 
    padding: 3rem; 
    min-height: 100vh;
  }}
  .header {{ text-align: center; margin-bottom: 3rem; }}
  .header h1 {{ 
    font-size: 3.5rem; 
    font-weight: 800;
    letter-spacing: -0.05em;
    background: linear-gradient(135deg, #00ff88, #00ccff); 
    -webkit-background-clip: text; 
    -webkit-text-fill-color: transparent; 
    filter: drop-shadow(0 0 20px rgba(0, 255, 136, 0.2));
  }}
  .header .subtitle {{ color: #888; margin-top: 0.5rem; font-size: 1.1rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 3rem; }}
  .stat-card {{ 
    background: rgba(18, 18, 26, 0.6); 
    border: 1px solid rgba(255, 255, 255, 0.05); 
    border-radius: 16px; 
    padding: 2rem; 
    text-align: center; 
    backdrop-filter: blur(10px);
    transition: transform 0.3s ease, box-shadow 0.3s ease;
  }}
  .stat-card:hover {{ 
    transform: translateY(-5px); 
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5); 
  }}
  .stat-card .value {{ font-size: 2.5rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; }}
  .stat-card .label {{ color: #a0a0a0; font-size: 0.9rem; margin-top: 0.5rem; text-transform: uppercase; letter-spacing: 0.1em; }}
  .stat-card.danger .value {{ color: #ff4d4d; text-shadow: 0 0 15px rgba(255, 77, 77, 0.3); }}
  .stat-card.success .value {{ color: #00ff88; text-shadow: 0 0 15px rgba(0, 255, 136, 0.3); }}
  .stat-card.info .value {{ color: #00ccff; text-shadow: 0 0 15px rgba(0, 204, 255, 0.3); }}
  .stat-card.warn .value {{ color: #ffb84d; text-shadow: 0 0 15px rgba(255, 184, 77, 0.3); }}
  
  .table-container {{
    background: rgba(18, 18, 26, 0.6);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 16px;
    backdrop-filter: blur(10px);
    overflow-x: auto;
    box-shadow: 0 20px 40px rgba(0,0,0,0.4);
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ 
    background: rgba(26, 26, 46, 0.8); 
    padding: 1.2rem 1.5rem; 
    text-align: left; 
    font-size: 0.85rem; 
    text-transform: uppercase; 
    letter-spacing: 0.1em; 
    color: #00ccff; 
    border-bottom: 2px solid rgba(0, 204, 255, 0.2);
  }}
  td {{ padding: 1.2rem 1.5rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 0.95rem; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
  code {{ 
    background: rgba(0, 0, 0, 0.3); 
    padding: 0.4rem 0.6rem; 
    border-radius: 6px; 
    font-family: 'JetBrains Mono', monospace; 
    font-size: 0.85rem; 
    color: #00ff88; 
    word-break: break-all; 
    border: 1px solid rgba(0, 255, 136, 0.1);
  }}
  .badge {{ 
    padding: 0.4rem 0.8rem; 
    border-radius: 999px; 
    font-size: 0.75rem; 
    font-weight: 700; 
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .badge.critical {{ background: rgba(255, 77, 77, 0.15); color: #ff4d4d; border: 1px solid rgba(255, 77, 77, 0.3); }}
  .badge.high {{ background: rgba(255, 136, 68, 0.15); color: #ff8844; border: 1px solid rgba(255, 136, 68, 0.3); }}
  .badge.medium {{ background: rgba(255, 184, 77, 0.15); color: #ffb84d; border: 1px solid rgba(255, 184, 77, 0.3); }}
  .badge.low {{ background: rgba(0, 255, 136, 0.15); color: #00ff88; border: 1px solid rgba(0, 255, 136, 0.3); }}
  .reason {{ max-width: 350px; font-size: 0.9rem; color: #a0a0a0; line-height: 1.5; }}
  .footer {{ text-align: center; margin-top: 4rem; color: #555; font-size: 0.85rem; letter-spacing: 0.05em; }}
  
  @keyframes fadeIn {{
    from {{ opacity: 0; transform: translateY(20px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}
  tr {{ animation: fadeIn 0.5s ease-out forwards; opacity: 0; }}
  tr:nth-child(1) {{ animation-delay: 0.1s; }}
  tr:nth-child(2) {{ animation-delay: 0.2s; }}
  tr:nth-child(3) {{ animation-delay: 0.3s; }}
  tr:nth-child(4) {{ animation-delay: 0.4s; }}
  tr:nth-child(5) {{ animation-delay: 0.5s; }}
</style>
</head>
<body>
  <div class="header">
    <h1>MUTAGEN</h1>
    <p class="subtitle">AI-Powered Zero-Day Fuzzer — Crash Report</p>
    <p class="subtitle" style="margin-top: 1rem;">Target: <strong style="color: #fff;">{target_name}.c</strong> &nbsp;|&nbsp; {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
  </div>
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
  <div class="footer">GENERATED BY MUTAGEN V2.0 &bull; BUILT BY AARON ALVA</div>
</body>
</html>"""

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    return json_file, html_file
