import os
import sys
import glob
import json
import time
import argparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

# Add current directory to path so mutagen package imports work cleanly
sys.path.insert(0, os.getcwd())

from mutagen.core import run_fuzzer
from mutagen.cli import load_env, is_supported_language

console = Console(force_terminal=True, force_jupyter=False)

def get_supported_files(directory: str) -> list[str]:
    """Finds all supported source files recursively in the given directory."""
    supported_files = []
    for root, _, files in os.walk(directory):
        # Exclude internal virtualenvs, cache dirs, git etc.
        if any(exclude in root.lower() for exclude in [".venv", "venv", ".git", ".gemini", "node_modules", "crashes", "htmlcov", "tests"]):
            continue
        for file in files:
            ext = os.path.splitext(file)[1]
            if is_supported_language(ext):
                supported_files.append(os.path.join(root, file))
    return supported_files

def find_newest_report(target_name: str, start_time: float) -> str | None:
    """Finds the newest JSON crash report generated for a target after start_time."""
    safe_target = "".join(c if c.isalnum() or c in "._-" else "_" for c in target_name)
    pattern = os.path.join("crashes", f"crash_report_{safe_target}_*.json")
    matching_files = glob.glob(pattern)
    
    newest_file = None
    newest_mtime = 0.0
    
    for f in matching_files:
        mtime = os.path.getmtime(f)
        if mtime >= start_time - 5:  # Allow 5s clock skew buffer
            if mtime > newest_mtime:
                newest_mtime = mtime
                newest_file = f
                
    return newest_file

def generate_html_report(results: list[dict], output_path: str):
    """Generates a premium HTML/CSS dashboard containing all batch findings."""
    total_files = len(results)
    audited_files = [r for r in results if r["status"] == "success"]
    failed_files = [r for r in results if r["status"] == "failed"]
    
    # Calculate totals
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_findings = 0
    
    for r in results:
        for f in r.get("findings", []):
            sev = f.get("severity", "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
                total_findings += 1
                
    # Calculate simple health score (starts at 100, drops by severity weight)
    score_penalty = (severity_counts["critical"] * 25) + (severity_counts["high"] * 10) + (severity_counts["medium"] * 3) + (severity_counts["low"] * 1)
    health_score = max(0, 100 - score_penalty)
    
    # Sleek dark mode visual template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mutagen Unified Security Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0f172a;
            --panel-bg: rgba(30, 41, 59, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --crit-color: #ef4444;
            --high-color: #f97316;
            --med-color: #eab308;
            --low-color: #3b82f6;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            background: radial-gradient(circle at top right, #1e1b4b, var(--bg-dark));
            font-family: 'Outfit', sans-serif;
            color: var(--text-main);
            min-height: 100vh;
            padding: 2.5rem;
        }}
        
        header {{
            max-width: 1200px;
            margin: 0 auto 3rem auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .brand {{
            display: flex;
            flex-direction: column;
        }}
        
        .brand h1 {{
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #60a5fa, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .brand p {{
            color: var(--text-muted);
            font-size: 0.95rem;
            margin-top: 0.25rem;
        }}
        
        .health-badge {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            padding: 0.75rem 1.5rem;
            border-radius: 12px;
            display: flex;
            align-items: center;
            gap: 1rem;
            backdrop-filter: blur(10px);
        }}
        
        .health-val {{
            font-size: 2rem;
            font-weight: 800;
            color: {('#22c55e' if health_score >= 80 else '#eab308' if health_score >= 50 else '#ef4444')};
        }}
        
        .dashboard-grid {{
            max-width: 1200px;
            margin: 0 auto 3rem auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
        }}
        
        .stat-card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
        }}
        
        .stat-card.critical::before {{ background: var(--crit-color); }}
        .stat-card.high::before {{ background: var(--high-color); }}
        .stat-card.medium::before {{ background: var(--med-color); }}
        .stat-card.low::before {{ background: var(--low-color); }}
        
        .stat-title {{
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.05em;
        }}
        
        .stat-val {{
            font-size: 2.75rem;
            font-weight: 800;
            margin: 0.75rem 0;
        }}
        
        .stat-footer {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        
        main {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .section-header {{
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .file-panel {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(12px);
            overflow: hidden;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        
        .file-panel:hover {{
            border-color: rgba(255, 255, 255, 0.15);
            box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5);
        }}
        
        .file-header {{
            padding: 1.25rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}
        
        .file-info {{
            display: flex;
            align-items: center;
            gap: 1.25rem;
        }}
        
        .file-name {{
            font-weight: 600;
            font-size: 1.1rem;
        }}
        
        .file-path {{
            color: var(--text-muted);
            font-size: 0.85rem;
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .file-stats {{
            display: flex;
            gap: 0.5rem;
        }}
        
        .badge {{
            padding: 0.35rem 0.75rem;
            border-radius: 8px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .badge.critical {{ background: rgba(239, 68, 68, 0.15); color: var(--crit-color); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge.high {{ background: rgba(249, 115, 22, 0.15); color: var(--high-color); border: 1px solid rgba(249, 115, 22, 0.3); }}
        .badge.medium {{ background: rgba(234, 179, 8, 0.15); color: var(--med-color); border: 1px solid rgba(234, 179, 8, 0.3); }}
        .badge.low {{ background: rgba(59, 130, 246, 0.15); color: var(--low-color); border: 1px solid rgba(59, 130, 246, 0.3); }}
        .badge.clean {{ background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.3); }}
        .badge.failed {{ background: rgba(239, 68, 68, 0.2); color: var(--crit-color); }}
        
        .file-details {{
            display: none;
            padding: 0 1.5rem 1.5rem 1.5rem;
            border-top: 1px solid var(--border-color);
            background: rgba(15, 23, 42, 0.4);
        }}
        
        .finding-card {{
            background: rgba(30, 41, 59, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.25rem;
            margin-top: 1.25rem;
        }}
        
        .finding-title {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }}
        
        .finding-name {{
            font-size: 1.05rem;
            font-weight: 600;
        }}
        
        .finding-reason {{
            font-size: 0.95rem;
            color: #cbd5e1;
            line-height: 1.5;
            margin-bottom: 1rem;
        }}
        
        .finding-meta {{
            display: flex;
            gap: 1.5rem;
            font-size: 0.8rem;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .finding-payload {{
            margin-top: 1rem;
            background: #020617;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            border: 1px solid rgba(255,255,255,0.05);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: #c084fc;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <h1>Mutagen Security Audit Report</h1>
            <p>Unified scan results compiled on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        <div class="health-badge">
            <span class="stat-title">Workspace Health Score</span>
            <div class="health-val">{health_score}</div>
        </div>
    </header>

    <div class="dashboard-grid">
        <div class="stat-card critical">
            <div class="stat-title">Critical Severity</div>
            <div class="stat-val">{severity_counts["critical"]}</div>
            <div class="stat-footer">Direct code exploitation risk</div>
        </div>
        <div class="stat-card high">
            <div class="stat-title">High Severity</div>
            <div class="stat-val">{severity_counts["high"]}</div>
            <div class="stat-footer">High threat logical bypasses</div>
        </div>
        <div class="stat-card medium">
            <div class="stat-title">Medium Severity</div>
            <div class="stat-val">{severity_counts["medium"]}</div>
            <div class="stat-footer">Validation / config issues</div>
        </div>
        <div class="stat-card low">
            <div class="stat-title">Low Severity / Info</div>
            <div class="stat-val">{severity_counts["low"]}</div>
            <div class="stat-footer">Reconnaissance & design details</div>
        </div>
    </div>

    <main>
        <div class="section-header">
            <span>Audited Project Resources ({total_files} files)</span>
        </div>
        
    # Pre-render file panels for Python 3.10+ compatibility
    file_panels = []
    for r in results:
        base_name = os.path.basename(r["file"])
        file_path = r["file"]
        findings = r.get("findings", [])
        status = r.get("status")

        crit_count = len([f for f in findings if f["severity"].lower() == "critical"])
        high_count = len([f for f in findings if f["severity"].lower() == "high"])
        med_count = len([f for f in findings if f["severity"].lower() == "medium"])
        low_count = len([f for f in findings if f["severity"].lower() == "low"])

        crit_badge = f'<span class="badge critical">{crit_count} Critical</span>' if crit_count > 0 else ''
        high_badge = f'<span class="badge high">{high_count} High</span>' if high_count > 0 else ''
        med_badge = f'<span class="badge medium">{med_count} Med</span>' if med_count > 0 else ''
        low_badge = f'<span class="badge low">{low_count} Low</span>' if low_count > 0 else ''
        clean_badge = '<span class="badge clean">Clean</span>' if len(findings) == 0 and status == "success" else ''
        failed_badge = '<span class="badge failed">Audit Failed</span>' if status == "failed" else ''

        clean_msg = '<p style="color: var(--text-muted); font-size: 0.95rem; margin-top: 1rem;">No vulnerabilities detected in this target.</p>' if len(findings) == 0 and status == "success" else ''
        fail_msg = f'<p style="color: var(--crit-color); font-size: 0.95rem; margin-top: 1rem;">Failed to scan: {r.get("error")}</p>' if status == "failed" else ''

        finding_cards = []
        for f in findings:
            vuln_type = f["vuln_type"]
            severity = f["severity"]
            sev_lower = severity.lower()
            reason = f["reason"]
            cwe = f["cwe"] if f["cwe"] else 'N/A'
            conf = f.get("confidence_score", "N/A")
            payload = f.get("payload")
            payload_html = f'<div class="finding-payload"><b>Exploit Trigger Input:</b> {payload}</div>' if payload else ''

            finding_cards.append(f"""
                <div class="finding-card">
                    <div class="finding-title">
                        <div class="finding-name">{vuln_type}</div>
                        <span class="badge {sev_lower}">{severity}</span>
                    </div>
                    <div class="finding-reason">{reason}</div>
                    <div class="finding-meta">
                        <div>CWE: {cwe}</div>
                        <div>Trigger Confidence: {conf}/10</div>
                    </div>
                    {payload_html}
                </div>
            """)

        findings_html = "".join(finding_cards)

        file_panels.append(f"""
        <div class="file-panel">
            <div class="file-header" onclick="toggleDetails(this)">
                <div class="file-info">
                    <div class="file-name">{base_name}</div>
                    <div class="file-path">{file_path}</div>
                </div>
                <div class="file-stats">
                    {crit_badge}
                    {high_badge}
                    {med_badge}
                    {low_badge}
                    {clean_badge}
                    {failed_badge}
                </div>
            </div>
            
            <div class="file-details">
                {clean_msg}
                {fail_msg}
                {findings_html}
            </div>
        </div>
        """)

    file_panels_html = "".join(file_panels)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mutagen Batch Audit Report - {timestamp}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: rgba(22, 31, 48, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-color: #00ff88;
            --crit-color: #ff4d4d;
            --high-color: #ff9900;
            --med-color: #ffcc00;
            --low-color: #3399ff;
        }}
        body {{
            font-family: 'Outfit', sans-serif;
            background: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }}
        .title-area h1 {{
            font-size: 2.2rem;
            margin: 0;
            background: linear-gradient(135deg, #00ff88, #60a5fa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 1.5rem;
        }}
        .stat-title {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; }}
        .stat-val {{ font-size: 2.5rem; font-weight: 700; margin: 0.5rem 0; }}
        .stat-footer {{ font-size: 0.8rem; color: var(--text-muted); }}
        .stat-card.crit .stat-val {{ color: var(--crit-color); }}
        .stat-card.high .stat-val {{ color: var(--high-color); }}
        .stat-card.med .stat-val {{ color: var(--med-color); }}
        .stat-card.low .stat-val {{ color: var(--low-color); }}
        
        .section-header {{
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 0.5rem;
        }}
        .file-panel {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}
        .file-header {{
            padding: 1.2rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}
        .file-header:hover {{ background: rgba(255, 255, 255, 0.03); }}
        .file-name {{ font-weight: 600; font-size: 1.1rem; }}
        .file-path {{ font-size: 0.85rem; color: var(--text-muted); }}
        .file-stats {{ display: flex; gap: 0.5rem; }}
        .badge {{
            padding: 0.25rem 0.6rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge.critical {{ background: rgba(255, 77, 77, 0.2); color: var(--crit-color); border: 1px solid var(--crit-color); }}
        .badge.high {{ background: rgba(255, 153, 0, 0.2); color: var(--high-color); border: 1px solid var(--high-color); }}
        .badge.medium {{ background: rgba(255, 204, 0, 0.2); color: var(--med-color); border: 1px solid var(--med-color); }}
        .badge.low {{ background: rgba(51, 153, 255, 0.2); color: var(--low-color); border: 1px solid var(--low-color); }}
        .badge.clean {{ background: rgba(0, 255, 136, 0.15); color: var(--accent-color); border: 1px solid var(--accent-color); }}
        .badge.failed {{ background: rgba(255, 77, 77, 0.1); color: #ff6666; border: 1px solid #ff6666; }}
        
        .file-details {{
            display: none;
            padding: 0 1.5rem 1.5rem 1.5rem;
            border-top: 1px solid var(--card-border);
        }}
        .finding-card {{
            background: rgba(0, 0, 0, 0.2);
            border-left: 3px solid var(--card-border);
            padding: 1rem;
            margin-top: 1rem;
            border-radius: 4px;
        }}
        .finding-title {{ display: flex; justify-content: space-between; font-weight: 600; }}
        .finding-reason {{ font-size: 0.9rem; margin: 0.5rem 0; color: var(--text-muted); }}
        .finding-meta {{ display: flex; gap: 1.5rem; font-size: 0.8rem; color: var(--text-muted); }}
        .finding-payload {{ font-family: monospace; font-size: 0.8rem; background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 4px; margin-top: 0.5rem; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title-area">
            <h1>Mutagen Batch Audit</h1>
            <div style="color: var(--text-muted); font-size: 0.9rem;">Automated Multi-Target Security Scanning Pipeline</div>
        </div>
        <div style="text-align: right; color: var(--text-muted); font-size: 0.85rem;">
            <div>Target Directory: <b>{target_dir}</b></div>
            <div>Generated: <b>{timestamp}</b></div>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card crit">
            <div class="stat-title">Critical Severity</div>
            <div class="stat-val">{severity_counts["critical"]}</div>
            <div class="stat-footer">Immediate exploit potential</div>
        </div>
        <div class="stat-card high">
            <div class="stat-title">High Severity</div>
            <div class="stat-val">{severity_counts["high"]}</div>
            <div class="stat-footer">High impact vulnerabilities</div>
        </div>
        <div class="stat-card med">
            <div class="stat-title">Medium Severity</div>
            <div class="stat-val">{severity_counts["medium"]}</div>
            <div class="stat-footer">Logic & boundary flaws</div>
        </div>
        <div class="stat-card low">
            <div class="stat-title">Low Severity / Info</div>
            <div class="stat-val">{severity_counts["low"]}</div>
            <div class="stat-footer">Reconnaissance & design details</div>
        </div>
    </div>

    <main>
        <div class="section-header">
            <span>Audited Project Resources ({total_files} files)</span>
        </div>
        
        {file_panels_html}
    </main>

    <script>
        function toggleDetails(header) {{
            const details = header.nextElementSibling;
            if (details.style.display === 'block') {{
                details.style.display = 'none';
            }} else {{
                details.style.display = 'block';
            }}
        }}
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

def main():
    load_env()
    
    # Fix Windows console encoding for colored/unicode output
    import io
    if sys.platform == "win32" and "pytest" not in sys.modules:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    
    parser = argparse.ArgumentParser(description="Mutagen Batch Directory Security Audit Runner")
    parser.add_argument("--dir", default="targets", help="Directory to scan recursively (default: targets)")
    parser.add_argument("--provider", default="gemini", help="AI provider (gemini, openai, claude, ollama)")
    parser.add_argument("--model", default="gemini-2.5-flash", help="AI model name")
    parser.add_argument("--max-payloads", type=int, default=5, help="Max payloads per file")
    parser.add_argument("--output", default="batch_report.html", help="Dashboard HTML output file")
    args = parser.parse_args()
    
    # 1. Discover targets
    console.print(Panel.fit("[bold purple]MUTAGEN BATCH AUDIT[/bold purple]\nScanning directory for targets...", border_style="purple"))
    files = get_supported_files(args.dir)
    
    if not files:
        console.print(f"[yellow]No supported source files found in directory: {args.dir}[/yellow]")
        sys.exit(0)
        
    console.print(f"[green]>> Discovered {len(files)} files to audit.[/green]\n")
    
    # 2. Run scans
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        audit_task = progress.add_task("[cyan]Auditing source targets...", total=len(files))
        
        for file_path in files:
            progress.update(audit_task, description=f"[cyan]Auditing: {os.path.basename(file_path)}")
            start_time = time.time()
            
            try:
                # Run fuzzer programmatically in static_only mode
                run_fuzzer(
                    source_path=file_path,
                    api_key=None,  # Fallback keys will load from environment/env files
                    gcc_path="",
                    max_payloads=args.max_payloads,
                    timeout=60,
                    debug=False,
                    provider=args.provider,
                    model=args.model,
                    static_only=True
                )
                
                # Locate generated JSON report file
                new_report = find_newest_report(os.path.basename(file_path), start_time)
                findings = []
                
                if new_report and os.path.exists(new_report):
                    with open(new_report, "r", encoding="utf-8") as rf:
                        report_data = json.load(rf)
                        findings = report_data.get("crashes", [])
                
                results.append({
                    "file": file_path,
                    "status": "success",
                    "findings": findings
                })
                
            except Exception as e:
                results.append({
                    "file": file_path,
                    "status": "failed",
                    "findings": [],
                    "error": str(e)
                })
                
            progress.advance(audit_task)
            
    # 3. Rich summary table output
    console.print("\n[bold green]BATCH SCANS COMPLETE[/bold green]\n")
    
    summary_table = Table(title="Security Audit Summary", border_style="dim")
    summary_table.add_column("#", justify="right", style="cyan", no_wrap=True)
    summary_table.add_column("Target File", style="white")
    summary_table.add_column("Status", justify="center")
    summary_table.add_column("Critical", justify="right", style="red")
    summary_table.add_column("High", justify="right", style="orange3")
    summary_table.add_column("Medium", justify="right", style="yellow")
    summary_table.add_column("Low", justify="right", style="blue")
    
    for idx, r in enumerate(results, 1):
        if r["status"] == "failed":
            summary_table.add_row(
                str(idx),
                os.path.basename(r["file"]),
                "[red]FAILED[/red]",
                "0", "0", "0", "0"
            )
        else:
            crit = len([f for f in r["findings"] if f["severity"].lower() == "critical"])
            high = len([f for f in r["findings"] if f["severity"].lower() == "high"])
            med = len([f for f in r["findings"] if f["severity"].lower() == "medium"])
            low = len([f for f in r["findings"] if f["severity"].lower() == "low"])
            
            status_str = "[green]CLEAN[/green]" if len(r["findings"]) == 0 else "[yellow]VULNERABLE[/yellow]"
            
            summary_table.add_row(
                str(idx),
                os.path.basename(r["file"]),
                status_str,
                str(crit),
                str(high),
                str(med),
                str(low)
            )
            
    console.print(summary_table)
    
    # 4. Generate HTML Dashboard
    generate_html_report(results, args.output)
    console.print(f"\n[bold green][+] Unified Security Dashboard saved to: [yellow]{args.output}[/yellow][/bold green]")

if __name__ == "__main__":
    main()
