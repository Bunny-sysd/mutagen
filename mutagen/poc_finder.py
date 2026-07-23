"""
GitHub PoC & Vulnerability Intelligence Engine for Mutagen.
Queries public GitHub Security advisories, GitHub repository searches,
and CVE references for real-world exploit scripts and PoCs.
"""

import json
import urllib.parse
import urllib.request
import re

def search_github_pocs(query: str, max_results: int = 3) -> list[dict]:
    """
    Search GitHub repositories for public Proof of Concept (PoC) exploit scripts
    matching the specified vulnerability type, library, or CWE.
    """
    encoded_query = urllib.parse.quote(f"{query} poc exploit")
    url = f"https://api.github.com/search/repositories?q={encoded_query}&sort=stars&order=desc&per_page={max_results}"
    
    headers = {
        "User-Agent": "Mutagen-AI-Security-Agent/2.0",
        "Accept": "application/vnd.github.v3+json"
    }

    results = []
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                items = data.get("items", [])
                for item in items:
                    results.append({
                        "name": item.get("full_name", ""),
                        "url": item.get("html_url", ""),
                        "description": item.get("description", "") or "Public PoC Repository",
                        "stars": item.get("stargazers_count", 0),
                    })
    except Exception:
        pass

    if not results:
        results.append({
            "name": f"GitHub Search ({query})",
            "url": f"https://github.com/search?q={urllib.parse.quote(query)}+poc",
            "description": f"Real-world exploit intelligence query for {query}",
            "stars": 0
        })

    return results

def get_cwe_poc_intelligence(cwe_id: str, vuln_type: str) -> dict:
    """
    Retrieve real-world PoC intelligence and exploit hints for a given CWE or vuln type.
    """
    query = f"{cwe_id} {vuln_type}".strip()
    pocs = search_github_pocs(query, max_results=2)
    
    return {
        "cwe": cwe_id,
        "vuln_type": vuln_type,
        "query": query,
        "github_pocs": pocs
    }
