"""
GitHub PoC & Vulnerability Intelligence Engine for Mutagen.
Queries public GitHub Security advisories, GitHub repository searches,
and CVE references for real-world exploit scripts and PoCs.
"""

import json
import urllib.parse
import urllib.request

# Offline Red Team CWE Exploit Payload Templates (used when offline or rate-limited)
OFFLINE_CWE_DICTIONARY = {
    "CWE-120": {
        "pattern": "Buffer Copy without Checking Size of Input",
        "templates": [
            "A" * 512,
            "A" * 1024,
            "A" * 4096,
            "%x" * 20,
            "A" * 256 + "\x00" + "B" * 256,
        ],
        "technique": "Inject long contiguous bytes exceeding destination buffer bounds to overwrite return address or adjacent struct pointers."
    },
    "CWE-121": {
        "pattern": "Stack-based Buffer Overflow",
        "templates": [
            "A" * 260,
            "A" * 520,
            "A" * 1056,
            "A" * 128 + "\xeb\x04",
        ],
        "technique": "Overwrite local variables and saved frame pointer (EBP/RBP) on the stack."
    },
    "CWE-78": {
        "pattern": "OS Command Injection",
        "templates": [
            "; id;",
            "| id",
            "`id`",
            "$(id)",
            "\n id \n",
            "& ping -c 1 127.0.0.1 &",
            "; cat /etc/passwd",
        ],
        "technique": "Inject shell command delimiters (; | & ` $()) to execute arbitrary OS commands in subshell."
    },
    "CWE-134": {
        "pattern": "Use of Externally-Controlled Format String",
        "templates": [
            "%s%s%s%s%s%s%s%s%s%s",
            "%x.%x.%x.%x.%x.%x.%x.%x",
            "%p.%p.%p.%p.%p.%p.%p.%p",
            "%n",
            "%100$p",
        ],
        "technique": "Supply format specifiers (%s, %x, %p, %n) to leak stack memory or write arbitrary memory addresses."
    },
    "CWE-190": {
        "pattern": "Integer Overflow or Wraparound",
        "templates": [
            "2147483647",
            "4294967295",
            "-1",
            "9223372036854775807",
            "0",
        ],
        "technique": "Provide boundary integer values (INT_MAX, UINT_MAX, -1) to trigger arithmetic wraparound in allocation size calculations."
    },
    "CWE-416": {
        "pattern": "Use After Free",
        "templates": [
            "FREE_OBJECT",
            "REUSE_SLOT",
            "A" * 64,
        ],
        "technique": "Trigger object deallocation followed by access on dangling pointer or heap spray reallocation."
    }
}


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
        with urllib.request.urlopen(req, timeout=4) as response:
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
    Retrieve real-world PoC intelligence and exploit hints for a given CWE or vuln type,
    with offline fallback templates.
    """
    query = f"{cwe_id} {vuln_type}".strip()
    pocs = search_github_pocs(query, max_results=2)

    # Check for offline CWE payload templates
    cwe_key = cwe_id.upper() if cwe_id else "CWE-120"
    offline_data = OFFLINE_CWE_DICTIONARY.get(cwe_key, {
        "pattern": vuln_type or "Generic Vulnerability",
        "templates": ["A" * 256, "; id;", "%p%p%p%p"],
        "technique": "Inject boundary mutation payloads to test target robustness."
    })

    return {
        "cwe": cwe_id,
        "vuln_type": vuln_type,
        "query": query,
        "github_pocs": pocs,
        "offline_templates": offline_data["templates"],
        "exploit_technique": offline_data["technique"]
    }
