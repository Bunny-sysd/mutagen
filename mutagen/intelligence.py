"""
Token-Efficient Vulnerability Intelligence Engine for Mutagen.

Queries CVE/NVD references, GitHub security advisories, and offline CWE dictionaries.
Applies severity ranking (CVSS / Critical > High > Medium) and single-candidate deduplication
to prevent prompt token bloat in LLM contexts.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Severity Weights for Ranking (Higher score = higher priority)
SEVERITY_SCORES: dict[str, int] = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 50,
    "LOW": 20,
    "INFO": 10,
    "UNKNOWN": 0,
}

# Offline High-Density Signature Templates
SIGNATURE_INTELLIGENCE_DB: dict[str, dict[str, Any]] = {
    "CWE-120": {
        "cwe": "CWE-120",
        "name": "Buffer Copy without Checking Size of Input",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "exploit_vector": "Contiguous memory overflow exceeding destination buffer bounds",
        "signature_hint": "Supply long repetitive byte streams or boundary strings (>512 bytes) to overwrite adjacent variables or stack frame pointers.",
    },
    "CWE-121": {
        "cwe": "CWE-121",
        "name": "Stack-based Buffer Overflow",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "exploit_vector": "Stack return address / saved frame pointer corruption",
        "signature_hint": "Provide long input exceeding local stack buffer allocation to overwrite return addresses.",
    },
    "CWE-122": {
        "cwe": "CWE-122",
        "name": "Heap-based Buffer Overflow",
        "severity": "CRITICAL",
        "cvss_score": 8.8,
        "exploit_vector": "Heap chunk header / heap memory corruption",
        "signature_hint": "Craft inputs that cause rowbytes or buffer allocation size calculations to miscalculate, overflowing heap allocations during memcpy.",
    },
    "CWE-190": {
        "cwe": "CWE-190",
        "name": "Integer Overflow or Wraparound",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "exploit_vector": "Arithmetic wraparound in length or size calculations",
        "signature_hint": "Pass boundary integer constants (e.g. 0x7FFFFFFF, 0xFFFFFFFF, 0x04000000) to trigger 32-bit arithmetic wraparound before allocation.",
    },
    "CWE-78": {
        "cwe": "CWE-78",
        "name": "OS Command Injection",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "exploit_vector": "Subshell command execution delimiter injection",
        "signature_hint": "Inject command separators (; | & ` $()) to execute secondary OS commands.",
    },
    "CWE-134": {
        "cwe": "CWE-134",
        "name": "Use of Externally-Controlled Format String",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "exploit_vector": "Format specifier memory leak or write",
        "signature_hint": "Provide format specifiers (%s, %x, %p, %n) in input strings.",
    },
    "CWE-416": {
        "cwe": "CWE-416",
        "name": "Use After Free",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "exploit_vector": "Dangling pointer reference after object deallocation",
        "signature_hint": "Trigger free operation followed by immediate access or heap allocation reuse.",
    },
}


class VulnerabilityIntelligenceEngine:
    """
    Query, score, rank, and deduplicate vulnerability signature intelligence
    to produce token-efficient prompts for PayloadSynthesizerAgent.
    """

    def __init__(self):
        self.signature_db = SIGNATURE_INTELLIGENCE_DB

    def get_refined_intelligence(
        self,
        cwe_id: str,
        vuln_type: str = "",
        language: str = "c",
        os_platform: str = "linux",
    ) -> dict[str, Any]:
        """
        Retrieves, ranks, and returns a SINGLE highest-impact signature intelligence dict
        to minimize prompt token overhead.
        """
        cwe_key = (cwe_id or "CWE-120").upper().strip()

        # Extract candidates for the matching CWE or vulnerability pattern
        candidates = self._fetch_candidates(cwe_key, vuln_type)

        # Rank candidates by Severity & Impact score
        ranked_candidates = sorted(
            candidates,
            key=lambda item: (
                SEVERITY_SCORES.get(item.get("severity", "LOW").upper(), 0),
                item.get("cvss_score", 0.0),
            ),
            reverse=True,
        )

        # Deduplicate & select the SINGLE most impactful signature item
        selected_signature = ranked_candidates[0] if ranked_candidates else self._fallback_signature(cwe_key, vuln_type)

        return {
            "selected_cwe": selected_signature.get("cwe", cwe_key),
            "severity": selected_signature.get("severity", "HIGH"),
            "cvss_score": selected_signature.get("cvss_score", 7.5),
            "exploit_vector": selected_signature.get("exploit_vector", "Boundary mutation"),
            "signature_hint": selected_signature.get("signature_hint", "Provide targeted boundary payloads."),
            "candidates_evaluated": len(candidates),
            "token_optimized": True,
        }

    def _fetch_candidates(self, cwe_key: str, vuln_type: str) -> list[dict[str, Any]]:
        """Fetch candidates matching CWE or vulnerability keywords."""
        candidates = []
        if cwe_key in self.signature_db:
            candidates.append(dict(self.signature_db[cwe_key]))

        # Search by keyword in offline database
        for key, entry in self.signature_db.items():
            if key != cwe_key and vuln_type:
                if vuln_type.lower() in entry["name"].lower() or vuln_type.lower() in entry["exploit_vector"].lower():
                    candidates.append(dict(entry))

        if not candidates:
            candidates.append(self._fallback_signature(cwe_key, vuln_type))

        return candidates

    def _fallback_signature(self, cwe_key: str, vuln_type: str) -> dict[str, Any]:
        return {
            "cwe": cwe_key,
            "name": vuln_type or "Generic Memory Vulnerability",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "exploit_vector": "Boundary input mutation",
            "signature_hint": "Supply boundary mutated payloads to test allocation and memory bounds.",
        }


def get_token_efficient_signature(cwe_id: str, vuln_type: str = "") -> dict[str, Any]:
    """Helper function to quickly retrieve single-candidate optimized intelligence."""
    engine = VulnerabilityIntelligenceEngine()
    return engine.get_refined_intelligence(cwe_id, vuln_type)
