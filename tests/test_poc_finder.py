from mutagen.poc_finder import get_cwe_poc_intelligence, search_github_pocs


def test_search_github_pocs_fallback():
    """Verify search_github_pocs returns structured results or fallback search pointers."""
    results = search_github_pocs("CWE-120 buffer overflow", max_results=2)
    assert isinstance(results, list)
    assert len(results) >= 1
    assert "url" in results[0]
    assert "name" in results[0]

def test_get_cwe_poc_intelligence():
    """Verify CWE intelligence formatting."""
    intel = get_cwe_poc_intelligence("CWE-78", "command_injection")
    assert intel["cwe"] == "CWE-78"
    assert intel["vuln_type"] == "command_injection"
    assert "github_pocs" in intel
    assert isinstance(intel["github_pocs"], list)
