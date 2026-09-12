import json
import unittest
from unittest.mock import MagicMock, patch

from mutagen.cve_validator import fetch_cve_metadata
from mutagen.static_analyzer import analyze_source


class TestCvePipelineAudit(unittest.TestCase):
    def test_offline_cve_registry_returns_functions(self):
        """Validates that fetch_cve_metadata returns affected_functions for known CVEs."""
        meta = fetch_cve_metadata("CVE-2025-64505")
        self.assertEqual(meta["cve_id"], "CVE-2025-64505")
        self.assertIn("png_do_quantize", meta["affected_functions"])

    @patch("urllib.request.urlopen")
    def test_live_osv_function_extraction(self, mock_urlopen):
        """Validates that live OSV responses with backticks and vanir signatures extract functions cleanly."""
        mock_response_data = {
            "summary": "Vulnerability in `custom_image_decode` via invalid length",
            "details": "A heap overflow exists in custom_image_decode when parsing stream. Patched in 2.0.",
            "affected": [{
                "package": {"name": "sample_lib"},
                "database_specific": {
                    "vanir_signatures": [{
                        "target": {"function": "custom_image_decode", "file": "decode.c"}
                    }]
                }
            }]
        }
        mock_cm = MagicMock()
        mock_cm.status = 200
        mock_cm.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_cm.__enter__.return_value = mock_cm
        mock_urlopen.return_value = mock_cm

        meta = fetch_cve_metadata("CVE-2099-99999")
        self.assertEqual(meta["cve_id"], "CVE-2099-99999")
        self.assertIn("custom_image_decode", meta["affected_functions"])

    @patch("urllib.request.urlopen")
    def test_git_range_commit_hash_not_used_as_fixed_version(self, mock_urlopen):
        """A GIT-type range's events[].fixed is a commit hash, not a version -- it must
        never be surfaced as fixed_version when no real semver equivalent is available."""
        mock_response_data = {
            "summary": "Heap-double-free in mrb_default_allocf",
            "affected": [{
                "package": {"name": "mruby"},
                "ranges": [{
                    "type": "GIT",
                    "repo": "https://github.com/mruby/mruby",
                    "events": [
                        {"introduced": "9cdf439db52b66447b4e37c61179d54fad6c8f33"},
                        {"fixed": "97319697c8f9f6ff27b32589947e1918e3015503"},
                    ],
                }],
            }],
        }
        mock_cm = MagicMock()
        mock_cm.status = 200
        mock_cm.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_cm.__enter__.return_value = mock_cm
        mock_urlopen.return_value = mock_cm

        meta = fetch_cve_metadata("CVE-2099-99998")
        self.assertEqual(meta["fixed_version"], "Unknown")

    @patch("urllib.request.urlopen")
    def test_git_range_prefers_extracted_events_semver(self, mock_urlopen):
        """When OSV supplies ranges[].database_specific.extracted_events, that real
        semver must be used instead of the raw GIT commit hash."""
        mock_response_data = {
            "summary": "Path traversal in n8n",
            "affected": [{
                "package": {"name": "n8n"},
                "ranges": [{
                    "type": "GIT",
                    "repo": "https://github.com/n8n-io/n8n",
                    "events": [
                        {"introduced": "2f5228c8ba3c0ce1b1e0331e54f533022f6c4311"},
                        {"fixed": "4bf741ae67124724eb94e582de94daf0d70f9bd0"},
                    ],
                    "database_specific": {
                        "extracted_events": [
                            {"introduced": "0.123.1"},
                            {"fixed": "1.119.2"},
                        ],
                    },
                }],
            }],
        }
        mock_cm = MagicMock()
        mock_cm.status = 200
        mock_cm.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_cm.__enter__.return_value = mock_cm
        mock_urlopen.return_value = mock_cm

        meta = fetch_cve_metadata("CVE-2099-99997")
        self.assertEqual(meta["fixed_version"], "1.119.2")
        self.assertEqual(meta["affected_versions"], ">= 0.123.1")

    @patch("urllib.request.urlopen")
    def test_cwe_ids_extracted_from_database_specific(self, mock_urlopen):
        """Real OSV records carry CWE data in top-level database_specific.cwe_ids;
        it must not be silently discarded in favor of the CWE-119 placeholder."""
        mock_response_data = {
            "summary": "Improper handling of exceptional conditions",
            "affected": [{"package": {"name": "sample_lib"}}],
            "database_specific": {"cwe_ids": ["CWE-829"]},
        }
        mock_cm = MagicMock()
        mock_cm.status = 200
        mock_cm.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_cm.__enter__.return_value = mock_cm
        mock_urlopen.return_value = mock_cm

        meta = fetch_cve_metadata("CVE-2099-99996")
        self.assertEqual(meta["cwe"], "CWE-829")

    def test_sniper_mode_target_functions_reduction(self):
        """Validates that analyze_source with target_functions focuses specifically on target functions."""
        sample_code = (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n\n"
            "void helper_function(int a) {\n"
            "    char buf[64];\n"
            '    printf("val: %d\\n", a);\n'
            "}\n\n"
            "void target_vuln_func(char *data, int len) {\n"
            "    char dest[16];\n"
            "    for(int i=0; i<len; i++) {\n"
            "        dest[i] = data[i];\n"
            "    }\n"
            "}\n\n"
            "int main(int argc, char **argv) {\n"
            "    target_vuln_func(argv[1], 100);\n"
            "    return 0;\n"
            "}\n"
        )
        res = analyze_source(sample_code, target_functions=["target_vuln_func"])
        self.assertIn("target_vuln_func", res.focused_functions)
        self.assertTrue(res.reduction_percent >= 0.0)
        self.assertNotIn("if", res.focused_functions)


if __name__ == "__main__":
    unittest.main()
