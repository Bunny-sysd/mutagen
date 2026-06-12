"""Tests for the crash report generator."""

import json
import os
import shutil
import tempfile

import pytest

from mutagen.reporter import save_crash_report


class TestSaveCrashReport:
    """Test JSON and HTML report generation."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Run tests in a temporary directory to avoid polluting the workspace."""
        self._original_dir = os.getcwd()
        self._temp_dir = tempfile.mkdtemp()
        os.chdir(self._temp_dir)
        yield
        os.chdir(self._original_dir)
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def test_creates_json_and_html_files(self, sample_crash_data):
        """Both JSON and HTML report files should be created."""
        json_file, html_file = save_crash_report(
            [sample_crash_data], "test_target", 5,
        )

        assert os.path.exists(json_file)
        assert os.path.exists(html_file)
        assert json_file.endswith(".json")
        assert html_file.endswith(".html")

    def test_json_report_structure(self, sample_crash_data):
        """JSON report should contain all expected fields."""
        json_file, _ = save_crash_report(
            [sample_crash_data], "test_target", 5,
        )

        with open(json_file, "r") as f:
            report = json.load(f)

        assert "Mutagen" in report["tool"]
        assert report["target"] == "test_target"
        assert report["total_payloads_tested"] == 5
        assert report["total_crashes_found"] == 1
        assert len(report["crashes"]) == 1
        assert "CWE-120" in report["unique_cwes"]

    def test_html_report_contains_key_elements(self, sample_crash_data):
        """HTML report should contain the target name and crash data."""
        _, html_file = save_crash_report(
            [sample_crash_data], "test_target", 5,
        )

        with open(html_file, "r", encoding="utf-8") as f:
            content = f.read()

        assert "MUTAGEN" in content
        assert "test_target" in content
        assert "CWE-120" in content
        assert "Buffer Overflow" in content
        assert "CRITICAL" in content

    def test_html_xss_prevention(self):
        """HTML report should escape potentially malicious payload strings."""
        malicious_crash = {
            "args": ['<script>alert("xss")</script>'],
            "vuln_type": '<img onerror="evil()">',
            "cwe": "CWE-120",
            "severity": "critical",
            "crash_type": "ACCESS_VIOLATION",
            "reason": "test",
        }

        _, html_file = save_crash_report([malicious_crash], "xss_test", 1)

        with open(html_file, "r", encoding="utf-8") as f:
            content = f.read()

        # The raw <script> tag from the payload should NOT appear — it should be escaped
        assert '<script>alert("xss")</script>' not in content
        assert "&lt;script&gt;" in content

    def test_crash_rate_calculation(self, sample_crash_data):
        """Crash rate should be correctly calculated."""
        json_file, _ = save_crash_report(
            [sample_crash_data], "test_target", 5,
        )

        with open(json_file, "r") as f:
            report = json.load(f)

        assert report["crash_rate"] == "20.0%"

    def test_empty_crashes_zero_rate(self):
        """Zero crashes should produce 0% crash rate."""
        json_file, _ = save_crash_report([], "test_target", 5)

        with open(json_file, "r") as f:
            report = json.load(f)

        assert report["crash_rate"] == "0.0%"
        assert report["total_crashes_found"] == 0

    def test_creates_crashes_directory(self, sample_crash_data):
        """The crashes/ directory should be created if it doesn't exist."""
        assert not os.path.exists("crashes")

        save_crash_report([sample_crash_data], "test_target", 1)

        assert os.path.exists("crashes")
