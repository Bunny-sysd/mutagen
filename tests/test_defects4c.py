from unittest.mock import MagicMock, patch

import pytest

from mutagen.core import run_fuzzer
from mutagen.defects4c import Defects4CClient, Defects4CError


class TestDefects4CClient:
    @patch("requests.get")
    def test_list_projects_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"projects": ["libxml2", "openssl"]}
        mock_get.return_value = mock_resp

        client = Defects4CClient("http://localhost:8000")
        projects = client.list_projects()
        assert projects == ["libxml2", "openssl"]
        mock_get.assert_called_once_with("http://localhost:8000/projects", timeout=10)

    @patch("requests.get")
    def test_list_projects_failure(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp

        client = Defects4CClient("http://localhost:8000")
        with pytest.raises(Defects4CError) as exc:
            client.list_projects()
        assert "Failed to list projects" in str(exc.value)

    @patch("requests.post")
    @patch("requests.get")
    def test_reproduce_success(self, mock_get, mock_post):
        # Mock reproduction initiation
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {"handle": "task_123"}
        mock_post.return_value = mock_post_resp

        # Mock status check polling: first running, then success
        mock_get_resp1 = MagicMock()
        mock_get_resp1.status_code = 200
        mock_get_resp1.json.return_value = {"status": "running"}

        mock_get_resp2 = MagicMock()
        mock_get_resp2.status_code = 200
        mock_get_resp2.json.return_value = {"status": "success"}

        mock_get.side_effect = [mock_get_resp1, mock_get_resp2]

        client = Defects4CClient("http://localhost:8000")

        # Patch sleep to speed up test execution
        with patch("time.sleep") as mock_sleep:
            result = client.reproduce("libxml2@commit_hash")
            assert result is True
            assert mock_sleep.call_count == 2

    @patch("requests.post")
    def test_fix_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True, "message": "Tests passed"}
        mock_post.return_value = mock_resp

        client = Defects4CClient("http://localhost:8000")
        res = client.fix("libxml2@commit", "patches/fix.patch")
        assert res["success"] is True
        assert res["message"] == "Tests passed"

    @patch("requests.post")
    def test_error_dig(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"classification": "compile_error", "root_cause": "missing semicolon"}
        mock_post.return_value = mock_resp

        client = Defects4CClient("http://localhost:8000")
        res = client.error_dig("task_handle")
        assert res["classification"] == "compile_error"


class TestDefects4CIntegration:
    @patch("mutagen.core.get_engine")
    @patch("mutagen.defects4c.Defects4CClient")
    @patch("os.walk")
    @patch("builtins.open")
    def test_run_fuzzer_defects4c_mode(self, mock_open, mock_walk, mock_client_class, mock_get_engine):
        mock_engine = MagicMock()
        mock_engine.analyze_code.return_value = [{"vuln_type": "Buffer Overflow", "cwe": "CWE-120", "severity": "high"}]
        mock_engine.generate_patch.return_value = "void vuln() { /* fixed */ }"
        mock_get_engine.return_value = mock_engine

        mock_client = MagicMock()
        mock_client.fix.return_value = {"success": True}
        mock_client_class.return_value = mock_client

        # Mock finding buggy files in mount dir
        mock_walk.return_value = [("/mount/dir", [], ["vuln.c"])]

        # Mock reading file
        mock_file = MagicMock()
        mock_file.read.return_value = "void vuln() { strcpy(a, b); }"
        mock_open.return_value.__enter__.return_value = mock_file

        with patch("mutagen.core.validate_c_source") as mock_validate:
            mock_validate_res = MagicMock()
            mock_validate_res.is_valid = True
            mock_validate_res.node_count = 10
            mock_validate.return_value = mock_validate_res

            res = run_fuzzer(
                source_path="libxml2@commit",
                api_key="mock_key",
                gcc_path="",
                max_payloads=2,
                timeout=5,
                debug=False,
                defects4c_url="http://localhost:8000",
                defects4c_mount_dir="/mount/dir"
            )
            assert res == 1  # 1 represents patch verified successfully
            mock_client.reproduce.assert_called_once_with("libxml2@commit")
            mock_client.fix.assert_called_once_with("libxml2@commit", "/mount/dir\\vuln.c")
