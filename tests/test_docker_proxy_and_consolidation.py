import os
import unittest
from unittest.mock import MagicMock, patch

from mutagen.executor import (
    _check_docker_functional,
    get_docker_subprocess_env,
    is_docker_available,
)


class TestDockerProxyAndConsolidation(unittest.TestCase):
    def setUp(self):
        # Reset cached state before each test
        import mutagen.executor as ex
        ex._DOCKER_AVAILABLE_CACHE = None

    def tearDown(self):
        import mutagen.executor as ex
        ex._DOCKER_AVAILABLE_CACHE = None

    def test_get_docker_subprocess_env_bypasses_proxy_for_local_sockets(self):
        """Verify NO_PROXY and no_proxy include local docker socket endpoints when proxies are configured."""
        with patch.dict(os.environ, {
            "HTTP_PROXY": "http://http.docker.internal:3128",
            "HTTPS_PROXY": "https://http.docker.internal:3128",
            "NO_PROXY": "mycompany.internal",
        }, clear=True):
            env = get_docker_subprocess_env()
            self.assertIn("NO_PROXY", env)
            self.assertIn("no_proxy", env)
            self.assertIn("localhost", env["NO_PROXY"])
            self.assertIn("127.0.0.1", env["NO_PROXY"])
            self.assertIn("docker.internal", env["NO_PROXY"])
            self.assertIn("/var/run/docker.sock", env["NO_PROXY"])
            self.assertIn("mycompany.internal", env["NO_PROXY"])

    def test_is_docker_available_caching_consistency(self):
        """Verify is_docker_available returns consistent cached ground truth across multiple calls."""
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "27.0.1"

        with patch("subprocess.run", return_value=mock_res) as mock_sub:
            first_check = is_docker_available(force_refresh=True)
            self.assertTrue(first_check)
            self.assertEqual(mock_sub.call_count, 1)

            # Second and third calls must return cached result without spawning subprocesses
            second_check = is_docker_available()
            third_check = _check_docker_functional()
            self.assertTrue(second_check)
            self.assertTrue(third_check)
            self.assertEqual(mock_sub.call_count, 1)

    def test_is_docker_available_under_proxy_environment(self):
        """Verify is_docker_available successfully queries Docker daemon under HTTP/HTTPS proxy configuration."""
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "26.1.4\n"

        with patch.dict(os.environ, {
            "HTTP_PROXY": "http://http.docker.internal:3128",
            "HTTPS_PROXY": "https://http.docker.internal:3128"
        }):
            with patch("subprocess.run", return_value=mock_res) as mock_sub:
                avail = is_docker_available(force_refresh=True)
                self.assertTrue(avail)
                # Verify subprocess.run received the proxy-sanitized environment
                args, kwargs = mock_sub.call_args
                self.assertEqual(args[0], ["docker", "version", "--format", "{{.Server.Version}}"])
                passed_env = kwargs.get("env", {})
                self.assertIn("NO_PROXY", passed_env)
                self.assertIn("docker.internal", passed_env["NO_PROXY"])

    def test_is_docker_available_fallback_to_docker_info(self):
        """Verify is_docker_available gracefully falls back to docker info if docker version is unavailable."""
        # Fail first call (docker version), succeed second call (docker info)
        fail_res = MagicMock(returncode=1, stdout="", stderr="unknown flag")
        succ_res = MagicMock(returncode=0, stdout="Containers: 2\nServer Version: 26.1.4")

        with patch("subprocess.run", side_effect=[fail_res, succ_res]) as mock_sub:
            avail = is_docker_available(force_refresh=True)
            self.assertTrue(avail)
            self.assertEqual(mock_sub.call_count, 2)
            self.assertEqual(mock_sub.call_args_list[0][0][0][1], "version")
            self.assertEqual(mock_sub.call_args_list[1][0][0][1], "info")


if __name__ == "__main__":
    unittest.main()
