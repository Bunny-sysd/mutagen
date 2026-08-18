import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from mutagen.dependency_resolver import build_with_native_tool
from mutagen.executor import (
    _cleanup_staged_dependencies,
    _resolve_target_ld_library_path,
    _stage_shared_library_dependencies,
    execute_payload,
)


class TestSharedLibraryResolution(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="mutagen_test_shlib_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_resolve_target_ld_library_path_no_unexpanded_vars(self):
        """Validates that _resolve_target_ld_library_path produces clean search paths without shell variable literals."""
        ld_path = _resolve_target_ld_library_path(self.test_dir)
        self.assertNotIn("$LD_LIBRARY_PATH", ld_path)
        self.assertIn("/target", ld_path)
        self.assertIn("/usr/lib", ld_path)
        self.assertIn("/lib", ld_path)

    def test_resolve_target_ld_library_path_discovers_subdirs(self):
        """Validates that subdirectories containing .so files are added to container search paths."""
        build_lib_dir = os.path.join(self.test_dir, "build", "lib")
        os.makedirs(build_lib_dir, exist_ok=True)
        dummy_so = os.path.join(build_lib_dir, "libsample.so")
        with open(dummy_so, "w") as f:
            f.write("dummy")

        ld_path = _resolve_target_ld_library_path(self.test_dir)
        self.assertIn("/target/build/lib", ld_path)

    def test_stage_shared_library_dependencies_creates_soname_aliases(self):
        """Validates that _stage_shared_library_dependencies finds .so files in parent/sibling dirs and creates SONAME aliases."""
        bin_dir = os.path.join(self.test_dir, "build", "bin")
        lib_dir = os.path.join(self.test_dir, "build", "lib")
        os.makedirs(bin_dir, exist_ok=True)
        os.makedirs(lib_dir, exist_ok=True)

        exe_path = os.path.join(bin_dir, "pngimage")
        with open(exe_path, "w") as f:
            f.write("dummy_exe")

        # Create libpng16.so.16.50.0 in lib_dir
        real_so = os.path.join(lib_dir, "libpng16.so.16.50.0")
        with open(real_so, "w") as f:
            f.write("dummy_so_content")

        staged = _stage_shared_library_dependencies(exe_path)
        self.assertTrue(len(staged) > 0)

        # Verify staged aliases were created in bin_dir
        staged_names = [os.path.basename(p) for p in staged]
        self.assertIn("libpng16.so.16.50.0", staged_names)
        self.assertIn("libpng16.so.16", staged_names)
        self.assertIn("libpng16.so", staged_names)

        for p in staged:
            self.assertTrue(os.path.exists(p) or os.path.islink(p))

        # Test cleanup
        _cleanup_staged_dependencies(staged)
        for p in staged:
            self.assertFalse(os.path.exists(p) or os.path.islink(p))

    @patch("subprocess.run")
    def test_cmake_build_prefers_static_linking(self, mock_run):
        """Validates that build_with_native_tool passes -DBUILD_SHARED_LIBS=OFF for CMake builds."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        project_dir = os.path.join(self.test_dir, "sample_cmake_project")
        os.makedirs(project_dir, exist_ok=True)
        build_dir = os.path.join(project_dir, "build")
        os.makedirs(build_dir, exist_ok=True)

        # Create dummy target executable
        out_bin = os.path.join(build_dir, "sample_target")
        with open(out_bin, "w") as f:
            f.write("target")
        if os.name != 'nt':
            os.chmod(out_bin, 0o755)

        with patch("mutagen.dependency_resolver._is_shared_library_or_build_artifact", return_value=False):
            with patch("mutagen.reachability_checker.select_best_reachable_binary", return_value=(out_bin, "CONFIRMED")):
                res = build_with_native_tool("cmake", project_dir, target_hint="sample_target")
                self.assertEqual(res, out_bin)

        # Check cmake invocations
        cmake_calls = [call[0][0] for call in mock_run.call_args_list if call[0][0][0] == "cmake"]
        self.assertTrue(len(cmake_calls) >= 2)
        config_call = cmake_calls[0]
        self.assertIn("-DBUILD_SHARED_LIBS=OFF", config_call)
        self.assertIn("-DCMAKE_BUILD_RPATH_USE_ORIGIN=ON", config_call)

    @patch("mutagen.executor._check_docker_functional", return_value=True)
    @patch("subprocess.run")
    def test_execute_payload_docker_cmd_ld_library_path(self, mock_run, mock_docker_check):
        """Validates that execute_payload constructs docker create with clean LD_LIBRARY_PATH."""
        def fake_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and len(cmd) > 1 and cmd[0] == "docker" and cmd[1] == "create":
                return MagicMock(returncode=0, stdout="abc123containerid\n", stderr="")
            if isinstance(cmd, list) and len(cmd) > 1 and cmd[0] == "docker" and cmd[1] == "image":
                return MagicMock(returncode=0, stdout="sha256:1234567890abcdef", stderr="")
            if isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "ldd":
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="OK\n", stderr="")

        mock_run.side_effect = fake_run

        dummy_exe = os.path.join(self.test_dir, "test_target")
        with open(dummy_exe, "w") as f:
            f.write("dummy")

        result = execute_payload(dummy_exe, ["arg1"], "", "args", timeout=5, sandbox="docker")
        self.assertFalse(result["crashed"])

        # Check docker create call args
        docker_create_call = None
        for call in mock_run.call_args_list:
            cmd = call[0][0]
            if isinstance(cmd, list) and len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "create":
                docker_create_call = cmd
                break

        self.assertIsNotNone(docker_create_call)
        ld_flag_idx = docker_create_call.index("-e")
        ld_val = docker_create_call[ld_flag_idx + 1]
        self.assertTrue(ld_val.startswith("LD_LIBRARY_PATH="))
        self.assertNotIn("$LD_LIBRARY_PATH", ld_val)
        self.assertIn("/target", ld_val)


if __name__ == "__main__":
    unittest.main()
