import os
import tempfile

from mutagen.ghidra_decompiler import generate_decompile_headless_script


def test_generate_decompile_headless_script():
    with tempfile.TemporaryDirectory() as tmpdir:
        script_path = os.path.join(tmpdir, "DecompileHeadless.py")
        output_c = os.path.join(tmpdir, "out.c")
        generate_decompile_headless_script(script_path, output_c)

        assert os.path.exists(script_path)
        with open(script_path, encoding="utf-8") as f:
            content = f.read()
        assert "DecompInterface" in content
        assert "GhidraScript" in content
