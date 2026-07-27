import os
import tempfile

from mutagen.project_graph import (
    scan_workspace_symbols,
    summarize_project_graph,
)


def test_scan_workspace_symbols():
    with tempfile.TemporaryDirectory() as tmpdir:
        c_file = os.path.join(tmpdir, "auth.c")
        with open(c_file, "w") as f:
            f.write("#include <stdio.h>\nstruct UserSession { int id; };\nvoid authenticate_user() {}\n")

        symbols = scan_workspace_symbols(tmpdir)
        assert "auth.c" in symbols["files"]
        assert "authenticate_user" in symbols["functions"]
        assert "UserSession" in symbols["structs"]

def test_summarize_project_graph():
    with tempfile.TemporaryDirectory() as tmpdir:
        c_file = os.path.join(tmpdir, "main.c")
        with open(c_file, "w") as f:
            f.write("void process_request() {}\n")

        summary = summarize_project_graph(tmpdir)
        assert "Workspace Structure" in summary
        assert "process_request" in summary
