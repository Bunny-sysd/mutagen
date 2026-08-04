from mutagen.state import ProgramContext


def test_triage_agent_reverse_engineering_prompt_enrichment():
    context = ProgramContext(
        target_path="sample.elf",
        language="c",
        os_platform="linux",
        source_code="void main() { int a = 0; }",
        is_binary=True,
        decompiler_used="ghidra",
        architecture="x86:LE:64:default"
    )
    assert context.is_binary is True
    assert context.decompiler_used == "ghidra"
    assert context.architecture == "x86:LE:64:default"
