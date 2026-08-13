from mutagen.type_verifier import verify_finding_type_safety


def test_type_verifier_c_cpp_widening_cast_and_macro(tmp_path):
    """
    Tests C/C++ widening cast detection and header macro expansion (libpng case study).
    """
    # 1. Header with widening cast macro (e.g. libpng PNG_ROWBYTES)
    png_h = tmp_path / "png.h"
    png_h.write_text("""
#ifndef PNG_H
#define PNG_H
typedef unsigned long png_size_t;
#define PNG_ROWBYTES(pixel_depth, width) ((png_size_t)(width) * (png_size_t)(pixel_depth) + 7) >> 3
#endif
""")

    pngread_c = tmp_path / "pngread.c"
    pngread_c.write_text("""
#include "png.h"

void png_read_row_demo(int width, int pixel_depth) {
    size_t rowbytes = PNG_ROWBYTES(pixel_depth, width);
    char *buf = malloc(rowbytes);
}

void vulnerable_c_func(unsigned int width, unsigned int height) {
    unsigned int size = width * height; // Unprotected 32-bit multiplication
    char *buf = malloc(size);
}
""")

    # Test 1A: libpng PNG_ROWBYTES macro usage -> LIKELY_FALSE_POSITIVE
    res_libpng = verify_finding_type_safety(
        source_code=pngread_c.read_text(),
        line_number=5,
        cwe="CWE-190",
        vuln_type="Heap Buffer Overflow",
        language="c",
        target_path=str(pngread_c)
    )
    assert res_libpng.is_false_positive_risk is True
    assert res_libpng.verification_status == "LIKELY_FALSE_POSITIVE"
    assert "PNG_ROWBYTES" in res_libpng.annotation or "png_size_t" in res_libpng.annotation

    # Test 1B: Unprotected 32-bit multiplication -> UNCONFIRMED_RISK
    res_unsafe = verify_finding_type_safety(
        source_code=pngread_c.read_text(),
        line_number=10,
        cwe="CWE-190",
        vuln_type="Integer Overflow",
        language="c",
        target_path=str(pngread_c)
    )
    assert res_unsafe.is_false_positive_risk is False
    assert res_unsafe.verification_status == "UNCONFIRMED_RISK"


def test_type_verifier_rust():
    """
    Tests Rust checked/saturating arithmetic methods vs raw operators.
    """
    rust_code = """
fn safe_calc(a: u32, b: u32) -> Option<u32> {
    a.checked_mul(b)
}

fn unsafe_calc(a: u32, b: u32) -> u32 {
    a * b
}
"""
    # Safe checked_mul
    res_safe = verify_finding_type_safety(rust_code, line_number=3, cwe="CWE-190", vuln_type="Integer Overflow", language="rust")
    assert res_safe.is_false_positive_risk is True
    assert res_safe.verification_status == "LIKELY_FALSE_POSITIVE"
    assert "checked_mul" in res_safe.annotation

    # Raw operator
    res_unsafe = verify_finding_type_safety(rust_code, line_number=7, cwe="CWE-190", vuln_type="Integer Overflow", language="rust")
    assert res_unsafe.is_false_positive_risk is False
    assert res_unsafe.verification_status == "UNCONFIRMED_RISK"


def test_type_verifier_python():
    """
    Tests Python arbitrary-precision integers vs struct/ctypes interop.
    """
    py_code = """
def safe_py(a, b):
    return a * b

def struct_py(a, b):
    import struct
    return struct.pack('<I', a * b)
"""
    # Arbitrary precision -> LIKELY_FALSE_POSITIVE
    res_safe = verify_finding_type_safety(py_code, line_number=3, cwe="CWE-190", vuln_type="Integer Overflow", language="python")
    assert res_safe.is_false_positive_risk is True
    assert res_safe.verification_status == "LIKELY_FALSE_POSITIVE"

    # Fixed-width interop
    res_struct = verify_finding_type_safety(py_code, line_number=7, cwe="CWE-190", vuln_type="Integer Overflow", language="python")
    assert res_struct.is_false_positive_risk is False
    assert res_struct.verification_status == "UNCONFIRMED_RISK"


def test_type_verifier_go():
    """
    Tests Go math/bits package guards vs raw int operations.
    """
    go_code = """
package main
import "math/bits"

func safeGo(a, b uint32) (uint32, uint32) {
    return bits.Mul32(a, b)
}

func unsafeGo(a, b uint32) uint32 {
    return a * b
}
"""
    # math/bits primitive
    res_safe = verify_finding_type_safety(go_code, line_number=6, cwe="CWE-190", vuln_type="Integer Overflow", language="go")
    assert res_safe.is_false_positive_risk is True
    assert res_safe.verification_status == "LIKELY_FALSE_POSITIVE"

    # Raw uint32 multiplication
    res_unsafe = verify_finding_type_safety(go_code, line_number=10, cwe="CWE-190", vuln_type="Integer Overflow", language="go")
    assert res_unsafe.is_false_positive_risk is False
    assert res_unsafe.verification_status == "UNCONFIRMED_RISK"


def test_type_verifier_javascript():
    """
    Tests JavaScript float64 default vs Int32Array/BigInt.
    """
    js_code = """
function safeJS(a, b) {
    return a * b;
}

function typedJS(a, b) {
    let arr = new Int32Array(1);
    arr[0] = a * b;
    return arr[0];
}
"""
    # Standard JS float64 -> LIKELY_FALSE_POSITIVE
    res_safe = verify_finding_type_safety(js_code, line_number=3, cwe="CWE-190", vuln_type="Integer Overflow", language="javascript")
    assert res_safe.is_false_positive_risk is True
    assert res_safe.verification_status == "LIKELY_FALSE_POSITIVE"

    # Int32Array
    res_typed = verify_finding_type_safety(js_code, line_number=8, cwe="CWE-190", vuln_type="Integer Overflow", language="javascript")
    assert res_typed.is_false_positive_risk is False
    assert res_typed.verification_status == "UNCONFIRMED_RISK"


def test_grounding_verifier_rejects_unrelated_line():
    """
    Ensures that claiming an integer overflow or heap buffer overflow on a line
    with NO arithmetic calculations or memory writes (e.g. a simple null check)
    is caught and marked as UNGROUNDED_FINDING.
    """
    c_code = """
void png_start_read_image(png_structrp png_ptr) {
    if (png_ptr == NULL)
        return;

    int status = 0;
}
"""
    # Claiming integer overflow on a null check line
    res_ungrounded = verify_finding_type_safety(
        source_code=c_code,
        line_number=3,
        cwe="CWE-190",
        vuln_type="Heap Buffer Overflow",
        language="c"
    )
    assert res_ungrounded.verification_status == "UNGROUNDED_FINDING"
    assert res_ungrounded.is_false_positive_risk is True
    assert "UNGROUNDED FINDING" in res_ungrounded.annotation
    assert res_ungrounded.confidence == "LOW"


import pytest
from mutagen.state import ProgramContext, VulnerabilityDetail
from mutagen.agents.synthesizer import PayloadSynthesizerAgent


@pytest.mark.asyncio
async def test_pipeline_orchestration_c_libpng_downgrade(tmp_path):
    """
    Verifies that C/libpng findings with widening macro casts are structured with
    LIKELY_FALSE_POSITIVE and can be skipped with skip_flagged_findings.
    """
    png_h = tmp_path / "png.h"
    png_h.write_text("""
#ifndef PNG_H
#define PNG_H
typedef unsigned long png_size_t;
#define PNG_ROWBYTES(pixel_depth, width) ((png_size_t)(width) * (png_size_t)(pixel_depth) + 7) >> 3
#endif
""")
    pngread_c = tmp_path / "pngread.c"
    src_content = """#include "png.h"
void png_read_row_demo(int width, int pixel_depth) {
    size_t rowbytes = PNG_ROWBYTES(pixel_depth, width);
    char *buf = malloc(rowbytes);
}
"""
    pngread_c.write_text(src_content)

    res = verify_finding_type_safety(
        source_code=src_content,
        line_number=3,
        cwe="CWE-190",
        vuln_type="Heap Buffer Overflow",
        language="c",
        target_path=str(pngread_c)
    )

    detail = VulnerabilityDetail(
        vuln_type="Heap Buffer Overflow",
        cwe="CWE-190",
        severity="high",
        line_number=3,
        code_snippet="size_t rowbytes = PNG_ROWBYTES(pixel_depth, width);",
        verification_status=res.verification_status,
        verification_annotation=res.annotation,
        confidence=res.confidence,
        is_false_positive_risk=res.is_false_positive_risk
    )
    assert detail.verification_status == "LIKELY_FALSE_POSITIVE"
    assert detail.is_false_positive_risk is True
    assert detail.confidence == "LOW"

    # Test skip_flagged_findings in synthesizer
    ctx = ProgramContext(
        target_path=str(pngread_c),
        language="c",
        os_platform="linux",
        source_code=src_content,
        vulnerabilities=[detail],
        skip_flagged_findings=True
    )
    synth = PayloadSynthesizerAgent(model_provider="ollama")  # mock offline engine
    updated_ctx = await synth.process(ctx)
    assert len(updated_ctx.active_payloads) == 0
    assert any("Skipping payload synthesis" in log for log in updated_ctx.logs)


@pytest.mark.asyncio
async def test_pipeline_orchestration_rust_checked_mul_downgrade():
    """
    Verifies that non-C (Rust) findings using checked_mul are structured with
    LIKELY_FALSE_POSITIVE and confidence LOW at the pipeline data-structure level.
    """
    rust_code = """
fn calc(width: u32, height: u32) -> Option<u32> {
    width.checked_mul(height)
}
"""
    res = verify_finding_type_safety(
        source_code=rust_code,
        line_number=3,
        cwe="CWE-190",
        vuln_type="Integer Overflow",
        language="rust"
    )

    detail = VulnerabilityDetail.from_any({
        "vuln_type": "Integer Overflow",
        "cwe": "CWE-190",
        "severity": "high",
        "line_number": 3,
        "code_snippet": "width.checked_mul(height)",
        "verification_status": res.verification_status,
        "verification_annotation": res.annotation,
        "confidence": res.confidence,
        "is_false_positive_risk": res.is_false_positive_risk
    })
    assert detail.verification_status == "LIKELY_FALSE_POSITIVE"
    assert detail.is_false_positive_risk is True
    assert detail.confidence == "LOW"
    assert "checked_mul" in detail.verification_annotation


@pytest.mark.asyncio
async def test_pipeline_orchestration_go_safe_bits_downgrade():
    """
    Verifies that non-C (Go) findings using math/bits are structured with
    LIKELY_FALSE_POSITIVE across the pipeline.
    """
    go_code = """
package main
import "math/bits"
func safeMul(a, b uint32) (uint32, uint32) {
    return bits.Mul32(a, b)
}
"""
    res = verify_finding_type_safety(
        source_code=go_code,
        line_number=5,
        cwe="CWE-190",
        vuln_type="Integer Overflow",
        language="go"
    )
    detail = VulnerabilityDetail.from_any({
        "vuln_type": "Integer Overflow",
        "cwe": "CWE-190",
        "severity": "high",
        "line_number": 5,
        "code_snippet": "return bits.Mul32(a, b)",
        "verification_status": res.verification_status,
        "verification_annotation": res.annotation,
        "confidence": res.confidence,
        "is_false_positive_risk": res.is_false_positive_risk
    })
    assert detail.verification_status == "LIKELY_FALSE_POSITIVE"
    assert detail.is_false_positive_risk is True
    assert detail.confidence == "LOW"
