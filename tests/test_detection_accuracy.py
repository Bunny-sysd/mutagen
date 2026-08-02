from mutagen.static_analyzer import analyze_source, DANGEROUS_CALLS


def test_static_analyzer_preserves_context_for_medium_files():
    # Construct a sample C code with 30 lines (well under 1500 line threshold)
    sample_c = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void png_image_finish_read(int bit_depth, int format) {
    if (bit_depth == 16 && format == 8) {
        printf("Potential bit-depth mismatch\\n");
    }
}

int main(int argc, char **argv) {
    char buf[64];
    memcpy(buf, argv[1], 10);
    png_image_finish_read(16, 8);
    return 0;
}
"""
    result = analyze_source(sample_c)
    # Ensure full source code is preserved in focused_code for medium-sized files
    assert result.focused_code == sample_c
    assert result.original_line_count == len(sample_c.splitlines())
    # Ensure png_image_finish_read is registered in DANGEROUS_CALLS
    assert "png_image_finish_read" in DANGEROUS_CALLS
