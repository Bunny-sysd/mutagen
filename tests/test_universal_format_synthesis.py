import io
import struct
import unittest
import zipfile
import zlib

from mutagen.agents.synthesizer import _detect_file_extension, _generate_file_mode_fallback_payloads
from mutagen.binary_repair import (
    MAGIC_ELF,
    MAGIC_JPEG,
    MAGIC_PNG,
    MAGIC_RIFF,
    MAGIC_SQLITE,
    _repair_png,
    _repair_zip,
    repair_binary_payload,
)


class TestUniversalFormatSynthesis(unittest.TestCase):
    def test_extension_detection(self):
        self.assertEqual(_detect_file_extension("libpng/pngrtran.c", ""), ".png")
        self.assertEqual(_detect_file_extension("jpeg_decoder.c", ""), ".jpg")
        self.assertEqual(_detect_file_extension("parser.c", "void parse_pdf()"), ".pdf")
        self.assertEqual(_detect_file_extension("cJSON.c", ""), ".json")
        self.assertEqual(_detect_file_extension("xmlparse.c", ""), ".xml")
        self.assertEqual(_detect_file_extension("archive.c", "int unzip_file()"), ".zip")
        self.assertEqual(_detect_file_extension("audio.c", "RIFF wave parser"), ".wav")
        self.assertEqual(_detect_file_extension("generic_target.c", ""), ".bin")

    def test_fallback_payload_generation(self):
        # Image
        payloads_png = _generate_file_mode_fallback_payloads("libpng/pngrtran.c", "png_do_quantize")
        self.assertTrue(any("png" in p["reason"].lower() for p in payloads_png))

        # JSON
        payloads_json = _generate_file_mode_fallback_payloads("cJSON.c", "cJSON_Parse")
        self.assertTrue(any("json" in p["reason"].lower() for p in payloads_json))

        # XML
        payloads_xml = _generate_file_mode_fallback_payloads("expat.c", "XML_Parse")
        self.assertTrue(any("xml" in p["reason"].lower() for p in payloads_xml))

        # ZIP
        payloads_zip = _generate_file_mode_fallback_payloads("miniz.c", "mz_zip_reader")
        self.assertTrue(any("zip" in p["reason"].lower() for p in payloads_zip))

    def test_universal_binary_repair(self):
        # PNG Repair
        corrupted_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x04IHDR1234\x00\x00\x00\x00"
        repaired_png = repair_binary_payload(corrupted_png, target_hint="target.png")
        self.assertTrue(repaired_png.startswith(MAGIC_PNG))

        # JPEG Repair
        corrupted_jpeg = b"\x00\x00\xff\xe0\x00\x10JFIF"
        repaired_jpeg = repair_binary_payload(corrupted_jpeg, target_hint="target.jpg")
        self.assertTrue(repaired_jpeg.startswith(MAGIC_JPEG[:2]))
        self.assertTrue(repaired_jpeg.endswith(b"\xff\xd9"))

        # GIF Repair
        corrupted_gif = b"XXXX\x00\x00"
        repaired_gif = repair_binary_payload(corrupted_gif, target_hint="image.gif")
        self.assertTrue(repaired_gif.startswith(b"GIF89a"))
        self.assertTrue(repaired_gif.endswith(b"\x3b"))

        # ELF Repair
        corrupted_elf = b"XXXX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        repaired_elf = repair_binary_payload(corrupted_elf, target_hint="binary.elf")
        self.assertTrue(repaired_elf.startswith(MAGIC_ELF))

        # SQLite Repair
        corrupted_sqlite = b"XXXX" * 4
        repaired_sqlite = repair_binary_payload(corrupted_sqlite, target_hint="test.db")
        self.assertTrue(repaired_sqlite.startswith(MAGIC_SQLITE))

        # RIFF Repair
        corrupted_riff = b"XXXX\x00\x00\x00\x00WAVE"
        repaired_riff = repair_binary_payload(corrupted_riff, target_hint="sound.wav")
        self.assertTrue(repaired_riff.startswith(MAGIC_RIFF))

    def _make_png_chunk(self, chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    def test_png_repair_preserves_multichunk_structure(self):
        """Regression test: a prior bug in the CRC-skip heuristic desynced chunk
        parsing after the first chunk, corrupting every subsequent chunk's type
        field. A shallow "starts with the PNG magic" check does not catch this —
        this test walks the repaired output's actual chunk sequence."""
        ihdr = self._make_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0))
        idat = self._make_png_chunk(b"IDAT", zlib.compress(b"\x00\xaa\xbb\xcc" * 4 * 3))
        iend = self._make_png_chunk(b"IEND", b"")
        png = MAGIC_PNG + ihdr + idat + iend

        repaired = _repair_png(png)

        pos = 8
        seen_types = []
        while pos + 8 <= len(repaired):
            length = struct.unpack(">I", repaired[pos : pos + 4])[0]
            ctype = repaired[pos + 4 : pos + 8]
            seen_types.append(ctype)
            pos += 8 + length + 4
            if ctype == b"IEND":
                break
        self.assertEqual(seen_types, [b"IHDR", b"IDAT", b"IEND"])

    def test_png_repair_tops_up_undersized_pixel_data(self):
        """Regression test for the 'not enough image data' failure: an AI payload
        whose IDAT data is shorter than the declared IHDR dimensions require must
        be padded to spec, not left to fail at the target parser's header check."""
        ihdr = self._make_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0))
        short_idat = self._make_png_chunk(b"IDAT", zlib.compress(b"\x00\x01\x02\x03"))
        iend = self._make_png_chunk(b"IEND", b"")
        png = MAGIC_PNG + ihdr + short_idat + iend

        repaired = _repair_png(png)

        idat_pos = repaired.find(b"IDAT") + 4
        idat_len = struct.unpack(">I", repaired[idat_pos - 8 : idat_pos - 4])[0]
        idat_data = repaired[idat_pos : idat_pos + idat_len]
        raw = zlib.decompress(idat_data)
        expected = 16 * (1 + 16 * 3)  # height * (filter byte + width * RGB channels)
        self.assertEqual(len(raw), expected)
        self.assertTrue(raw.startswith(b"\x00\x01\x02\x03"))

    def test_zip_repair_fixes_all_entries_and_central_directory(self):
        """Regression test: a prior bug only recalculated CRC32 for a single entry
        at a fixed offset, and never touched the Central Directory's separate copy
        of each entry's CRC — so any real archive tool (which trusts the Central
        Directory) still rejected the file after 'repair'. Verified against
        Python's actual zipfile module, not just byte-level inspection."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("a.txt", b"hello world")
            zf.writestr("b.txt", b"second entry data here")
        raw = bytearray(buf.getvalue())

        # Mutate entry 1's data bytes only (same length), simulating fuzz content
        # injected by the AI, and confirm the whole archive is still valid after repair.
        fname_len = struct.unpack("<H", raw[26:28])[0]
        extra_len = struct.unpack("<H", raw[28:30])[0]
        data_start = 30 + fname_len + extra_len
        raw[data_start : data_start + 11] = b"MUTATED!!!!"

        repaired = _repair_zip(bytes(raw))
        zf2 = zipfile.ZipFile(io.BytesIO(repaired))
        self.assertEqual(zf2.namelist(), ["a.txt", "b.txt"])
        self.assertEqual(zf2.read("a.txt"), b"MUTATED!!!!")
        self.assertEqual(zf2.read("b.txt"), b"second entry data here")


if __name__ == "__main__":
    unittest.main()
