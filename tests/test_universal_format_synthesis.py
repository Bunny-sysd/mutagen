import unittest

from mutagen.agents.synthesizer import _detect_file_extension, _generate_file_mode_fallback_payloads
from mutagen.binary_repair import (
    MAGIC_ELF,
    MAGIC_JPEG,
    MAGIC_PNG,
    MAGIC_RIFF,
    MAGIC_SQLITE,
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


if __name__ == "__main__":
    unittest.main()
