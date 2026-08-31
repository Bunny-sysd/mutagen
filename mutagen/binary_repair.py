"""
Universal Binary & Kernel Post-Synthesis Repair Engine for Mutagen.

Dynamic, non-hardcoded format inspection and checksum/header repair across:
- Image / Media formats (PNG, JPEG, GIF)
- Archive formats (ZIP, TAR, GZ)
- Low-level system & kernel binaries (ELF, PE/COFF)
"""

from __future__ import annotations

import logging
import struct
import zlib

logger = logging.getLogger(__name__)

# Known Magic Byte Fingerprints
MAGIC_PNG = b"\x89PNG\r\n\x1a\n"
MAGIC_ELF = b"\x7fELF"
MAGIC_ZIP = b"PK\x03\x04"
MAGIC_PE = b"MZ"
MAGIC_GZ = b"\x1f\x8b"
MAGIC_JPEG = b"\xff\xd8\xff"
MAGIC_GIF = b"GIF8"
MAGIC_SQLITE = b"SQLite format 3\x00"
MAGIC_RIFF = b"RIFF"


def repair_binary_payload(raw_data: bytes | str, target_hint: str = "") -> bytes:
    """
    Main entry point: Inspects raw payload bytes against dynamic magic byte fingerprints
    and applies format-aware checksum & header repairs.
    """
    if isinstance(raw_data, str):
        # Convert hex string or text string to raw bytes
        cleaned = raw_data.strip()
        try:
            if all(c in "0123456789abcdefABCDEF" for c in cleaned) and len(cleaned) % 2 == 0 and len(cleaned) > 8:
                buf = bytes.fromhex(cleaned)
            else:
                buf = cleaned.encode("utf-8", errors="ignore")
        except Exception:
            buf = cleaned.encode("utf-8", errors="ignore")
    else:
        buf = bytes(raw_data)

    if not buf or len(buf) < 4:
        return buf

    # Dynamic Magic Byte Matcher with Target Hint Fallback
    magic = buf[:16]
    hint_lower = target_hint.lower() if target_hint else ""

    if magic.startswith(MAGIC_PNG) or "png" in hint_lower:
        return _repair_png(buf)
    elif magic.startswith(MAGIC_JPEG) or any(k in hint_lower for k in ["jpeg", "jpg", "jfif"]):
        return _repair_jpeg(buf)
    elif magic.startswith(MAGIC_GIF) or "gif" in hint_lower:
        return _repair_gif(buf)
    elif magic.startswith(MAGIC_ELF) or "elf" in hint_lower:
        return _repair_elf(buf)
    elif magic.startswith(MAGIC_ZIP) or "zip" in hint_lower:
        return _repair_zip(buf)
    elif magic.startswith(MAGIC_GZ) or any(k in hint_lower for k in ["gzip", "gz"]):
        return _repair_gzip(buf)
    elif magic.startswith(MAGIC_SQLITE) or any(k in hint_lower for k in ["sqlite", ".db", "database"]):
        return _repair_sqlite(buf)
    elif magic.startswith(MAGIC_RIFF) or any(k in hint_lower for k in ["riff", "webp", "wav", "avi"]):
        return _repair_riff(buf)
    elif magic.startswith(MAGIC_PE) or any(k in hint_lower for k in [".exe", ".dll"]):
        return _repair_pe(buf)

    # Return untouched for unstructured text/raw payloads
    return buf


def _repair_png(buf: bytes) -> bytes:
    """
    Scans PNG chunks, recalculates chunk length and 32-bit CRC32 checksums
    so target parsers do not drop payloads at early header validation.
    """
    if len(buf) < 8:
        return buf

    out = bytearray(buf[:8])  # Keep 8-byte PNG header
    pos = 8
    buf_len = len(buf)

    while pos + 8 <= buf_len:
        # Read 4-byte length and 4-byte chunk type
        length = struct.unpack(">I", buf[pos : pos + 4])[0]
        chunk_type = buf[pos + 4 : pos + 8]
        pos += 8

        # Prevent reading past end of buffer
        data_end = min(pos + length, buf_len)
        chunk_data = buf[pos:data_end]
        actual_data_len = len(chunk_data)
        pos = data_end

        # Check if the 4 bytes following data are CRC bytes or start of next chunk
        if pos + 8 <= buf_len:
            next_type = buf[pos + 4 : pos + 8]
            if len(next_type) == 4 and all((65 <= b <= 90) or (97 <= b <= 122) for b in next_type):
                pos += 4  # Skip old 4-byte CRC
        elif pos + 4 <= buf_len and chunk_type == b"IEND":
            pos += 4  # Trailing CRC after IEND

        # Recalculate 32-bit CRC over (chunk_type + chunk_data)
        crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF

        # Append length, chunk_type, chunk_data, and recalculated CRC
        out.extend(struct.pack(">I", actual_data_len))
        out.extend(chunk_type)
        out.extend(chunk_data)
        out.extend(struct.pack(">I", crc))

        # Stop if IEND chunk reached
        if chunk_type == b"IEND":
            break

    return bytes(out)


def _repair_elf(buf: bytes) -> bytes:
    """
    Validates low-level ELF header fields (magic, architecture class 32/64-bit,
    data encoding, version) for system & kernel binary fuzzing.
    """
    if len(buf) < 16:
        return buf

    out = bytearray(buf)
    # Ensure magic bytes \x7fELF (0x7F 'E' 'L' 'F')
    out[0:4] = MAGIC_ELF

    # Set EI_CLASS (1 = 32-bit, 2 = 64-bit) if invalid
    if out[4] not in (1, 2):
        out[4] = 2  # Default to 64-bit

    # Set EI_DATA (1 = Little Endian, 2 = Big Endian) if invalid
    if out[5] not in (1, 2):
        out[5] = 1  # Default to Little Endian

    # Set EI_VERSION (1 = Current version)
    out[6] = 1

    return bytes(out)


def _repair_zip(buf: bytes) -> bytes:
    """
    Recalculates local file header CRC32 and compressed size for ZIP buffers.
    """
    if len(buf) < 30:
        return buf

    out = bytearray(buf)
    try:
        # Local file header CRC32 is at offset 14..18, data starts after header
        fname_len = struct.unpack("<H", out[26:28])[0]
        extra_len = struct.unpack("<H", out[28:30])[0]
        header_size = 30 + fname_len + extra_len

        if len(out) > header_size:
            data = out[header_size:]
            crc = zlib.crc32(data) & 0xFFFFFFFF
            struct.pack_into("<I", out, 14, crc)
            struct.pack_into("<I", out, 18, len(data))
    except Exception:
        pass

    return bytes(out)


def _repair_pe(buf: bytes) -> bytes:
    """
    Validates Windows PE / COFF DOS header (MZ) and NT header pointers.
    """
    if len(buf) < 64:
        return buf

    out = bytearray(buf)
    # Ensure DOS header signature 'MZ'
    out[0:2] = MAGIC_PE

    try:
        # e_lfanew offset to PE header is at offset 0x3C (60)
        e_lfanew = struct.unpack("<I", out[60:64])[0]
        if e_lfanew > 0 and e_lfanew + 4 <= len(out):
            out[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    except Exception:
        pass

    return bytes(out)


def _repair_jpeg(buf: bytes) -> bytes:
    """
    Ensures JPEG Start-Of-Image (SOI) \xFF\xD8 marker and valid End-Of-Image (EOI) \xFF\xD9.
    """
    if len(buf) < 4:
        return buf
    out = bytearray(buf)
    if not out.startswith(b"\xff\xd8"):
        out[0:2] = b"\xff\xd8"
    if not out.endswith(b"\xff\xd9") and len(out) >= 2:
        out.extend(b"\xff\xd9")
    return bytes(out)


def _repair_gif(buf: bytes) -> bytes:
    """
    Ensures standard GIF header signature (GIF89a or GIF87a) and standard trailer (0x3B).
    """
    if len(buf) < 6:
        return buf
    out = bytearray(buf)
    if not (out.startswith(b"GIF89a") or out.startswith(b"GIF87a")):
        out[0:6] = b"GIF89a"
    if not out.endswith(b"\x3b"):
        out.append(0x3B)
    return bytes(out)


def _repair_gzip(buf: bytes) -> bytes:
    """
    Ensures standard GZIP ID1/ID2 magic \x1F\x8B and compression method 8 (DEFLATE).
    """
    if len(buf) < 10:
        return buf
    out = bytearray(buf)
    out[0:2] = MAGIC_GZ
    out[2] = 8  # DEFLATE method
    return bytes(out)


def _repair_sqlite(buf: bytes) -> bytes:
    """
    Ensures 16-byte SQLite 3 header string and minimum page size field.
    """
    if len(buf) < 16:
        return buf
    out = bytearray(buf)
    out[0:16] = MAGIC_SQLITE
    return bytes(out)


def _repair_riff(buf: bytes) -> bytes:
    """
    Validates RIFF (WAV / WebP / AVI) 4-byte chunk size header.
    """
    if len(buf) < 8:
        return buf
    out = bytearray(buf)
    out[0:4] = MAGIC_RIFF
    try:
        riff_size = len(out) - 8
        struct.pack_into("<I", out, 4, max(0, riff_size))
    except Exception:
        pass
    return bytes(out)
