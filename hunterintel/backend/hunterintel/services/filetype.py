"""Local file hashing and magic-byte type identification.

The upload is streamed through hashlib and **discarded**: nothing is written to disk,
stored, or sent to any third party. The analyst can then choose to look the *hash* up.
"""

from __future__ import annotations

import hashlib
import re
import struct
from collections.abc import AsyncIterator
from typing import Any

HEAD_BYTES = 8192

_SIGNATURES: list[tuple[bytes, int, str, str]] = [
    (b"\x7fELF", 0, "ELF executable / shared object", "application/x-executable"),
    (b"%PDF-", 0, "PDF document", "application/pdf"),
    (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        0,
        "OLE2 compound file (legacy Office document, MSI, …)",
        "application/x-ole-storage",
    ),
    (b"Rar!\x1a\x07", 0, "RAR archive", "application/vnd.rar"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", "application/x-7z-compressed"),
    (b"\x1f\x8b", 0, "gzip compressed data", "application/gzip"),
    (b"BZh", 0, "bzip2 compressed data", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", 0, "xz compressed data", "application/x-xz"),
    (b"MSCF", 0, "Microsoft Cabinet archive", "application/vnd.ms-cab-compressed"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", "image/png"),
    (b"\xff\xd8\xff", 0, "JPEG image", "image/jpeg"),
    (b"GIF87a", 0, "GIF image", "image/gif"),
    (b"GIF89a", 0, "GIF image", "image/gif"),
    (b"{\\rtf", 0, "Rich Text Format document", "application/rtf"),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit executable", "application/x-mach-binary"),
    (b"\xce\xfa\xed\xfe", 0, "Mach-O 32-bit executable", "application/x-mach-binary"),
    (
        b"\xca\xfe\xba\xbe",
        0,
        "Mach-O universal binary or Java class file",
        "application/octet-stream",
    ),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "Windows shortcut (.lnk)", "application/x-ms-shortcut"),
    (b"SQLite format 3\x00", 0, "SQLite database", "application/vnd.sqlite3"),
]
_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _pe_kind(head: bytes) -> str | None:
    if len(head) < 0x40 or not head.startswith(b"MZ"):
        return None
    (offset,) = struct.unpack_from("<I", head, 0x3C)
    if offset + 24 > len(head) or head[offset : offset + 4] != b"PE\x00\x00":
        return "DOS/MZ executable"
    (characteristics,) = struct.unpack_from("<H", head, offset + 22)
    return "Windows DLL (PE)" if characteristics & 0x2000 else "Windows executable (PE)"


def identify(head: bytes) -> dict[str, Any]:
    """Identify by leading bytes. A signature is a classification aid, not a verdict."""
    result: dict[str, Any] = {
        "type": "unknown binary or text data",
        "mime": "application/octet-stream",
        "basis": "none",
    }
    pe = _pe_kind(head)
    if pe:
        result.update(
            type=pe, mime="application/vnd.microsoft.portable-executable", basis="magic bytes"
        )
    elif head.startswith(b"PK\x03\x04"):
        names = head[:HEAD_BYTES]
        if b"word/" in names:
            label, mime = (
                "Word document (OOXML)",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        elif b"xl/" in names:
            label, mime = (
                "Excel workbook (OOXML)",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        elif b"ppt/" in names:
            label, mime = (
                "PowerPoint presentation (OOXML)",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            )
        elif b"AndroidManifest.xml" in names:
            label, mime = "Android package (APK)", "application/vnd.android.package-archive"
        elif b"META-INF/" in names:
            label, mime = "Java archive (JAR)", "application/java-archive"
        else:
            label, mime = "ZIP archive", "application/zip"
        result.update(type=label, mime=mime, basis="magic bytes")
    elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        result.update(type="WebP image", mime="image/webp", basis="magic bytes")
    elif head.startswith(b"#!"):
        line = head.split(b"\n", 1)[0][:80].decode("utf-8", "replace")
        result.update(type=f"script ({line})", mime="text/x-script", basis="shebang")
    else:
        for magic, offset, label, mime in _SIGNATURES:
            if head[offset : offset + len(magic)] == magic:
                result.update(type=label, mime=mime, basis="magic bytes")
                break
        else:
            text = head[:512].lstrip().lower()
            if _EICAR in head[:200]:
                result.update(
                    type="EICAR anti-malware test string", mime="text/plain", basis="exact content"
                )
            elif text.startswith((b"<?php", b"<html", b"<!doctype html", b"<script")):
                result.update(
                    type="web content (HTML/PHP/JS)", mime="text/html", basis="leading markup"
                )
            elif re.fullmatch(rb"[\x09\x0a\x0d\x20-\x7e]*", head[:512]) and head:
                result.update(type="plain text", mime="text/plain", basis="printable ASCII")
    result["note"] = (
        "Identified from leading bytes only. A matching signature is not a safety verdict."
    )
    return result


class FileTooLargeError(ValueError):
    pass


async def hash_stream(chunks: AsyncIterator[bytes], max_bytes: int) -> dict[str, Any]:
    md5, sha1, sha256 = (
        hashlib.md5(usedforsecurity=False),
        hashlib.sha1(usedforsecurity=False),
        hashlib.sha256(),
    )
    head = b""
    size = 0
    async for chunk in chunks:
        size += len(chunk)
        if size > max_bytes:
            raise FileTooLargeError(f"file exceeds the {max_bytes} byte limit")
        if len(head) < HEAD_BYTES:
            head += chunk[: HEAD_BYTES - len(head)]
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
    return {
        "size": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "file_type": identify(head),
        "privacy": "The file was hashed in memory and discarded. Nothing was stored or sent anywhere.",
    }
