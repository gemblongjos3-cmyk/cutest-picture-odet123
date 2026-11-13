#!/usr/bin/env python3
"""Deterministic entry for make.fun bounty 'cutest-picture-01'.

Reads the finished picture (picture.jpg) shipped beside this file and
writes its bytes unchanged to /output/entry.png. Standard library only.
Byte-identical on every run.
"""

import hashlib
import os
import struct
import sys

MAX_BYTES = 1048576
MAX_DIMENSION = 1024
OUTPUT_PATH = "/output/entry.png"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def locate_picture():
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "picture.jpg"),
        "/bot/picture.jpg",
        "picture.jpg",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    raise FileNotFoundError(
        "picture.jpg not found in any of: " + ", ".join(candidates)
    )


def verify_image_bytes(data):
    if len(data) == 0:
        raise ValueError("picture file is empty")
    if len(data) > MAX_BYTES:
        raise ValueError(
            f"picture is {len(data)} bytes, exceeding limit of {MAX_BYTES}"
        )
    is_jpeg = data[:2] == b"\xff\xd8" and data[-2:] == b"\xff\xd9"
    is_png = data[:8] == PNG_SIGNATURE
    if not (is_jpeg or is_png):
        raise ValueError(
            "picture is not a whole JPEG (FF D8 ... FF D9) or PNG image"
        )
    return "jpeg" if is_jpeg else "png"


def image_dimensions(data, kind):
    """Return (width, height) parsed with the standard library only.

    JPEG: walk the marker segments until a Start Of Frame marker
    (SOF0 = 0xC0 or SOF2 = 0xC2) is found; its payload carries
    precision (1 byte), height (2 bytes) and width (2 bytes).
    PNG: width and height are big-endian uint32 in the IHDR chunk,
    at byte offsets 16 and 20.
    """
    if kind == "png":
        if len(data) < 24 or data[12:16] != b"IHDR":
            raise ValueError("PNG image has no IHDR chunk")
        width, height = struct.unpack(">II", data[16:24])
        return width, height
    # JPEG marker walk.
    if data[:2] != b"\xff\xd8":
        raise ValueError("JPEG image does not start with SOI")
    pos = 2
    while pos + 1 < len(data):
        if data[pos] != 0xFF:
            raise ValueError(f"corrupt JPEG marker at offset {pos}")
        marker = data[pos + 1]
        # Standalone markers carry no length field.
        if marker in (0x01,) or 0xD0 <= marker <= 0xD9:
            pos += 2
            continue
        if pos + 3 >= len(data):
            raise ValueError("truncated JPEG segment header")
        seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        if seg_len < 2:
            raise ValueError("invalid JPEG segment length")
        if marker in (0xC0, 0xC2):  # SOF0 / SOF2
            if pos + 8 >= len(data):
                raise ValueError("truncated JPEG SOF segment")
            height, width = struct.unpack(">HH", data[pos + 5 : pos + 9])
            return width, height
        pos += 2 + seg_len
    raise ValueError("no JPEG SOF0/SOF2 marker found")


def verify_dimensions(data, kind):
    width, height = image_dimensions(data, kind)
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise ValueError(
            f"picture is {width}x{height}, exceeding "
            f"{MAX_DIMENSION}x{MAX_DIMENSION}"
        )
    return width, height


def main():
    source = locate_picture()
    with open(source, "rb") as fh:
        data = fh.read()
    kind = verify_image_bytes(data)
    width, height = verify_dimensions(data, kind)
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "wb") as out:
        out.write(data)
    with open(OUTPUT_PATH, "rb") as fh:
        written = fh.read()
    source_sha = hashlib.sha256(data).hexdigest()
    written_sha = hashlib.sha256(written).hexdigest()
    if written_sha != source_sha:
        raise ValueError(
            f"output mismatch: source sha256 {source_sha} "
            f"!= output sha256 {written_sha}"
        )
    print(
        f"entry.png: {kind} {width}x{height}, {len(data)} bytes, "
        f"sha256 {written_sha} (verified byte-identical to {source})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
