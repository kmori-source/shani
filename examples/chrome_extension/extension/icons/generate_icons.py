"""
Run this script once to generate the PNG icon files for the Chrome extension.
Usage: python3 generate_icons.py
"""

import struct
import zlib
import os


def create_png(width, height, r, g, b):
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    raw = b""
    for _ in range(height):
        raw += b"\x00"
        raw += bytes([r, g, b] * width)
    idat = chunk(b"IDAT", zlib.compress(raw))
    iend = chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


if __name__ == "__main__":
    icons_dir = os.path.dirname(os.path.abspath(__file__))
    for size in [16, 48, 128]:
        data = create_png(size, size, 99, 102, 241)
        path = os.path.join(icons_dir, f"icon{size}.png")
        with open(path, "wb") as f:
            f.write(data)
        print(f"Created {path} ({len(data)} bytes)")
