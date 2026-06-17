#!/usr/bin/env python3
"""Generate BinaryHammer assets/icon.ico and src/rendering/app_icon.h"""
import struct, os

# Palette
BG    = (12,  14,  22,  255)   # dark navy
MAIN  = (220, 90,  40,  255)   # orange
HIGH  = (255, 145, 75,  255)   # highlight
SHADE = (130, 48,  15,  255)   # shadow
DARK  = (8,   9,   15,  255)   # very dark edge


def make_grid(size):
    return [list(BG)] * (size * size)


def sp(px, size, x, y, c):
    if 0 <= x < size and 0 <= y < size:
        px[y * size + x] = list(c)


def rect(px, size, x, y, w, h, c):
    for dy in range(h):
        for dx in range(w):
            sp(px, size, x + dx, y + dy, c)


def draw_32():
    """32x32 hammer icon."""
    s = 32
    px = make_grid(s)

    # ── Hammer head ───────────────────────────────────────────────────────
    # Main body: cols 3-19 (17 wide), rows 5-11 (7 tall)
    rect(px, s, 3, 5, 17, 7, MAIN)

    # Highlight – top edge + left face
    rect(px, s, 3, 5, 17, 1, HIGH)  # top strip
    rect(px, s, 3, 5,  3, 7, HIGH)  # left face strip

    # Shadow – bottom edge + right edge
    rect(px, s, 3, 11, 17, 1, SHADE)   # bottom strip
    rect(px, s, 19, 5,  1,  7, SHADE)  # right edge

    # 1-pixel dark outline along very top + left
    for x in range(2, 21):
        sp(px, s, x, 4, DARK)
    for y in range(4, 13):
        sp(px, s, 2, y, DARK)

    # ── Handle ────────────────────────────────────────────────────────────
    # cols 12-15 (4 wide), rows 12-25 (14 tall)
    rect(px, s, 12, 12, 4, 14, MAIN)

    # Left highlight, right shadow
    rect(px, s, 12, 12, 1, 14, HIGH)
    rect(px, s, 15, 12, 1, 14, SHADE)

    # Bottom cap
    rect(px, s, 12, 25, 4, 1, SHADE)

    # Dark outline around handle left + bottom
    for y in range(11, 27):
        sp(px, s, 11, y, DARK)
    for x in range(11, 17):
        sp(px, s, x, 26, DARK)

    return px


def draw_16():
    """16x16 hammer icon (simplified)."""
    s = 16
    px = make_grid(s)

    # Head: cols 1-10 (10w), rows 2-6 (5h)
    rect(px, s, 1, 2, 10, 5, MAIN)
    rect(px, s, 1, 2, 10, 1, HIGH)   # top highlight
    rect(px, s, 1, 2,  2, 5, HIGH)   # left face
    rect(px, s, 1, 6, 10, 1, SHADE)  # bottom shadow
    rect(px, s,10, 2,  1, 5, SHADE)  # right shadow

    # Handle: cols 6-8 (3w), rows 7-13 (7h)
    rect(px, s, 6, 7, 3, 7, MAIN)
    rect(px, s, 6, 7, 1, 7, HIGH)
    rect(px, s, 8, 7, 1, 7, SHADE)
    rect(px, s, 6,13, 3, 1, SHADE)

    return px


def draw_48():
    """48x48 hammer icon (scaled-up version)."""
    s = 48
    px = make_grid(s)

    # Head: cols 4-29 (26w), rows 7-17 (11h)
    rect(px, s,  4,  7, 26, 11, MAIN)
    rect(px, s,  4,  7, 26,  2, HIGH)
    rect(px, s,  4,  7,  5, 11, HIGH)
    rect(px, s,  4, 17, 26,  1, SHADE)
    rect(px, s, 29,  7,  1, 11, SHADE)

    for x in range(3, 31): sp(px, s, x,  6, DARK)
    for y in range(6, 19): sp(px, s,  3, y, DARK)

    # Handle: cols 18-23 (6w), rows 18-37 (20h)
    rect(px, s, 18, 18, 6, 20, MAIN)
    rect(px, s, 18, 18, 1, 20, HIGH)
    rect(px, s, 23, 18, 1, 20, SHADE)
    rect(px, s, 18, 37, 6,  1, SHADE)

    for y in range(17, 40): sp(px, s, 17, y, DARK)
    for x in range(17, 25): sp(px, s,  x, 39, DARK)

    return px


def flatten(px):
    return bytes(sum(px, []))


def make_bmp_blob(w, h, rgba):
    """ICO-compatible BMP blob (32-bit BGRA, bottom-up, with AND mask)."""
    header = struct.pack('<IiiHHIIiiII',
        40, w, h * 2, 1, 32, 0, w * h * 4, 0, 0, 0, 0)

    bgra = bytearray()
    for row in range(h - 1, -1, -1):
        for col in range(w):
            idx = (row * w + col) * 4
            r, g, b, a = rgba[idx:idx + 4]
            bgra += bytes([b, g, r, a])

    row_stride = ((w + 31) // 32) * 4
    and_mask   = bytes(row_stride * h)

    return header + bytes(bgra) + and_mask


def write_ico(path, images):
    """images: list of (size, rgba_bytes)"""
    n      = len(images)
    blobs  = [make_bmp_blob(s, s, rb) for s, rb in images]
    offset = 6 + 16 * n

    ico_hdr = struct.pack('<HHH', 0, 1, n)
    dir_entries = b''
    for (s, _), blob in zip(images, blobs):
        dir_entries += struct.pack('<BBBBHHII',
            s if s < 256 else 0,
            s if s < 256 else 0,
            0, 0, 1, 32, len(blob), offset)
        offset += len(blob)

    with open(path, 'wb') as f:
        f.write(ico_hdr + dir_entries)
        for blob in blobs:
            f.write(blob)


def write_header(path, px32):
    flat = flatten(px32)
    lines = [
        '#pragma once',
        '',
        'static const unsigned char app_icon_32x32[32 * 32 * 4] = {',
    ]
    for row in range(0, len(flat), 128):   # 32 pixels × 4 bytes
        chunk = flat[row:row + 128]
        lines.append('  ' + ', '.join(f'0x{b:02x}' for b in chunk) + ',')
    lines.append('};')
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(root, 'assets'), exist_ok=True)

    px16 = draw_16()
    px32 = draw_32()
    px48 = draw_48()

    ico_path = os.path.join(root, 'assets', 'icon.ico')
    hdr_path = os.path.join(root, 'src', 'rendering', 'app_icon.h')

    write_ico(ico_path, [
        (16, flatten(px16)),
        (32, flatten(px32)),
        (48, flatten(px48)),
    ])
    write_header(hdr_path, px32)

    print(f'[+] {ico_path}')
    print(f'[+] {hdr_path}')
