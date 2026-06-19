#!/usr/bin/env python3
"""
Generate BinaryHammer assets/icon.ico and src/rendering/app_icon.h
Design: diagonal metallic hammer — steel head, amber wood handle, spark accents.
"""
import struct, os, math

def clamp(v): return max(0, min(255, int(v)))
def lerp(a, b, t): return clamp(a + (b - a) * t)
def lerp3(c0, c1, t): return (lerp(c0[0],c1[0],t), lerp(c0[1],c1[1],t), lerp(c0[2],c1[2],t))


def make_pixels(size):
    W = H = size
    sc = size / 32.0
    pix = [[0, 0, 0, 0] for _ in range(W * H)]

    def put(x, y, r, g, b, a=255):
        xi, yi = int(x), int(y)
        if 0 <= xi < W and 0 <= yi < H:
            pix[yi * W + xi] = [clamp(r), clamp(g), clamp(b), clamp(a)]

    def blend(x, y, r, g, b, a=255):
        xi, yi = int(x), int(y)
        if 0 <= xi < W and 0 <= yi < H:
            d = pix[yi * W + xi]
            t = a / 255.0
            pix[yi * W + xi] = [
                clamp(d[0]*(1-t) + r*t),
                clamp(d[1]*(1-t) + g*t),
                clamp(d[2]*(1-t) + b*t),
                max(d[3], clamp(a))
            ]

    def local(px, py, cx, cy, angle_deg):
        a = math.radians(-angle_deg)
        dx = px - cx; dy = py - cy
        return dx*math.cos(a) - dy*math.sin(a), dx*math.sin(a) + dy*math.cos(a)

    def in_rect(lx, ly, w, h):
        return abs(lx) <= w/2 and abs(ly) <= h/2

    # ── Background: dark rounded square ───────────────────────────────────
    BG  = (18, 20, 28)
    BG2 = (26, 30, 44)
    cr   = 5.0 * sc
    half = size / 2.0
    for y in range(H):
        for x in range(W):
            ex = max(abs(x + 0.5 - half) - (half - cr), 0.0)
            ey = max(abs(y + 0.5 - half) - (half - cr), 0.0)
            if ex*ex + ey*ey <= cr*cr:
                t = (x + y) / (2.0 * size)
                c = lerp3(BG, BG2, t)
                put(x, y, *c, 255)

    # Head: long axis NE-SW (angle=-45°), wide-and-flat
    # Handle: long axis SE-NW (angle=+45°), connects from head center down-right
    HEAD_ANG   = -45.0
    HANDLE_ANG = +45.0

    # All coords in 32-space, scaled by sc
    HEAD_CX, HEAD_CY = 11.0*sc, 11.0*sc
    HEAD_W,  HEAD_H  = 18.0*sc,  9.0*sc

    HAND_CX, HAND_CY = 20.0*sc, 20.0*sc
    HAND_W,  HAND_H  = 20.0*sc,  5.0*sc   # W = length, H = thickness

    # Metallic steel colours
    STEEL_DARK   = (50,  56,  68)
    STEEL_MID    = (95, 108, 126)
    STEEL_LIGHT  = (158, 176, 198)
    STEEL_BRIGHT = (214, 230, 248)
    STEEL_WHITE  = (240, 250, 255)

    # Amber wood colours
    WOOD_BRIGHT = (225, 130, 32)
    WOOD_MID    = (175,  85, 15)
    WOOD_DARK   = (105,  48,  7)

    # ── Handle (drawn first — head overlaps) ─────────────────────────────
    for y in range(H):
        for x in range(W):
            lx, ly = local(x+0.5, y+0.5, HAND_CX, HAND_CY, HANDLE_ANG)
            if in_rect(lx, ly, HAND_W, HAND_H):
                tx = lx / (HAND_W / 2)   # -1=neck, +1=butt
                ty = ly / (HAND_H / 2)   # -1=upper, +1=lower

                # Cylindrical wood: bright upper side, dark lower
                side = (ty + 1) / 2.0
                if side < 0.3:
                    c = lerp3(WOOD_BRIGHT, WOOD_MID, side / 0.3)
                elif side < 0.7:
                    c = lerp3(WOOD_MID, WOOD_DARK, (side - 0.3) / 0.4)
                else:
                    c = WOOD_DARK

                # Darken at neck (near head)
                neck = max(0.0, (-tx - 0.4) / 0.6) * 0.5
                put(x, y, clamp(c[0]*(1-neck)), clamp(c[1]*(1-neck)), clamp(c[2]*(1-neck)), 255)

    # ── Hammer head ───────────────────────────────────────────────────────
    for y in range(H):
        for x in range(W):
            lx, ly = local(x+0.5, y+0.5, HEAD_CX, HEAD_CY, HEAD_ANG)
            if in_rect(lx, ly, HEAD_W, HEAD_H):
                tx = lx / (HEAD_W / 2)   # -1=face (SW), +1=poll (NE)
                ty = ly / (HEAD_H / 2)   # -1=upper (NW), +1=lower (SE)

                # Lighting: face edge bright, top face bright, back-bottom dark
                face_t = max(0.0, -tx) * 0.65
                top_t  = max(0.0, -ty - 0.1) * 0.55
                total  = min(1.0, face_t + top_t)
                shadow = max(0.0, tx * 0.45 + ty * 0.3) * 0.55

                if total > 0.82:
                    c = lerp3(STEEL_BRIGHT, STEEL_WHITE, (total - 0.82) / 0.18)
                elif total > 0.55:
                    c = lerp3(STEEL_LIGHT, STEEL_BRIGHT, (total - 0.55) / 0.27)
                elif total > 0.28:
                    c = lerp3(STEEL_MID, STEEL_LIGHT, (total - 0.28) / 0.27)
                else:
                    c = lerp3(STEEL_DARK, STEEL_MID, total / 0.28)

                put(x, y,
                    clamp(c[0]*(1-shadow)),
                    clamp(c[1]*(1-shadow)),
                    clamp(c[2]*(1-shadow)), 255)

    # ── Bright glint along head's NW face (top edge) ──────────────────────
    for y in range(H):
        for x in range(W):
            lx, ly = local(x+0.5, y+0.5, HEAD_CX, HEAD_CY, HEAD_ANG)
            if in_rect(lx, ly, HEAD_W, HEAD_H):
                ty = ly / (HEAD_H / 2)
                if ty < -0.80:
                    blend(x, y, 245, 252, 255, 180)

    # ── Bright edge on striking face ──────────────────────────────────────
    for y in range(H):
        for x in range(W):
            lx, ly = local(x+0.5, y+0.5, HEAD_CX, HEAD_CY, HEAD_ANG)
            if in_rect(lx, ly, HEAD_W, HEAD_H):
                tx = lx / (HEAD_W / 2)
                if tx < -0.87:
                    blend(x, y, 248, 254, 255, 200)

    # ── Orange ferrule (collar where handle meets head) ───────────────────
    # Place it at the handle's neck end, just outside the head's lower edge
    FERR_CX = 14.5 * sc
    FERR_CY = 14.5 * sc
    FERR_W  =  6.5 * sc
    FERR_H  =  3.0 * sc
    for y in range(H):
        for x in range(W):
            lx, ly = local(x+0.5, y+0.5, FERR_CX, FERR_CY, HANDLE_ANG)
            if in_rect(lx, ly, FERR_W, FERR_H):
                # Only draw if NOT inside head body (avoids painting over steel)
                hlx, hly = local(x+0.5, y+0.5, HEAD_CX, HEAD_CY, HEAD_ANG)
                if not in_rect(hlx, hly, HEAD_W * 0.95, HEAD_H * 0.95):
                    blend(x, y, 200, 105, 18, 210)

    # ── Orange + yellow sparks at striking face ───────────────────────────
    # Face centre in screen space (32-scale) ≈ (4.6, 17.4); shift a bit out
    fx = int(2.8 * sc)
    fy = int(18.5 * sc)
    sparks = [
        ( 0,  0, 255, 185,  20, 230),
        (-1,  1, 255, 145,   5, 190),
        ( 1, -1, 255, 215,  55, 175),
        (-1, -1, 255, 160,  10, 160),
        ( 0, -2, 255, 238,  95, 155),
        ( 2,  1, 230, 115,  10, 140),
        (-2,  0, 255, 200,  40, 130),
    ]
    spread = max(1, int(sc * 0.9))
    for sdx, sdy, sr, sg, sb, sa in sparks:
        blend(fx + sdx*spread, fy + sdy*spread, sr, sg, sb, sa)

    return pix


def flatten(pix):
    return bytes(sum(pix, []))


def make_bmp_blob(w, h, rgba):
    header = struct.pack('<IiiHHIIiiII', 40, w, h*2, 1, 32, 0, w*h*4, 0, 0, 0, 0)
    bgra = bytearray()
    for row in range(h-1, -1, -1):
        for col in range(w):
            idx = (row*w + col)*4
            r, g, b, a = rgba[idx:idx+4]
            bgra += bytes([b, g, r, a])
    row_stride = ((w + 31) // 32) * 4
    and_mask   = bytes(row_stride * h)
    return header + bytes(bgra) + and_mask


def write_ico(path, images):
    n      = len(images)
    blobs  = [make_bmp_blob(s, s, rb) for s, rb in images]
    offset = 6 + 16*n
    ico_hdr = struct.pack('<HHH', 0, 1, n)
    dir_entries = b''
    for (s, _), blob in zip(images, blobs):
        dir_entries += struct.pack('<BBBBHHII',
            s if s < 256 else 0, s if s < 256 else 0,
            0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    with open(path, 'wb') as f:
        f.write(ico_hdr + dir_entries)
        for blob in blobs:
            f.write(blob)


def write_header(path, pix32):
    flat = flatten(pix32)
    lines = [
        '#pragma once',
        '',
        'static const unsigned char app_icon_32x32[32 * 32 * 4] = {',
    ]
    for row in range(0, len(flat), 128):
        chunk = flat[row:row+128]
        lines.append('  ' + ', '.join(f'0x{b:02x}' for b in chunk) + ',')
    lines.append('};')
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(root, 'assets'), exist_ok=True)

    px16 = make_pixels(16)
    px32 = make_pixels(32)
    px48 = make_pixels(48)

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
