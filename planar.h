/* planar.h - RDP 6.0 planar bitmap codec. */
#pragma once
#include <stddef.h>
#include <stdint.h>

/* Decode a planar stream of w x h into ARGB32 dst (dst_stride in pixels).
 * vflip: planes are bottom-up (bitmap updates); GFX planar is top-down. */
int planar_decode(const uint8_t *p, size_t n, int w, int h, int vflip, uint32_t *dst, int dst_stride);

/* Encode w x h BGRX pixels as planar RLE without alpha. out needs
 * planar_max(w, h) bytes. vflip: bottom-up planes (bitmap updates).
 * flags (diagnostics): PLANAR_SWAP_RB sends blue first, PLANAR_ALPHA an
 * opaque alpha plane instead of the no-alpha flag. */
#define PLANAR_SWAP_RB 1
#define PLANAR_ALPHA 2
#define planar_max(w, h) (1 + 4 * ((size_t)(h) * ((w) + (w) / 15 + 2)))
size_t planar_encode(const uint8_t *src, int stride, int w, int h, int vflip, int flags, uint8_t *out);
