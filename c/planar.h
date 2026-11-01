/* planar.h - RDP 6.0 planar bitmap codec. */
#pragma once
#include <stddef.h>
#include <stdint.h>

/* Decode a planar stream of w x h into ARGB32 dst (dst_stride in pixels).
 * vflip: planes are bottom-up (bitmap updates); GFX planar is top-down. */
int planar_decode(const uint8_t *p, size_t n, int w, int h, int vflip, uint32_t *dst, int dst_stride);
