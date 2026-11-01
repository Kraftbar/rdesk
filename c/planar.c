/* planar.c - RDP 6.0 planar bitmap codec (MS-RDPEGDI 2.2.2.5.1, 3.1.9).
 * Decoder: raw or RLE planes, alpha, color loss (YCoCg) and chroma
 * subsampling. */
#include "planar.h"

#include <stdlib.h>
#include <string.h>

/* One RLE plane of w x h into out (stored scanline order). Returns bytes
 * consumed, or -1. */
static long rle_plane(const uint8_t *p, size_t n, int w, int h, uint8_t *out)
{
	size_t i = 0;
	for (int y = 0; y < h; y++) {
		uint8_t *row = out + (size_t)y * w;
		const uint8_t *prev = y ? row - w : NULL;
		int x = 0;
		int pixel = 0;
		while (x < w) {
			if (i >= n)
				return -1;
			uint8_t ctl = p[i++];
			int run = ctl & 0x0f, raw = ctl >> 4;
			if (run == 1) {
				run = 16 + raw;
				raw = 0;
			} else if (run == 2) {
				run = 32 + raw;
				raw = 0;
			}
			if (x + raw + run > w || i + raw > n)
				return -1;
			for (int k = 0; k < raw; k++, x++) {
				uint8_t v = p[i++];
				if (!prev) {
					pixel = v;
					row[x] = v;
				} else {
					pixel = v & 1 ? -((v >> 1) + 1) : v >> 1;
					row[x] = prev[x] + pixel;
				}
			}
			for (int k = 0; k < run; k++, x++)
				row[x] = prev ? prev[x] + pixel : pixel;
		}
	}
	return i;
}

static inline uint8_t clamp(int v)
{
	return v < 0 ? 0 : v > 255 ? 255 : v;
}

int planar_decode(const uint8_t *p, size_t n, int w, int h, int vflip, uint32_t *dst, int dst_stride)
{
	if (n < 1 || w <= 0 || h <= 0)
		return -1;
	uint8_t hdr = p[0];
	int cll = hdr & 7, cs = hdr >> 3 & 1, rle = hdr >> 4 & 1, na = hdr >> 5 & 1;
	if (cs && !cll)
		return -1;
	size_t i = 1;
	int cw = cs ? (w + 1) / 2 : w, ch = cs ? (h + 1) / 2 : h;
	int pw[4] = {w, w, cs ? cw : w, cs ? cw : w};
	int ph[4] = {h, h, cs ? ch : h, cs ? ch : h};
	uint8_t *pl[4] = {0};
	int rc = -1;
	for (int k = 0; k < 4; k++) {
		pl[k] = malloc((size_t)pw[k] * ph[k]);
		if (!pl[k])
			goto out;
	}
	if (na)
		memset(pl[0], 0xff, (size_t)w * h);
	for (int k = na ? 1 : 0; k < 4; k++) {
		size_t sz = (size_t)pw[k] * ph[k];
		if (rle) {
			long used = rle_plane(p + i, n - i, pw[k], ph[k], pl[k]);
			if (used < 0)
				goto out;
			i += used;
		} else {
			if (i + sz > n)
				goto out;
			memcpy(pl[k], p + i, sz);
			i += sz;
		}
	}
	for (int y = 0; y < h; y++) {
		uint32_t *row = dst + (size_t)(vflip ? h - 1 - y : y) * dst_stride;
		const uint8_t *a = pl[0] + (size_t)y * w, *p1 = pl[1] + (size_t)y * w;
		int cy = cs ? y / 2 : y;
		const uint8_t *p2 = pl[2] + (size_t)cy * pw[2], *p3 = pl[3] + (size_t)cy * pw[3];
		for (int x = 0; x < w; x++) {
			int cx = cs ? x / 2 : x;
			int r, g, b;
			if (!cll) {
				r = p1[x];
				g = p2[cx];
				b = p3[cx];
			} else {
				int Y = p1[x];
				int co = (int8_t)p2[cx] * (1 << (cll - 1));
				int cg = (int8_t)p3[cx] * (1 << (cll - 1));
				r = clamp(Y + co - cg);
				g = clamp(Y + cg);
				b = clamp(Y - co - cg);
			}
			row[x] = (uint32_t)a[x] << 24 | r << 16 | g << 8 | b;
		}
	}
	rc = 0;
out:
	for (int k = 0; k < 4; k++)
		free(pl[k]);
	return rc;
}
