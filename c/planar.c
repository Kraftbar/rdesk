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

/* ---- encoder --------------------------------------------------------- */

static void seg(uint8_t **o, const uint8_t *raw, int k, int run)
{
	*(*o)++ = k << 4 | run;
	memcpy(*o, raw, k);
	*o += k;
}

/* One scanline of symbols (raw values on the first line, delta codes after)
 * as RLE segments. A run repeats the previous symbol, 0 at line start. */
static void rle_line(const uint8_t *v, int w, uint8_t **o)
{
	uint8_t raw[15];
	int k = 0, last = 0, i = 0;
	while (i < w) {
		int r = 0;
		while (i + r < w && v[i + r] == last)
			r++;
		if (r >= 3) {
			int first = r > 15 ? 15 : r;
			seg(o, raw, k, first);
			k = 0;
			int rest = r - first;
			while (rest >= 3) {
				int n;
				if (rest >= 32) {
					n = rest - 32 > 15 ? 47 : rest;
					*(*o)++ = (n - 32) << 4 | 2;
				} else if (rest >= 16) {
					n = rest;
					*(*o)++ = (n - 16) << 4 | 1;
				} else {
					n = rest;
					*(*o)++ = n;
				}
				rest -= n;
			}
			i += r - rest; /* 1 or 2 leftovers go out as raw */
			continue;
		}
		raw[k++] = v[i];
		last = v[i];
		i++;
		if (k == 15) {
			seg(o, raw, k, 0);
			k = 0;
		}
	}
	if (k)
		seg(o, raw, k, 0);
}

size_t planar_encode(const uint8_t *src, int stride, int w, int h, int vflip, uint8_t *out)
{
	uint8_t *o = out, *cur = malloc(w), *prev = malloc(w), *sym = malloc(w);
	*o++ = 0x30; /* RLE | no alpha, no color loss */
	for (int plane = 2; plane >= 0; plane--) { /* R, G, B = bytes 2, 1, 0 of BGRX */
		for (int y = 0; y < h; y++) {
			const uint8_t *row = src + (size_t)(vflip ? h - 1 - y : y) * stride;
			for (int x = 0; x < w; x++)
				cur[x] = row[x * 4 + plane];
			if (!y) {
				memcpy(sym, cur, w);
			} else {
				for (int x = 0; x < w; x++) {
					int d = (int8_t)(cur[x] - prev[x]);
					sym[x] = d >= 0 ? 2 * d : 2 * -d - 1;
				}
			}
			rle_line(sym, w, &o);
			uint8_t *t = prev;
			prev = cur;
			cur = t;
		}
	}
	free(cur);
	free(prev);
	free(sym);
	return o - out;
}
