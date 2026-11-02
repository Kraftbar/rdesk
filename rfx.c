/* rfx.c - RemoteFX (MS-RDPRFX) encoder, as FreeRDP's: per 64x64 tile,
 * RGB to YCbCr (ICT) with 5 fractional bits, three levels of the 5/3
 * wavelet (DWT_53_A), scalar quantization, LL3 differences, RLGR1. */
#include "rfx.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define T 64

/* LL3 LH3 HL3 HH3 LH2 HL2 HH2 LH1 HL1 HH1: FreeRDP's default */
static const uint8_t quant[10] = {6, 6, 6, 6, 7, 7, 8, 8, 8, 9};

#define CODEC_MODE 0x02 /* image mode: every message stands alone */
#define COL_CONV_ICT 1
#define CLW_XFORM_DWT_53_A 1
#define CLW_ENTROPY_RLGR1 1
#define SCALAR_QUANTIZATION 1

/* ---- RLGR1 ----------------------------------------------------------- */

typedef struct {
	buf *b;
	uint32_t acc;
	int n;
} bits;

static void put_bits(bits *s, uint32_t v, int n)
{
	if (!n)
		return;
	s->acc = s->acc << n | (v & ((1u << n) - 1));
	s->n += n;
	while (s->n >= 8) {
		s->n -= 8;
		w_u8(s->b, s->acc >> s->n);
	}
	s->acc &= (1u << s->n) - 1;
}

static void put_ones(bits *s, uint32_t count)
{
	for (; count > 16; count -= 16)
		put_bits(s, 0xffff, 16);
	put_bits(s, 0xffff, count);
}

static void put_flush(bits *s)
{
	if (s->n)
		w_u8(s->b, s->acc << (8 - s->n));
	s->n = 0;
	s->acc = 0;
}

#define KPMAX 80
#define LSGR 3
#define UP_GR 4
#define DN_GR 6
#define UQ_GR 3
#define DQ_GR 3

static void update(int *p, int d)
{
	*p += d;
	*p = *p < 0 ? 0 : *p > KPMAX ? KPMAX : *p;
}

static void code_gr(bits *s, int *krp, uint32_t val)
{
	int kr = *krp >> LSGR;
	uint32_t vk = val >> kr;
	put_ones(s, vk);
	put_bits(s, 0, 1);
	put_bits(s, val, kr);
	if (vk == 0)
		update(krp, -2);
	else if (vk > 1)
		update(krp, vk);
}

static void rlgr1(buf *out, const int16_t *d, int n)
{
	bits s = {out, 0, 0};
	int kp = 1 << LSGR, krp = 1 << LSGR, i = 0;
	while (i < n) {
		int k = kp >> LSGR;
		if (k) {
			/* run of zeros, then a value */
			int zeros = 0, in = d[i++];
			while (in == 0 && i < n) {
				zeros++;
				in = d[i++];
			}
			while (zeros >= 1 << k) {
				put_bits(&s, 0, 1);
				zeros -= 1 << k;
				update(&kp, UP_GR);
				k = kp >> LSGR;
			}
			put_bits(&s, 1, 1);
			put_bits(&s, zeros, k);
			int mag = in < 0 ? -in : in;
			put_bits(&s, in < 0, 1);
			code_gr(&s, &krp, mag ? mag - 1 : 0);
			update(&kp, -DN_GR);
		} else {
			/* Golomb-Rice of 2 * magnitude - sign */
			int in = d[i++];
			uint32_t two = in >= 0 ? 2 * in : -2 * in - 1;
			code_gr(&s, &krp, two);
			update(&kp, two ? -DQ_GR : UQ_GR);
		}
	}
	put_flush(&s);
}

/* ---- wavelet, quantization ------------------------------------------- */

/* One level on the sw*2 square at buf: HL, LH, HH, LL sub-bands, each
 * sw x sw, in that order. */
static void dwt_level(int16_t *buf, int16_t *tmp, int sw)
{
	int tw = sw * 2;
	/* vertical: L rows then H rows into tmp */
	for (int x = 0; x < tw; x++) {
		for (int n = 0; n < sw; n++) {
			int16_t *l = tmp + n * tw + x, *h = l + sw * tw;
			const int16_t *src = buf + n * 2 * tw + x;
			*h = (src[tw] - ((src[0] + src[n < sw - 1 ? 2 * tw : 0]) >> 1)) >> 1;
			*l = src[0] + (n == 0 ? *h : (*h + *(h - tw)) >> 1);
		}
	}
	/* horizontal: L gives HL and LL, H gives HH and LH */
	int16_t *hl = buf, *lh = buf + sw * sw, *hh = buf + sw * sw * 2, *ll = buf + sw * sw * 3;
	const int16_t *ls = tmp, *hs = tmp + sw * tw;
	for (int y = 0; y < sw; y++) {
		for (int n = 0; n < sw; n++) {
			int x = n * 2;
			hl[n] = (ls[x + 1] - ((ls[x] + ls[n < sw - 1 ? x + 2 : x]) >> 1)) >> 1;
			ll[n] = ls[x] + (n == 0 ? hl[n] : (hl[n] + hl[n - 1]) >> 1);
		}
		for (int n = 0; n < sw; n++) {
			int x = n * 2;
			hh[n] = (hs[x + 1] - ((hs[x] + hs[n < sw - 1 ? x + 2 : x]) >> 1)) >> 1;
			lh[n] = hs[x] + (n == 0 ? hh[n] : (hh[n] + hh[n - 1]) >> 1);
		}
		hl += sw;
		ll += sw;
		lh += sw;
		hh += sw;
		ls += tw;
		hs += tw;
	}
}

static void quant_block(int16_t *d, int n, int factor)
{
	if (factor <= 0)
		return;
	int half = 1 << (factor - 1);
	for (int i = 0; i < n; i++)
		d[i] = (d[i] + half) >> factor;
}

/* One component of a tile, 4096 coefficients, onto out. */
static void encode_component(buf *out, int16_t *d)
{
	int16_t tmp[T * T];
	dwt_level(d, tmp, 32);
	dwt_level(d + 3072, tmp, 16);
	dwt_level(d + 3840, tmp, 8);
	quant_block(d, 1024, quant[8] - 6);        /* HL1 */
	quant_block(d + 1024, 1024, quant[7] - 6); /* LH1 */
	quant_block(d + 2048, 1024, quant[9] - 6); /* HH1 */
	quant_block(d + 3072, 256, quant[5] - 6);  /* HL2 */
	quant_block(d + 3328, 256, quant[4] - 6);  /* LH2 */
	quant_block(d + 3584, 256, quant[6] - 6);  /* HH2 */
	quant_block(d + 3840, 64, quant[2] - 6);   /* HL3 */
	quant_block(d + 3904, 64, quant[1] - 6);   /* LH3 */
	quant_block(d + 3968, 64, quant[3] - 6);   /* HH3 */
	quant_block(d + 4032, 64, quant[0] - 6);   /* LL3 */
	quant_block(d, 4096, 5);                   /* the 5 fractional bits */
	for (int i = 63; i > 0; i--)
		d[4032 + i] -= d[4032 + i - 1];
	rlgr1(out, d, 4096);
}

static int16_t clamp12(int v)
{
	return v < -4096 ? -4096 : v > 4095 ? 4095 : v;
}

/* A tile as a CBT_TILE, or for progressive a TILE_SIMPLE: the same
 * component data, after a different header. */
static void encode_tile(buf *out, const uint8_t *cur, int stride, int w, int h, int tx, int ty, int progressive)
{
	int16_t yc[T * T], cb[T * T], cr[T * T]; /* per thread */
	/* edge tiles repeat their last pixel */
	for (int r = 0; r < T; r++) {
		int sy = ty * T + r < h ? ty * T + r : h - 1;
		const uint8_t *row = cur + (size_t)sy * stride;
		for (int c = 0; c < T; c++) {
			int sx = tx * T + c < w ? tx * T + c : w - 1;
			const uint8_t *p = row + sx * 4;
			int b = p[0], g = p[1], rd = p[2], i = r * T + c;
			yc[i] = clamp12(((9798 * rd + 19235 * g + 3735 * b) >> 10) - 4096);
			cb[i] = clamp12((-5535 * rd - 10868 * g + 16403 * b) >> 10);
			cr[i] = clamp12((16377 * rd - 13714 * g - 2663 * b) >> 10);
		}
	}
	size_t at = out->len;
	w_u16(out, progressive ? 0xccc5 : 0xcac3); /* TILE_SIMPLE, CBT_TILE */
	w_u32(out, 0);
	w_u8(out, 0); /* quant indexes: the one set */
	w_u8(out, 0);
	w_u8(out, 0);
	w_u16(out, tx);
	w_u16(out, ty);
	if (progressive)
		w_u8(out, 0); /* flags: not a difference */
	size_t lens = out->len;
	w_zero(out, progressive ? 8 : 6); /* Y, Cb, Cr lengths; progressive: no tail */
	int16_t *comp[3] = {yc, cb, cr};
	for (int i = 0; i < 3; i++) {
		size_t start = out->len;
		encode_component(out, comp[i]);
		put_u16(out, lens + 2 * i, out->len - start);
	}
	put_u32(out, at + 2, out->len - at);
}

/* A run of tiles (indexes into the tw-wide grid) for one thread. */
typedef struct {
	const uint8_t *cur;
	int stride, w, h, tw, progressive;
	const int *tiles;
	int n;
	buf out;
} job;

static void *run_job(void *arg)
{
	job *j = arg;
	for (int i = 0; i < j->n; i++)
		encode_tile(&j->out, j->cur, j->stride, j->w, j->h, j->tiles[i] % j->tw, j->tiles[i] / j->tw,
			    j->progressive);
	return NULL;
}

/* The marked tiles onto o, in grid order. A whole-screen change is a few
 * hundred tiles at a quarter millisecond each: split over the cores,
 * contiguous runs, appended in order. */
static void encode_tiles(buf *o, const uint8_t *cur, int stride, int w, int h, const uint8_t *mark, int tw, int th,
			 int progressive)
{
	enum { MAXJOBS = 8, MINRUN = 16 };
	int *tiles = malloc(tw * th * sizeof *tiles), count = 0;
	for (int i = 0; i < tw * th; i++)
		if (mark[i])
			tiles[count++] = i;
	static int cores;
	if (!cores) {
		cores = sysconf(_SC_NPROCESSORS_ONLN);
		cores = cores < 1 ? 1 : cores > MAXJOBS ? MAXJOBS : cores;
	}
	int njobs = count / MINRUN < cores ? count / MINRUN : cores;
	if (njobs < 2) {
		job j = {cur, stride, w, h, tw, progressive, tiles, count, *o};
		run_job(&j);
		*o = j.out;
		free(tiles);
		return;
	}
	job jobs[MAXJOBS];
	pthread_t th_id[MAXJOBS];
	int started[MAXJOBS] = {0};
	for (int k = 0, start = 0; k < njobs; k++) {
		int end = count * (k + 1) / njobs;
		jobs[k] = (job){cur, stride, w, h, tw, progressive, tiles + start, end - start, {0}};
		b_init(&jobs[k].out, (end - start) * 1024);
		start = end;
	}
	/* this thread takes the first run, and any a thread couldn't */
	for (int k = 1; k < njobs; k++)
		started[k] = !pthread_create(&th_id[k], NULL, run_job, &jobs[k]);
	for (int k = 0; k < njobs; k++)
		if (!started[k])
			run_job(&jobs[k]);
	for (int k = 0; k < njobs; k++) {
		if (started[k])
			pthread_join(th_id[k], NULL);
		w_bytes(o, jobs[k].out.p, jobs[k].out.len);
		b_free(&jobs[k].out);
	}
	free(tiles);
}

/* The tiles rects touch, marked in a tw x th grid; their count. */
static uint8_t *touched(const gfx_rect *rects, int n, int tw, int th, int *count)
{
	uint8_t *mark = calloc(tw * th, 1);
	for (int i = 0; i < n; i++)
		for (int y = rects[i].y / T; y <= (rects[i].y + rects[i].h - 1) / T; y++)
			memset(mark + y * tw + rects[i].x / T, 1, (rects[i].x + rects[i].w - 1) / T - rects[i].x / T + 1);
	*count = 0;
	for (int i = 0; i < tw * th; i++)
		*count += mark[i];
	return mark;
}

/* Each marked tile as a rect, clipped to w x h. */
static void tile_rects(buf *o, const uint8_t *mark, int tw, int th, int w, int h)
{
	for (int y = 0; y < th; y++)
		for (int x = 0; x < tw; x++)
			if (mark[y * tw + x]) {
				w_u16(o, x * T);
				w_u16(o, y * T);
				w_u16(o, x * T + T > w ? w - x * T : T);
				w_u16(o, y * T + T > h ? h - y * T : T);
			}
}

void rfx_progressive(buf *o, const uint8_t *cur, int stride, int w, int h, const gfx_rect *rects, int n,
		     uint32_t frame)
{
	/* as FreeRDP's encoder: sync, context, frame begin, one region of
	 * simple (full quality, one pass) tiles, frame end */
	w_u16(o, 0xccc0);
	w_u32(o, 12);
	w_u32(o, 0xcaccacca);
	w_u16(o, 0x0100);

	w_u16(o, 0xccc3); /* context */
	w_u32(o, 10);
	w_u8(o, 0);
	w_u16(o, T);
	w_u8(o, 0); /* no subband diffing */

	w_u16(o, 0xccc1); /* frame begin */
	w_u32(o, 12);
	w_u32(o, frame);
	w_u16(o, 1);

	int tw = (w + T - 1) / T, th = (h + T - 1) / T, count;
	uint8_t *mark = touched(rects, n, tw, th, &count);
	size_t at = o->len;
	w_u16(o, 0xccc4); /* region */
	w_u32(o, 0);
	w_u8(o, T);
	w_u16(o, count);
	w_u8(o, 1); /* quant sets */
	w_u8(o, 0); /* progressive quant sets */
	w_u8(o, 0); /* flags: the plain wavelet, not reduce-extrapolate */
	w_u16(o, count);
	size_t size_at = o->len;
	w_u32(o, 0);
	tile_rects(o, mark, tw, th, w, h);
	for (int i = 0; i < 10; i += 2)
		w_u8(o, quant[i] | quant[i + 1] << 4);
	size_t tiles_at = o->len;
	encode_tiles(o, cur, stride, w, h, mark, tw, th, 1);
	free(mark);
	put_u32(o, size_at, o->len - tiles_at);
	put_u32(o, at + 2, o->len - at);

	w_u16(o, 0xccc2); /* frame end */
	w_u32(o, 6);
}

/* ---- message --------------------------------------------------------- */

static void rfx_headers(buf *o, int w, int h);
static void rfx_frame(buf *o, const uint8_t *cur, int stride, int w, int h, const gfx_rect *rects, int n,
		      uint32_t frame);

void rfx_message(buf *o, const uint8_t *cur, int stride, int w, int h, const gfx_rect *rects, int n,
		 uint32_t frame, int headers)
{
	/* sync, codec versions, channels, context: once, first (mstsc
	 * stops decoding when they come again) */
	if (headers)
		rfx_headers(o, w, h);
	rfx_frame(o, cur, stride, w, h, rects, n, frame);
}

static void rfx_headers(buf *o, int w, int h)
{
	w_u16(o, 0xccc0);
	w_u32(o, 12);
	w_u32(o, 0xcaccacca);
	w_u16(o, 0x0100);

	w_u16(o, 0xccc1);
	w_u32(o, 10);
	w_u8(o, 1);
	w_u8(o, 1);
	w_u16(o, 0x0100);

	w_u16(o, 0xccc2);
	w_u32(o, 12);
	w_u8(o, 1);
	w_u8(o, 0);
	w_u16(o, w);
	w_u16(o, h);

	w_u16(o, 0xccc3);
	w_u32(o, 13);
	w_u8(o, 1);
	w_u8(o, 0xff);
	w_u8(o, 0);
	w_u16(o, T);
	w_u16(o, CODEC_MODE | COL_CONV_ICT << 3 | CLW_XFORM_DWT_53_A << 5 | CLW_ENTROPY_RLGR1 << 9 |
			 SCALAR_QUANTIZATION << 13);
}

static void rfx_frame(buf *o, const uint8_t *cur, int stride, int w, int h, const gfx_rect *rects, int n,
		      uint32_t frame)
{
	w_u16(o, 0xccc4); /* frame begin */
	w_u32(o, 14);
	w_u8(o, 1);
	w_u8(o, 0);
	w_u32(o, frame);
	w_u16(o, 1);

	/* the tiles the rects touch; the region is those whole tiles */
	int tw = (w + T - 1) / T, th = (h + T - 1) / T, count;
	uint8_t *mark = touched(rects, n, tw, th, &count);

	w_u16(o, 0xccc6); /* region */
	w_u32(o, 15 + 8 * count);
	w_u8(o, 1);
	w_u8(o, 0);
	w_u8(o, 0x01);
	w_u16(o, count);
	tile_rects(o, mark, tw, th, w, h);
	w_u16(o, 0xcac1);
	w_u16(o, 1);

	size_t at = o->len;
	w_u16(o, 0xccc7); /* WBT_EXTENSION: a tileset */
	w_u32(o, 0);
	w_u8(o, 1);
	w_u8(o, 0);
	w_u16(o, 0xcac2);
	w_u16(o, 0);
	w_u16(o, 1 | CODEC_MODE << 1 | COL_CONV_ICT << 4 | CLW_XFORM_DWT_53_A << 6 | CLW_ENTROPY_RLGR1 << 10 |
			 SCALAR_QUANTIZATION << 14);
	w_u8(o, 1);
	w_u8(o, T);
	size_t count_at = o->len;
	w_u16(o, 0);
	w_u32(o, 0);
	for (int i = 0; i < 10; i += 2)
		w_u8(o, quant[i] | quant[i + 1] << 4);
	size_t tiles_at = o->len;
	encode_tiles(o, cur, stride, w, h, mark, tw, th, 0);
	free(mark);
	put_u16(o, count_at, count);
	put_u32(o, count_at + 2, o->len - tiles_at);
	put_u32(o, at + 2, o->len - at);

	w_u16(o, 0xccc5); /* frame end */
	w_u32(o, 8);
	w_u8(o, 1);
	w_u8(o, 0);
}
