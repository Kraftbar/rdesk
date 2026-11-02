/* gfxdec.c - graphics pipeline codecs, decoding, as FreeRDP's:
 *
 * RemoteFX Progressive (MS-RDPEGFX 2.2.4.2): 64x64 tiles of RemoteFX
 * (RLGR1, quantization, 5/3 wavelet, ICT colour), sent first at a coarse
 * quality and then upgraded, pass by pass, with more bits of each
 * coefficient: the tiles' coefficients are kept for that. The wavelet is
 * either RemoteFX's or the "reduce extrapolate" one (bands of 33/31,
 * 17/16, 9/8), which Windows uses.
 *
 * ClearCodec (MS-RDPEGFX 2.2.4.1): a residual layer (runs of colour),
 * bands of vertical bars (cached), and subcodec rects (raw, NSCodec,
 * RLEX), applied in that order; whole bitmaps can be cached as glyphs. */
#include "gfxdec.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline uint8_t clamp8(int v)
{
	return v < 0 ? 0 : v > 255 ? 255 : v;
}

static inline uint32_t bgr(const uint8_t *p)
{
	return p[2] << 16 | p[1] << 8 | p[0];
}

/* ---- reading -------------------------------------------------------- */

typedef struct {
	const uint8_t *p;
	size_t n, pos;
	int err;
} rd;

static const uint8_t *take(rd *r, size_t k)
{
	if (r->err || k > r->n - r->pos) {
		r->err = 1;
		return NULL;
	}
	r->pos += k;
	return r->p + r->pos - k;
}

static uint32_t u8(rd *r)
{
	const uint8_t *p = take(r, 1);
	return p ? p[0] : 0;
}

static uint32_t u16(rd *r)
{
	const uint8_t *p = take(r, 2);
	return p ? p[0] | p[1] << 8 : 0;
}

static uint32_t u32(rd *r)
{
	const uint8_t *p = take(r, 4);
	return p ? p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24 : 0;
}

static size_t left(const rd *r)
{
	return r->err ? 0 : r->n - r->pos;
}

/* bits, most significant first; zeros past the end. acc holds the next
 * cnt bits at its top. */
typedef struct {
	const uint8_t *p;
	size_t n, i;     /* bytes; the next one to load */
	size_t pos, end; /* bits taken; all there are */
	uint64_t acc;
	int cnt;
} bits;

static void bits_init(bits *b, const uint8_t *p, size_t n)
{
	*b = (bits){p, n, 0, 0, n * 8, 0, 0};
}

static inline void refill(bits *b)
{
	while (b->cnt <= 56) {
		uint64_t byte = b->i < b->n ? b->p[b->i] : 0;
		b->i++;
		b->acc |= byte << (56 - b->cnt);
		b->cnt += 8;
	}
}

static inline void skip(bits *b, int k)
{
	b->acc = k < 64 ? b->acc << k : 0;
	b->cnt -= k;
	b->pos += k;
}

static inline uint32_t get(bits *b, int k) /* k <= 32 */
{
	if (!k)
		return 0;
	if (b->cnt < k)
		refill(b);
	uint32_t v = b->acc >> (64 - k);
	skip(b, k);
	return v;
}

/* 1 bits up to a 0 (taken too) or the end: how many */
static inline uint32_t ones(bits *b)
{
	uint32_t n = 0;
	for (;;) {
		if (b->pos >= b->end)
			return n;
		if (b->cnt < 8)
			refill(b);
		uint64_t inv = ~b->acc;
		int lead = inv ? __builtin_clzll(inv) : 64;
		if (lead > b->cnt)
			lead = b->cnt;
		size_t rest = b->end - b->pos;
		if ((size_t)lead >= rest) {
			skip(b, rest);
			return n + rest;
		}
		skip(b, lead);
		n += lead;
		if (b->cnt) { /* a 0 ends them */
			skip(b, 1);
			return n;
		}
	}
}

/* ---- RLGR1 ----------------------------------------------------------- */

#define KPMAX 80
#define LSGR 3
#define UP_GR 4
#define DN_GR 6
#define UQ_GR 3
#define DQ_GR 3

static int clampk(int v)
{
	return v < 0 ? 0 : v > KPMAX ? KPMAX : v;
}

static uint32_t gr(bits *b, int *krp)
{
	int kr = *krp >> LSGR;
	uint32_t vk = ones(b);
	uint32_t mag = vk << kr | get(b, kr);
	if (!vk)
		*krp = clampk(*krp - 2);
	else if (vk > 1)
		*krp = clampk(*krp + vk);
	return mag;
}

static void rlgr1(const uint8_t *p, size_t n, int16_t *out, int count)
{
	bits b;
	bits_init(&b, p, n);
	int kp = 1 << LSGR, krp = 1 << LSGR, i = 0;
	while (i < count && b.pos < b.end) {
		int k = kp >> LSGR;
		if (k) {
			/* zeros: a 0 bit for each full run of 1 << k, then a 1
			 * and the rest in k bits; then a value */
			while (b.pos < b.end && !get(&b, 1)) {
				for (int z = 1 << k; z > 0 && i < count; z--)
					out[i++] = 0;
				kp = clampk(kp + UP_GR);
				k = kp >> LSGR;
			}
			for (int z = get(&b, k); z > 0 && i < count; z--)
				out[i++] = 0;
			int sign = get(&b, 1);
			int mag = gr(&b, &krp) + 1;
			if (i < count)
				out[i++] = sign ? -mag : mag;
			kp = clampk(kp - DN_GR);
		} else {
			/* 2 * magnitude - sign */
			uint32_t m = gr(&b, &krp);
			out[i++] = m & 1 ? -(int)((m + 1) >> 1) : (int)(m >> 1);
			kp = clampk(kp + (m ? -DQ_GR : UQ_GR));
		}
	}
	while (i < count)
		out[i++] = 0;
}

/* ---- Progressive ------------------------------------------------------ */

/* sub-bands: offset and size in the 4096 coefficients, plain and reduce
 * extrapolate, and the index of their quant value (LL3 LH3 HL3 HH3 LH2
 * HL2 HH2 LH1 HL1 HH1, as they come packed). LL3 last. */
static const struct {
	uint16_t off[2], len[2];
	uint8_t q;
} bands[10] = {
	{{0, 0}, {1024, 1023}, 8},        /* HL1 */
	{{1024, 1023}, {1024, 1023}, 7},  /* LH1 */
	{{2048, 2046}, {1024, 961}, 9},   /* HH1 */
	{{3072, 3007}, {256, 272}, 5},    /* HL2 */
	{{3328, 3279}, {256, 272}, 4},    /* LH2 */
	{{3584, 3551}, {256, 256}, 6},    /* HH2 */
	{{3840, 3807}, {64, 72}, 2},      /* HL3 */
	{{3904, 3879}, {64, 72}, 1},      /* LH3 */
	{{3968, 3951}, {64, 64}, 3},      /* HH3 */
	{{4032, 4015}, {64, 81}, 0},      /* LL3 */
};

typedef struct {
	int16_t cur[3][4096];  /* coefficients so far, dequantized */
	int16_t sign[3][4096]; /* their signs, as the first pass left them */
	uint8_t bitpos[3][10]; /* how many low bits are still to come */
} ptile;

struct prog {
	int w, h, tw, th;
	int extrapolate;
	ptile **tiles;
};

prog *prog_new(int w, int h)
{
	prog *p = calloc(1, sizeof *p);
	p->w = w;
	p->h = h;
	p->tw = (w + 63) / 64;
	p->th = (h + 63) / 64;
	p->tiles = calloc((size_t)p->tw * p->th, sizeof *p->tiles);
	return p;
}

void prog_free(prog *p)
{
	if (!p)
		return;
	for (int i = 0; i < p->tw * p->th; i++)
		free(p->tiles[i]);
	free(p->tiles);
	free(p);
}

/* RemoteFX's inverse wavelet, one level on the 2sw square at d (HL, LH,
 * HH, LL sub-bands of sw x sw): the inverse of the encoder in rfx.c. */
static void idwt_plain(int16_t *d, int16_t *tmp, int sw)
{
	int tw = 2 * sw;
	const int16_t *hl = d, *lh = d + sw * sw, *hh = d + 2 * sw * sw, *ll = d + 3 * sw * sw;
	/* horizontal: LL + HL into L rows, LH + HH into H rows */
	for (int y = 0; y < sw; y++) {
		int16_t *l = tmp + y * tw, *h = tmp + (sw + y) * tw;
		const int16_t *a = ll + y * sw, *ah = hl + y * sw, *b = lh + y * sw, *bh = hh + y * sw;
		for (int n = 0; n < sw; n++) {
			l[2 * n] = a[n] - (n ? (ah[n] + ah[n - 1]) >> 1 : ah[0]);
			h[2 * n] = b[n] - (n ? (bh[n] + bh[n - 1]) >> 1 : bh[0]);
		}
		for (int n = 0; n < sw; n++) {
			int e = n < sw - 1 ? 2 * n + 2 : 2 * n;
			l[2 * n + 1] = ah[n] * 2 + ((l[2 * n] + l[e]) >> 1);
			h[2 * n + 1] = bh[n] * 2 + ((h[2 * n] + h[e]) >> 1);
		}
	}
	/* vertical */
	for (int x = 0; x < tw; x++) {
		for (int n = 0; n < sw; n++) {
			int l = tmp[n * tw + x], h = tmp[(sw + n) * tw + x];
			d[2 * n * tw + x] = l - (n ? (h + tmp[(sw + n - 1) * tw + x]) >> 1 : h);
		}
		for (int n = 0; n < sw; n++) {
			int e = n < sw - 1 ? 2 * n + 2 : 2 * n;
			d[(2 * n + 1) * tw + x] = tmp[(sw + n) * tw + x] * 2 + ((d[2 * n * tw + x] + d[e * tw + x]) >> 1);
		}
	}
}

/* Reduce extrapolate, as FreeRDP's: lows and highs to nl + nh outputs
 * along each of count lines, values steps apart (ls, hs, xs) and lines
 * lstep etc. apart. */
static void idwt_line(const int16_t *L, int ls, const int16_t *H, int hs, int16_t *X, int xs,
		      int nl, int nh, int count, int lstep, int hstep, int xstep)
{
	for (int i = 0; i < count; i++, L += lstep, H += hstep, X += xstep) {
		const int16_t *pl = L, *ph = H;
		int16_t *px = X;
		int h0 = *ph, l0 = *pl, x0, x2;
		ph += hs;
		pl += ls;
		x0 = x2 = l0 - h0;
		for (int j = 0; j < nh - 1; j++) {
			int h1 = *ph;
			ph += hs;
			l0 = *pl;
			pl += ls;
			x2 = l0 - (h0 + h1) / 2;
			int x1 = (x0 + x2) / 2 + 2 * h0;
			px[0] = x0;
			px[xs] = x1;
			px += 2 * xs;
			x0 = x2;
			h0 = h1;
		}
		if (nl <= nh + 1) {
			if (nl <= nh) {
				px[0] = x2;
				px[xs] = x2 + 2 * h0;
			} else {
				l0 = *pl;
				x0 = l0 - h0;
				px[0] = x2;
				px[xs] = (x0 + x2) / 2 + 2 * h0;
				px[2 * xs] = x0;
			}
		} else {
			l0 = *pl;
			pl += ls;
			x0 = l0 - h0 / 2;
			px[0] = x2;
			px[xs] = (x0 + x2) / 2 + 2 * h0;
			px[2 * xs] = x0;
			px[3 * xs] = (x0 + *pl) / 2;
		}
	}
}

/* idwt_line down every column at once: lows L (nl rows) and highs H (nh
 * rows), all n wide, to nl + nh rows of X. The columns don't depend on
 * each other, so the inner loops run along rows and vectorize. */
static void idwt_cols(const int16_t *L, const int16_t *H, int16_t *X, int nl, int nh, int n)
{
	int16_t x0[64], h0[64];
	for (int c = 0; c < n; c++) {
		h0[c] = H[c];
		x0[c] = L[c] - H[c];
	}
	for (int j = 0; j < nh - 1; j++) {
		const int16_t *h1 = H + (j + 1) * n, *l = L + (j + 1) * n;
		int16_t *o = X + 2 * j * n;
		for (int c = 0; c < n; c++) {
			int16_t x2 = l[c] - (h0[c] + h1[c]) / 2;
			o[c] = x0[c];
			o[n + c] = (x0[c] + x2) / 2 + 2 * h0[c];
			x0[c] = x2;
			h0[c] = h1[c];
		}
	}
	int16_t *o = X + 2 * (nh - 1) * n;
	const int16_t *l = L + nh * n;
	for (int c = 0; c < n; c++) { /* x0 is the last x2 */
		if (nl <= nh) {
			o[c] = x0[c];
			o[n + c] = x0[c] + 2 * h0[c];
		} else if (nl == nh + 1) {
			int16_t x = l[c] - h0[c];
			o[c] = x0[c];
			o[n + c] = (x + x0[c]) / 2 + 2 * h0[c];
			o[2 * n + c] = x;
		} else {
			int16_t x = l[c] - h0[c] / 2;
			o[c] = x0[c];
			o[n + c] = (x + x0[c]) / 2 + 2 * h0[c];
			o[2 * n + c] = x;
			o[3 * n + c] = (x + l[n + c]) / 2;
		}
	}
}

static void idwt_extrapolate(int16_t *d, int16_t *tmp, int level)
{
	int nl = (64 >> level) + 1, nh = level == 1 ? 31 : (64 + (1 << (level - 1))) >> level;
	const int16_t *hl = d, *lh = hl + nh * nl, *hh = lh + nl * nh, *ll = hh + nh * nh;
	int w = nl + nh;
	int16_t *L = tmp, *H = tmp + nl * w;
	idwt_line(ll, 1, hl, 1, L, 1, nl, nh, nl, nl, nh, w); /* LL + HL -> L */
	idwt_line(lh, 1, hh, 1, H, 1, nl, nh, nh, nl, nh, w); /* LH + HH -> H */
	idwt_cols(L, H, d, nl, nh, w);                        /* L + H, down the columns */
}

static void idwt(int16_t *d, int extrapolate)
{
	int16_t tmp[4096];
	if (extrapolate) {
		idwt_extrapolate(d + 3807, tmp, 3);
		idwt_extrapolate(d + 3007, tmp, 2);
		idwt_extrapolate(d, tmp, 1);
	} else {
		idwt_plain(d + 3840, tmp, 8);
		idwt_plain(d + 3072, tmp, 16);
		idwt_plain(d, tmp, 32);
	}
}

/* Y, Cb, Cr of a tile (11.5 fixed point, Y less 4096) to BGRX. */
static void to_rgb(int16_t *c[3], uint32_t *rgb)
{
	for (int k = 0; k < 4096; k++) {
		int64_t Y = (int64_t)(c[0][k] + 4096) << 16;
		int cb = c[1][k], cr = c[2][k];
		rgb[k] = clamp8((int16_t)((Y + cr * 91916LL) >> 16) >> 5) << 16 |
			 clamp8((int16_t)((Y - cb * 22527LL - cr * 46819LL) >> 16) >> 5) << 8 |
			 clamp8((int16_t)((Y + cb * 115992LL) >> 16) >> 5);
	}
}

/* A decoded tile onto px where the region's rects cover it. */
static void put_tile(prog *p, uint32_t *px, const uint32_t *rgb, int tx, int ty, const uint16_t *rects, int nr,
		     void (*done)(void *, int, int, int, int), void *arg)
{
	int x0 = tx * 64, y0 = ty * 64;
	for (int i = 0; i < nr; i++) {
		const uint16_t *r = rects + 4 * i;
		int l = r[0] > x0 ? r[0] : x0, t = r[1] > y0 ? r[1] : y0;
		int rr = r[0] + r[2] < x0 + 64 ? r[0] + r[2] : x0 + 64, b = r[1] + r[3] < y0 + 64 ? r[1] + r[3] : y0 + 64;
		if (rr > p->w) rr = p->w;
		if (b > p->h) b = p->h;
		if (rr <= l || b <= t)
			continue;
		for (int y = t; y < b; y++)
			memcpy(px + (size_t)y * p->w + l, rgb + (y - y0) * 64 + (l - x0), (size_t)(rr - l) * 4);
		done(arg, l, t, rr - l, b - t);
	}
}

typedef struct {
	int nrects, nquant, nprog;
	const uint16_t *rects; /* x, y, w, h each */
	uint8_t quant[256][10];
	uint8_t progq[256][3][10];
} region;

static void unpack_quant(const uint8_t *p, uint8_t q[10])
{
	for (int i = 0; i < 5; i++) {
		q[2 * i] = p[i] & 15;
		q[2 * i + 1] = p[i] >> 4;
	}
}

/* An upgrade pass's state for one component's new bits. */
typedef struct {
	bits srl, raw;
	int kp, nz, mode;
} upgrade;

/* The next value of a coefficient that was zero so far: runs of zeros,
 * then a sign and unary magnitude. */
static int srl_read(upgrade *u, int nbits)
{
	if (u->nz) {
		u->nz--;
		return 0;
	}
	int k = u->kp / 8;
	if (!u->mode) {
		if (!get(&u->srl, 1)) {
			u->nz = (1 << k) - 1;
			u->kp = u->kp + 4 > 80 ? 80 : u->kp + 4;
			return 0;
		}
		u->mode = 1;
		u->nz = get(&u->srl, k);
		if (u->nz) {
			u->nz--;
			return 0;
		}
	}
	u->mode = 0;
	int sign = get(&u->srl, 1);
	u->kp = u->kp < 6 ? 0 : u->kp - 6;
	if (nbits == 1)
		return sign ? -1 : 1;
	int mag = 1, max = (1 << nbits) - 1;
	while (mag < max && !get(&u->srl, 1))
		mag++;
	return sign ? -mag : mag;
}

static void upgrade_band(upgrade *u, int16_t *cur, int16_t *sign, int n, int shift, int nbits, int ll)
{
	if (nbits <= 0)
		return;
	for (int i = 0; i < n; i++) {
		int v;
		if (ll || sign[i]) {
			/* LL3 adds its bits as they are; elsewhere they follow
			 * the coefficient's sign */
			v = get(&u->raw, nbits);
			if (!ll && sign[i] < 0)
				v = -v;
		} else {
			v = srl_read(u, nbits);
			sign[i] = v;
		}
		cur[i] += v * (1 << shift);
	}
}

/* A tile's next pass, onto its coefficients, and its pixels into rgb.
 * Touches only its own tile's state: tiles go to threads. */
static int prog_tile(prog *p, const region *rg, int type, rd *r, uint32_t *rgb, int *txp, int *typ)
{
	int qi[3] = {u8(r), u8(r), u8(r)};
	int tx = u16(r), ty = u16(r);
	int flags = 0, quality = 0xff;
	if (type != 0xccc7)
		flags = u8(r);
	if (type != 0xccc5)
		quality = u8(r);
	int nlen = type == 0xccc7 ? 6 : 4;
	uint32_t len[6];
	for (int i = 0; i < nlen; i++)
		len[i] = u16(r);
	const uint8_t *data[6];
	for (int i = 0; i < nlen; i++)
		data[i] = take(r, len[i]);
	if (r->err || tx >= p->tw || ty >= p->th || qi[0] >= rg->nquant || qi[1] >= rg->nquant ||
	    qi[2] >= rg->nquant || (quality != 0xff && quality >= rg->nprog))
		return -1;
	static const uint8_t full[3][10];
	const uint8_t(*pq)[10] = quality == 0xff ? full : (const uint8_t(*)[10])rg->progq[quality];
	ptile **slot = &p->tiles[ty * p->tw + tx];
	if (!*slot)
		*slot = calloc(1, sizeof **slot);
	ptile *t = *slot;
	int ex = p->extrapolate;
	int16_t out[3][4096], *c[3] = {out[0], out[1], out[2]};
	for (int k = 0; k < 3; k++) {
		const uint8_t *q = rg->quant[qi[k]];
		uint8_t pos[10];
		for (int i = 0; i < 10; i++)
			pos[i] = q[i] + pq[k][i];
		if (type != 0xccc7) {
			int16_t *d = out[k];
			rlgr1(data[k], len[k], d, 4096);
			memcpy(t->sign[k], d, sizeof t->sign[k]);
			int off = bands[9].off[ex];
			for (int i = 1; i < bands[9].len[ex]; i++) /* LL3 differences */
				d[off + i] += d[off + i - 1];
			for (int b = 0; b < 10; b++) {
				int shift = pos[bands[b].q] - 1;
				if (shift > 0)
					for (int i = 0; i < bands[b].len[ex]; i++)
						d[bands[b].off[ex] + i] *= 1 << shift;
			}
			if (flags & 1) /* difference from what the tile had */
				for (int i = 0; i < 4096; i++)
					d[i] += t->cur[k][i];
			memcpy(t->cur[k], d, sizeof t->cur[k]);
		} else {
			upgrade u = {.kp = 8};
			bits_init(&u.srl, data[2 * k], len[2 * k]);
			bits_init(&u.raw, data[2 * k + 1], len[2 * k + 1]);
			for (int b = 0; b < 10; b++) {
				int qn = bands[b].q, o = bands[b].off[ex];
				upgrade_band(&u, t->cur[k] + o, t->sign[k] + o, bands[b].len[ex], pos[qn] - 1,
					     t->bitpos[k][qn] - pos[qn], b == 9);
			}
			memcpy(out[k], t->cur[k], sizeof out[k]);
		}
		memcpy(t->bitpos[k], pos, 10);
		idwt(out[k], ex);
	}
	to_rgb(c, rgb);
	*txp = tx;
	*typ = ty;
	return 0;
}

typedef struct {
	int type;
	rd body;
	int tx, ty, bad;
} tjob;

typedef struct {
	prog *p;
	const region *rg;
	tjob *jobs;
	uint32_t (*rgb)[4096];
	int from, to;
} trun;

static void *run_tiles(void *arg)
{
	trun *t = arg;
	for (int i = t->from; i < t->to; i++) {
		tjob *j = &t->jobs[i];
		j->bad = prog_tile(t->p, t->rg, j->type, &j->body, t->rgb[i], &j->tx, &j->ty);
	}
	return NULL;
}

/* Decode the tiles: a whole-screen change is hundreds at a fifth of a
 * millisecond each, so they go to every core in contiguous runs (the
 * server's encoder does the same), unless a tile comes twice. */
static void decode_tiles(prog *p, const region *rg, tjob *jobs, int n, uint32_t (*rgb)[4096])
{
	enum { MAXRUNS = 8, MINRUN = 8 };
	static int cores;
	if (!cores) {
		cores = sysconf(_SC_NPROCESSORS_ONLN);
		cores = cores < 1 ? 1 : cores > MAXRUNS ? MAXRUNS : cores;
	}
	int runs = n / MINRUN < cores ? n / MINRUN : cores;
	if (runs > 1) {
		uint8_t *seen = calloc((size_t)p->tw * p->th, 1);
		for (int i = 0; i < n && runs > 1; i++) {
			const uint8_t *b = jobs[i].body.p;
			int tx = jobs[i].body.n >= 7 ? b[3] | b[4] << 8 : -1, ty = jobs[i].body.n >= 7 ? b[5] | b[6] << 8 : -1;
			if (tx < 0 || tx >= p->tw || ty >= p->th || seen[ty * p->tw + tx]++)
				runs = 1;
		}
		free(seen);
	}
	trun r[MAXRUNS];
	pthread_t th[MAXRUNS];
	int started[MAXRUNS] = {0};
	if (runs < 1)
		runs = 1;
	for (int k = 0; k < runs; k++)
		r[k] = (trun){p, rg, jobs, rgb, n * k / runs, n * (k + 1) / runs};
	/* this thread takes the first run, and any a thread couldn't */
	for (int k = 1; k < runs; k++)
		started[k] = !pthread_create(&th[k], NULL, run_tiles, &r[k]);
	for (int k = 0; k < runs; k++)
		if (!started[k])
			run_tiles(&r[k]);
	for (int k = 1; k < runs; k++)
		if (started[k])
			pthread_join(th[k], NULL);
}

static int prog_region(prog *p, rd *r, uint32_t *px, void (*done)(void *, int, int, int, int), void *arg)
{
	static region rg; /* big; one region at a time */
	if (u8(r) != 64)
		return -1;
	rg.nrects = u16(r);
	rg.nquant = u8(r);
	rg.nprog = u8(r);
	int flags = u8(r);
	int ntiles = u16(r);
	uint32_t tsize = u32(r);
	const uint8_t *rects = take(r, (size_t)rg.nrects * 8);
	const uint8_t *qv = take(r, (size_t)rg.nquant * 5);
	const uint8_t *pv = take(r, (size_t)rg.nprog * 16);
	const uint8_t *tiles = take(r, tsize);
	if (r->err)
		return -1;
	p->extrapolate = flags & 1;
	uint16_t *rc = malloc((size_t)rg.nrects * 8 + 1);
	for (int i = 0; i < rg.nrects * 4; i++)
		rc[i] = rects[2 * i] | rects[2 * i + 1] << 8;
	rg.rects = rc;
	for (int i = 0; i < rg.nquant; i++)
		unpack_quant(qv + 5 * i, rg.quant[i]);
	for (int i = 0; i < rg.nprog; i++)
		for (int k = 0; k < 3; k++)
			unpack_quant(pv + 16 * i + 1 + 5 * k, rg.progq[i][k]);
	rd t = {tiles, tsize, 0, 0};
	int bad = 0, n = 0;
	tjob *jobs = malloc((size_t)(ntiles + 1) * sizeof *jobs);
	for (int i = 0; i < ntiles && left(&t) >= 6; i++) {
		size_t start = t.pos;
		int type = u16(&t);
		uint32_t len = u32(&t);
		if (len < 6 || len > tsize - start) {
			bad = 1;
			break;
		}
		if (type >= 0xccc5 && type <= 0xccc7)
			jobs[n++] = (tjob){type, {tiles + start + 6, len - 6, 0, 0}, 0, 0, 0};
		t.pos = start + len;
	}
	uint32_t(*rgb)[4096] = malloc((size_t)(n + 1) * sizeof *rgb);
	decode_tiles(p, &rg, jobs, n, rgb);
	for (int i = 0; i < n; i++) {
		if (jobs[i].bad)
			bad = 1;
		else
			put_tile(p, px, rgb[i], jobs[i].tx, jobs[i].ty, rg.rects, rg.nrects, done, arg);
	}
	free(rgb);
	free(jobs);
	free(rc);
	return bad ? -1 : 0;
}

int prog_decode(prog *p, const uint8_t *data, size_t n, uint32_t *px,
		void (*done)(void *arg, int x, int y, int w, int h), void *arg)
{
	rd r = {data, n, 0, 0};
	while (left(&r) >= 6) {
		size_t start = r.pos;
		int type = u16(&r);
		uint32_t len = u32(&r);
		if (len < 6 || len > n - start)
			return -1;
		rd b = {data + start + 6, len - 6, 0, 0};
		if (type == 0xccc4 && prog_region(p, &b, px, done, arg))
			return -1;
		/* sync, context, frame begin and end: nothing to keep */
		r.pos = start + len;
	}
	return 0;
}

/* ---- NSCodec ----------------------------------------------------------- */

static void nsc_rle(const uint8_t *in, size_t n, uint8_t *out, size_t size)
{
	size_t i = 0, o = 0;
	while (size - o > 4 && i < n) {
		uint8_t v = in[i++];
		if (size - o == 5) {
			out[o++] = v;
		} else if (i < n && in[i] == v) {
			i++;
			size_t run;
			if (i < n && in[i] < 0xff) {
				run = in[i++] + 2;
			} else {
				i++;
				run = i + 4 <= n ? in[i] | in[i + 1] << 8 | in[i + 2] << 16 | (size_t)in[i + 3] << 24 : 0;
				i += 4;
			}
			if (run > size - o)
				run = size - o;
			memset(out + o, v, run);
			o += run;
		} else {
			out[o++] = v;
		}
	}
	/* the last 4 bytes as they are */
	for (int k = 0; k < 4 && o < size && i < n; k++)
		out[o++] = in[i++];
}

static int nscodec(const uint8_t *p, size_t n, int w, int h, uint32_t *out)
{
	rd r = {p, n, 0, 0};
	uint32_t plen[4];
	for (int i = 0; i < 4; i++)
		plen[i] = u32(&r);
	int cll = u8(&r), css = u8(&r);
	u16(&r);
	if (r.err || cll < 1 || cll > 7)
		return -1;
	int rw = (w + 7) & ~7, rh = (h + 1) & ~1;
	size_t org[4] = {(size_t)w * h, (size_t)w * h, (size_t)w * h, (size_t)w * h};
	if (css) {
		org[0] = (size_t)rw * h;
		org[1] = org[2] = (size_t)(rw / 2) * (rh / 2);
	}
	uint8_t *plane[4];
	int bad = 0;
	for (int i = 0; i < 4; i++) {
		plane[i] = malloc(org[i] + 8);
		const uint8_t *d = take(&r, plen[i]);
		if (!d)
			bad = 1;
		else if (!plen[i])
			memset(plane[i], 0xff, org[i]);
		else if (plen[i] < org[i])
			nsc_rle(d, plen[i], plane[i], org[i]);
		else
			memcpy(plane[i], d, org[i]);
	}
	int shift = cll - 1;
	for (int y = 0; y < h && !bad; y++) {
		const uint8_t *yp = plane[0] + (size_t)y * (css ? rw : w);
		const uint8_t *co = plane[1] + (css ? (size_t)(y / 2) * (rw / 2) : (size_t)y * w);
		const uint8_t *cg = plane[2] + (css ? (size_t)(y / 2) * (rw / 2) : (size_t)y * w);
		for (int x = 0; x < w; x++) {
			int yv = yp[x];
			int cov = (int8_t)(uint8_t)(*co << shift), cgv = (int8_t)(uint8_t)(*cg << shift);
			out[(size_t)y * w + x] = clamp8(yv + cov - cgv) << 16 | clamp8(yv + cgv) << 8 | clamp8(yv - cov - cgv);
			co += css ? x % 2 : 1;
			cg += css ? x % 2 : 1;
		}
	}
	for (int i = 0; i < 4; i++)
		free(plane[i]);
	return bad ? -1 : 0;
}

/* ---- ClearCodec -------------------------------------------------------- */

#define VBARS 32768
#define SHORT_VBARS 16384
#define BAR_MAX 52
#define GLYPHS 4000

typedef struct {
	int count;
	uint32_t px[BAR_MAX];
} vbar;

typedef struct {
	int w, h;
	uint32_t *px;
} glyph;

struct clear {
	vbar *vbars, *shorts;
	int vcur, scur;
	glyph glyphs[GLYPHS];
};

clear *clear_new(void)
{
	clear *c = calloc(1, sizeof *c);
	c->vbars = calloc(VBARS, sizeof *c->vbars);
	c->shorts = calloc(SHORT_VBARS, sizeof *c->shorts);
	return c;
}

void clear_free(clear *c)
{
	if (!c)
		return;
	for (int i = 0; i < GLYPHS; i++)
		free(c->glyphs[i].px);
	free(c->vbars);
	free(c->shorts);
	free(c);
}

static uint32_t run_length(rd *r)
{
	uint32_t n = u8(r);
	if (n == 0xff) {
		n = u16(r);
		if (n == 0xffff)
			n = u32(r);
	}
	return n;
}

static void residual(rd *r, uint32_t *px, size_t total)
{
	size_t i = 0;
	while (left(r) >= 4 && i < total) {
		const uint8_t *c = take(r, 3);
		uint32_t v = bgr(c), n = run_length(r);
		while (n-- && i < total)
			px[i++] = v;
	}
}

static int bands_layer(clear *c, rd *r, uint32_t *px, int w, int h)
{
	while (left(r) >= 11) {
		int xs = u16(r), xe = u16(r), ys = u16(r), ye = u16(r);
		uint32_t bkg = bgr(take(r, 3));
		int vh = ye - ys + 1;
		if (xe < xs || vh < 1 || vh > BAR_MAX)
			return -1;
		for (int x = xs; x <= xe; x++) {
			int hdr = u16(r);
			vbar *v;
			const vbar *sv = NULL;
			int yon = 0;
			if ((hdr & 0xc000) == 0x4000) { /* short bar cache hit */
				sv = &c->shorts[hdr & 0x3fff];
				yon = u8(r);
			} else if ((hdr & 0xc000) == 0) { /* short bar, new */
				yon = hdr & 0xff;
				int n = (hdr >> 8 & 0x3f) - yon;
				if (n < 0 || n > BAR_MAX)
					return -1;
				vbar *s = &c->shorts[c->scur];
				c->scur = (c->scur + 1) % SHORT_VBARS;
				s->count = n;
				for (int i = 0; i < n; i++) {
					const uint8_t *p = take(r, 3);
					s->px[i] = p ? bgr(p) : 0;
				}
				sv = s;
			}
			if (r->err)
				return -1;
			if (sv) { /* a whole bar: background, the short bar, background */
				v = &c->vbars[c->vcur];
				c->vcur = (c->vcur + 1) % VBARS;
				v->count = vh;
				for (int y = 0; y < vh; y++)
					v->px[y] = y >= yon && y - yon < sv->count ? sv->px[y - yon] : bkg;
			} else { /* bar cache hit */
				v = &c->vbars[hdr & 0x7fff];
			}
			if (v->count != vh)
				continue;
			for (int y = 0; y < vh; y++)
				if (x < w && ys + y < h)
					px[(size_t)(ys + y) * w + x] = v->px[y];
		}
	}
	return 0;
}

static int rlex(const uint8_t *p, size_t n, int w, int h, uint32_t *out)
{
	rd r = {p, n, 0, 0};
	int pc = u8(&r);
	if (pc < 1 || pc > 127)
		return -1;
	uint32_t pal[127];
	for (int i = 0; i < pc; i++) {
		const uint8_t *c = take(&r, 3);
		pal[i] = c ? bgr(c) : 0;
	}
	int nb = 1;
	while (nb < 8 && (1 << nb) < pc)
		nb++;
	size_t i = 0, total = (size_t)w * h;
	while (left(&r) && i < total) {
		int v = u8(&r);
		int stop = v & ((1 << nb) - 1), depth = v >> nb, start = stop - depth;
		uint32_t run = run_length(&r);
		if (r.err || start < 0 || stop >= pc)
			return -1;
		while (run-- && i < total)
			out[i++] = pal[start];
		for (int k = start; k <= stop && i < total; k++)
			out[i++] = pal[k];
	}
	return 0;
}

static int subcodecs(rd *r, uint32_t *px, int w, int h)
{
	while (left(r) >= 13) {
		int xs = u16(r), ys = u16(r), sw = u16(r), sh = u16(r);
		uint32_t len = u32(r);
		int id = u8(r);
		const uint8_t *d = take(r, len);
		if (!d || xs + sw > w || ys + sh > h)
			return -1;
		uint32_t *tmp = malloc((size_t)sw * sh * 4 + 4);
		int bad = 0;
		if (id == 0) {
			if ((size_t)sw * sh * 3 > len)
				bad = 1;
			else
				for (size_t i = 0; i < (size_t)sw * sh; i++)
					tmp[i] = bgr(d + 3 * i);
		} else if (id == 1) {
			bad = nscodec(d, len, sw, sh, tmp);
		} else if (id == 2) {
			bad = rlex(d, len, sw, sh, tmp);
		} else {
			bad = 1;
		}
		if (!bad)
			for (int y = 0; y < sh; y++)
				memcpy(px + (size_t)(ys + y) * w + xs, tmp + (size_t)y * sw, (size_t)sw * 4);
		free(tmp);
		if (bad)
			return -1;
	}
	return 0;
}

#define GLYPH_INDEX 0x01
#define GLYPH_HIT 0x02
#define CACHE_RESET 0x04

int clear_decode(clear *c, const uint8_t *data, size_t n, uint32_t *px, int w, int h)
{
	rd r = {data, n, 0, 0};
	int flags = u8(&r);
	u8(&r); /* sequence number */
	int gi = flags & GLYPH_INDEX ? (int)u16(&r) : -1;
	if (r.err || gi >= GLYPHS)
		return -1;
	if (flags & CACHE_RESET)
		c->vcur = c->scur = 0;
	if (flags & GLYPH_HIT) {
		glyph *g = gi >= 0 ? &c->glyphs[gi] : NULL;
		if (!g || !g->px || g->w * g->h < w * h)
			return -1;
		for (int y = 0; y < h; y++)
			memcpy(px + (size_t)y * w, g->px + (size_t)y * w, (size_t)w * 4);
		return 0;
	}
	if (left(&r)) {
		uint32_t rn = u32(&r), bn = u32(&r), sn = u32(&r);
		rd res = {take(&r, rn), rn, 0, 0}, bnd = {take(&r, bn), bn, 0, 0}, sub = {take(&r, sn), sn, 0, 0};
		if (r.err)
			return -1;
		residual(&res, px, (size_t)w * h);
		if (bands_layer(c, &bnd, px, w, h) || subcodecs(&sub, px, w, h))
			return -1;
	}
	if (gi >= 0 && w * h <= 1024 * 1024) {
		glyph *g = &c->glyphs[gi];
		g->w = w;
		g->h = h;
		g->px = realloc(g->px, (size_t)w * h * 4);
		memcpy(g->px, px, (size_t)w * h * 4);
	}
	return 0;
}
