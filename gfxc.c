/* gfxc.c - the graphics pipeline (MS-RDPEGFX) on a dynamic virtual
 * channel (MS-RDPEDYC), client side. The server's PDUs come compressed
 * with ZGFX (RDP8 bulk compression). Surfaces are kept here and copied to
 * the desktop where mapped; frames come as H.264 (AVC420, decoded with
 * libavcodec), RemoteFX Progressive, ClearCodec (gfxdec.c), planar or
 * raw pixels, plus fills, copies and a cache.
 *
 * Windows draws the desktop with ClearCodec and Progressive, H.264 only
 * where things move. AVC444, plain RemoteFX and alpha are not
 * implemented: those commands are skipped, noted once each. */
#include "gfxc.h"
#include "gfxdec.h"
#include "planar.h"
#include <libavcodec/avcodec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GFX_CHANNEL "Microsoft::Windows::RDS::Graphics"
#define DISP_CHANNEL "Microsoft::Windows::RDS::DisplayControl"

/* DVC commands (high nibble of the header byte) */
#define DVC_CREATE 0x1
#define DVC_DATA_FIRST 0x2
#define DVC_DATA 0x3
#define DVC_CLOSE 0x4
#define DVC_CAPS 0x5

/* RDPGFX PDUs */
#define WIRE_TO_SURFACE_1 0x0001
#define WIRE_TO_SURFACE_2 0x0002
#define DELETE_ENCODING_CONTEXT 0x0003
#define SOLID_FILL 0x0004
#define SURFACE_TO_SURFACE 0x0005
#define SURFACE_TO_CACHE 0x0006
#define CACHE_TO_SURFACE 0x0007
#define EVICT_CACHE_ENTRY 0x0008
#define CREATE_SURFACE 0x0009
#define DELETE_SURFACE 0x000a
#define START_FRAME 0x000b
#define END_FRAME 0x000c
#define FRAME_ACK 0x000d
#define RESET_GRAPHICS 0x000e
#define MAP_SURFACE_TO_OUTPUT 0x000f
#define CACHE_IMPORT_REPLY 0x0011
#define CAPS_ADVERTISE 0x0012
#define CAPS_CONFIRM 0x0013
#define MAP_SURFACE_TO_WINDOW 0x0015
#define QOE_FRAME_ACK 0x0016
#define MAP_SURFACE_TO_SCALED_OUTPUT 0x0017

#define CODEC_UNCOMPRESSED 0x0000
#define CODEC_CLEARCODEC 0x0008
#define CODEC_CAPROGRESSIVE 0x0009
#define CODEC_PLANAR 0x000a
#define CODEC_AVC420 0x000b

#define CAPVERSION_8 0x00080004
#define CAPVERSION_81 0x00080105
#define CAPS81_AVC420_ENABLED 0x10
#define CAPS10_AVC_DISABLED 0x20

#define MAX_SURFACES 256
#define CACHE_SLOTS 4096
#define HISTORY 2500000 /* ZGFX history buffer */

typedef struct {
	int w, h;
	uint32_t *px;
	int mapped, ox, oy;
	AVCodecContext *avc; /* each surface its own H.264 stream */
	AVFrame *frame;
} surface;

/* Progressive tiles, kept per surface whatever the codec context */
#define MAX_CONTEXTS 32
typedef struct {
	int used;
	uint16_t surface;
	prog *prog;
} context;

typedef struct {
	int w, h;
	uint32_t *px;
} cached;

struct gfxc {
	gfxc_ops ops;
	int open; /* the graphics channel is created */
	uint32_t chan;
	int disp_open, disp_ready; /* display control: created, caps came */
	uint32_t disp;
	int want_w, want_h; /* a size asked for before display control was ready */
	buf in; /* a DVC message arriving in pieces */
	size_t in_total;
	buf out; /* a message decompressed */
	uint8_t *hist;
	size_t hpos;
	surface *surf[MAX_SURFACES];
	cached cache[CACHE_SLOTS + 1];
	uint32_t frame_id, decoded;
	int noted[16]; /* codecs said to be skipped */
	AVPacket *pkt;
	clear *clear;
	context ctx[MAX_CONTEXTS];
	FILE *rec; /* RDESK_GFX_RECORD */
	uint32_t *tmp;
	size_t tmpn;
};

gfxc *gfxc_new(const gfxc_ops *ops)
{
	gfxc *g = calloc(1, sizeof *g);
	g->ops = *ops;
	b_init(&g->in, 65536);
	b_init(&g->out, 65536);
	g->hist = malloc(HISTORY);
	g->pkt = av_packet_alloc();
	g->clear = clear_new();
	const char *rec = getenv("RDESK_GFX_RECORD");
	if (rec && !(g->rec = fopen(rec, "wb")))
		perror(rec);
	return g;
}

static void surface_free(surface *s)
{
	if (!s)
		return;
	avcodec_free_context(&s->avc);
	av_frame_free(&s->frame);
	free(s->px);
	free(s);
}

void gfxc_free(gfxc *g)
{
	if (!g)
		return;
	for (int i = 0; i < MAX_SURFACES; i++)
		surface_free(g->surf[i]);
	for (int i = 0; i <= CACHE_SLOTS; i++)
		free(g->cache[i].px);
	av_packet_free(&g->pkt);
	clear_free(g->clear);
	if (g->rec)
		fclose(g->rec);
	for (int i = 0; i < MAX_CONTEXTS; i++)
		prog_free(g->ctx[i].prog);
	b_free(&g->in);
	b_free(&g->out);
	free(g->hist);
	free(g->tmp);
	free(g);
}

static uint32_t *scratch(gfxc *g, size_t n)
{
	if (n > g->tmpn) {
		g->tmpn = n;
		g->tmp = realloc(g->tmp, n * 4);
	}
	return g->tmp;
}

/* ---- sending ---------------------------------------------------------- */

/* A DVC header: cmd, then the channel id in as few bytes as it takes. */
static void dvc_header(buf *o, int cmd, uint32_t id)
{
	int cb = id <= 0xff ? 0 : id <= 0xffff ? 1 : 2;
	w_u8(o, cmd << 4 | cb);
	if (cb == 0)
		w_u8(o, id);
	else if (cb == 1)
		w_u16(o, id);
	else
		w_u32(o, id);
}

/* One RDPGFX PDU as a DVC data PDU on our channel (client PDUs are small
 * and go uncompressed). */
static int send_pdu(gfxc *g, uint16_t cmd, const buf *body)
{
	buf o;
	b_init(&o, body->len + 16);
	dvc_header(&o, DVC_DATA, g->chan);
	w_u16(&o, cmd);
	w_u16(&o, 0);
	w_u32(&o, body->len + 8);
	w_bytes(&o, body->p, body->len);
	int r = g->ops.send(g->ops.arg, o.p, o.len);
	b_free(&o);
	return r;
}

static int caps_advertise(gfxc *g)
{
	int avc = avcodec_find_decoder(AV_CODEC_ID_H264) != NULL;
	if (getenv("RDESK_OFF") && strstr(getenv("RDESK_OFF"), "avc"))
		avc = 0;
	/* 8.0, 8.1, and 10.0 to 10.7 (Windows takes H.264 only with 10.x);
	 * RDESK_GFX_MAX=0x00080105 etc. caps the versions offered */
	static const uint32_t vers[] = {CAPVERSION_8, CAPVERSION_81, 0x000a0002, 0x000a0100, 0x000a0200,
					0x000a0301, 0x000a0400, 0x000a0502, 0x000a0600, 0x000a0701};
	uint32_t max = getenv("RDESK_GFX_MAX") ? strtoul(getenv("RDESK_GFX_MAX"), NULL, 0) : 0xffffffff;
	buf b;
	b_init(&b, 256);
	w_u16(&b, 0);
	int n = 0;
	for (size_t i = 0; i < sizeof vers / sizeof *vers && vers[i] <= max; i++, n++) {
		if (vers[i] == 0x000a0100 && !avc) { /* 10.1 can't say "no H.264" */
			n--;
			continue;
		}
		w_u32(&b, vers[i]);
		if (vers[i] == 0x000a0100) { /* 10.1: 16 reserved bytes, no flags */
			w_u32(&b, 16);
			w_zero(&b, 16);
			continue;
		}
		w_u32(&b, 4);
		w_u32(&b, vers[i] == CAPVERSION_8 ? 0 : vers[i] == CAPVERSION_81 ? (avc ? CAPS81_AVC420_ENABLED : 0)
				      : avc ? 0 : CAPS10_AVC_DISABLED);
	}
	put_u16(&b, 0, n);
	int r = send_pdu(g, CAPS_ADVERTISE, &b);
	b_free(&b);
	dbg("gfx: %d capability sets advertised, H.264 %s", n, avc ? "on" : "off");
	return r;
}

static int frame_ack(gfxc *g, uint32_t id)
{
	buf b;
	b_init(&b, 16);
	w_u32(&b, 0); /* queue depth unavailable */
	w_u32(&b, id);
	w_u32(&b, ++g->decoded);
	int r = send_pdu(g, FRAME_ACK, &b);
	b_free(&b);
	return r;
}

/* ---- surfaces --------------------------------------------------------- */

static surface *get_surface(gfxc *g, uint32_t id)
{
	return id < MAX_SURFACES ? g->surf[id] : NULL;
}

/* Clip l,t,r,b (right and bottom exclusive) to s; 0 if nothing is left. */
static int clip(const surface *s, int *l, int *t, int *r, int *b)
{
	if (*l < 0) *l = 0;
	if (*t < 0) *t = 0;
	if (*r > s->w) *r = s->w;
	if (*b > s->h) *b = s->h;
	return *r > *l && *b > *t;
}

/* The part of s in l,t,r,b onto the desktop, if s is on it. */
static void show(gfxc *g, surface *s, int l, int t, int r, int b)
{
	if (s->mapped && clip(s, &l, &t, &r, &b))
		g->ops.paint(g->ops.arg, s->ox + l, s->oy + t, r - l, b - t,
			     s->px + (size_t)t * s->w + l, s->w);
}

/* w x h pixels, rows stride bytes apart, to x,y on s. */
static void put(gfxc *g, surface *s, int x, int y, const uint8_t *src, size_t stride, int w, int h)
{
	if (x < 0) {
		src += (size_t)-x * 4;
		w += x;
		x = 0;
	}
	if (y < 0) {
		src += (size_t)-y * stride;
		h += y;
		y = 0;
	}
	if (x + w > s->w)
		w = s->w - x;
	if (y + h > s->h)
		h = s->h - y;
	if (w <= 0 || h <= 0)
		return;
	for (int i = 0; i < h; i++)
		memcpy(s->px + (size_t)(y + i) * s->w + x, src + i * stride, (size_t)w * 4);
	show(g, s, x, y, x + w, y + h);
}

/* l,t,r,b of s, clipped, copied out into the scratch buffer. */
static uint32_t *copy_out(gfxc *g, surface *s, int *l, int *t, int *r, int *b)
{
	if (!clip(s, l, t, r, b))
		return NULL;
	int w = *r - *l, h = *b - *t;
	uint32_t *p = scratch(g, (size_t)w * h);
	for (int y = 0; y < h; y++)
		memcpy(p + (size_t)y * w, s->px + (size_t)(*t + y) * s->w + *l, (size_t)w * 4);
	return p;
}

/* ---- codecs ----------------------------------------------------------- */

static int avc_open(surface *s)
{
	const AVCodec *c = avcodec_find_decoder(AV_CODEC_ID_H264);
	if (!c)
		return -1;
	s->avc = avcodec_alloc_context3(c);
	s->avc->flags |= AV_CODEC_FLAG_LOW_DELAY;
	s->avc->thread_type = FF_THREAD_SLICE;
	s->avc->thread_count = 0;
	if (avcodec_open2(s->avc, c, NULL) < 0) {
		avcodec_free_context(&s->avc);
		return -1;
	}
	s->frame = av_frame_alloc();
	return 0;
}

static inline uint8_t clamp8(int v)
{
	return v < 0 ? 0 : v > 255 ? 255 : v;
}

/* The rects of a decoded picture onto s: I420 to BGRX, full range BT.709
 * as FreeRDP's (what servers encode for). The picture lies at the
 * surface's origin, the rects in surface coordinates. */
static void yuv_rects(gfxc *g, surface *s, const AVFrame *f, const uint8_t *rects, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++) {
		const uint8_t *q = rects + 8 * i;
		int l = q[0] | q[1] << 8, t = q[2] | q[3] << 8, r = q[4] | q[5] << 8, b = q[6] | q[7] << 8;
		if (r > f->width) r = f->width;
		if (b > f->height) b = f->height;
		if (!clip(s, &l, &t, &r, &b))
			continue;
		for (int y = t; y < b; y++) {
			const uint8_t *Y = f->data[0] + (size_t)y * f->linesize[0];
			const uint8_t *U = f->data[1] + (size_t)(y / 2) * f->linesize[1];
			const uint8_t *V = f->data[2] + (size_t)(y / 2) * f->linesize[2];
			uint32_t *d = s->px + (size_t)y * s->w;
			for (int x = l; x < r; x++) {
				int yy = Y[x] * 256, u = U[x / 2] - 128, v = V[x / 2] - 128;
				d[x] = clamp8((yy + 403 * v) >> 8) << 16 | clamp8((yy - 48 * u - 120 * v) >> 8) << 8 |
				       clamp8((yy + 475 * u) >> 8);
			}
		}
		show(g, s, l, t, r, b);
	}
}

/* RFX_AVC420_BITMAP_STREAM: the region rects (and a quality for each),
 * then H.264 in Annex B. */
static void avc420(gfxc *g, surface *s, const uint8_t *p, size_t n)
{
	buf b = {.p = (uint8_t *)p, .len = n};
	uint32_t nr = r_u32(&b);
	const uint8_t *rects = nr <= 65536 ? r_bytes(&b, (size_t)nr * 8) : NULL;
	r_skip(&b, (size_t)nr * 2);
	if (!rects || b.err) {
		dbg("gfx: bad AVC420 metablock");
		return;
	}
	if (!s->avc && avc_open(s)) {
		msg("gfx: cannot open an H.264 decoder");
		return;
	}
	size_t len = r_left(&b);
	if (av_new_packet(g->pkt, len) < 0) /* padded, as the decoder wants */
		return;
	memcpy(g->pkt->data, b.p + b.pos, len);
	int e = avcodec_send_packet(s->avc, g->pkt);
	av_packet_unref(g->pkt);
	if (e < 0) {
		dbg("gfx: H.264 packet refused (%d)", e);
		return;
	}
	while (avcodec_receive_frame(s->avc, s->frame) == 0) {
		AVFrame *f = s->frame;
		if (f->format != AV_PIX_FMT_YUV420P && f->format != AV_PIX_FMT_YUVJ420P) {
			dbg("gfx: H.264 picture format %d", f->format);
			continue;
		}
		dbg("gfx: H.264 picture %dx%d, %u rects, first %u,%u-%u,%u", f->width, f->height, nr,
		    rects[0] | rects[1] << 8, rects[2] | rects[3] << 8, rects[4] | rects[5] << 8, rects[6] | rects[7] << 8);
		yuv_rects(g, s, f, rects, nr);
	}
}

static void note_codec(gfxc *g, uint16_t codec)
{
	if (codec < 16 && g->noted[codec]++)
		return;
	msg("gfx: codec 0x%x not implemented, skipped", codec);
}

/* ClearCodec draws over what is there: w x h of s at l,t, then back. */
static void clearcodec(gfxc *g, surface *s, int l, int t, int w, int h, const uint8_t *p, size_t n)
{
	uint32_t *px = calloc((size_t)w * h, 4);
	for (int y = 0; y < h; y++)
		for (int x = 0; x < w; x++)
			if (l + x < s->w && t + y < s->h)
				px[(size_t)y * w + x] = s->px[(size_t)(t + y) * s->w + l + x];
	if (clear_decode(g->clear, p, n, px, w, h))
		dbg("gfx: bad ClearCodec bitmap %dx%d", w, h);
	else
		put(g, s, l, t, (const uint8_t *)px, (size_t)w * 4, w, h);
	free(px);
}

typedef struct {
	gfxc *g;
	surface *s;
} shown;

static void prog_done(void *arg, int x, int y, int w, int h)
{
	shown *a = arg;
	if (verbose > 1)
		dbg("gfx: progressive at %d,%d %dx%d", x, y, w, h);
	show(a->g, a->s, x, y, x + w, y + h);
}

/* A surface's Progressive slot; NULL when there is no room. */
static context *find_context(gfxc *g, uint16_t sid)
{
	context *free_slot = NULL;
	for (int i = 0; i < MAX_CONTEXTS; i++) {
		context *c = &g->ctx[i];
		if (c->used && c->surface == sid)
			return c;
		if (!c->used && !free_slot)
			free_slot = c;
	}
	if (free_slot)
		*free_slot = (context){1, sid, NULL};
	return free_slot;
}

/* the surface is gone, or new */
static void drop_contexts(gfxc *g, uint16_t sid)
{
	for (int i = 0; i < MAX_CONTEXTS; i++) {
		context *c = &g->ctx[i];
		if (c->used && c->surface == sid) {
			prog_free(c->prog);
			*c = (context){0};
		}
	}
}

/* WIRE_TO_SURFACE_2: RemoteFX Progressive, onto the whole surface. */
static void wire_to_surface_2(gfxc *g, buf *b)
{
	uint16_t sid = r_u16(b), codec = r_u16(b);
	r_u32(b); /* codec context */
	r_u8(b);
	uint32_t len = r_u32(b);
	const uint8_t *p = r_bytes(b, len);
	surface *s = get_surface(g, sid);
	if (!s || !p)
		return;
	if (codec != CODEC_CAPROGRESSIVE) {
		note_codec(g, codec);
		return;
	}
	context *c = find_context(g, sid);
	if (!c) {
		msg("gfx: Progressive on more than %d surfaces", MAX_CONTEXTS);
		return;
	}
	if (!c->prog)
		c->prog = prog_new(s->w, s->h);
	shown a = {g, s};
	if (prog_decode(c->prog, p, len, s->px, prog_done, &a))
		msg("gfx: bad Progressive message, %u bytes", len);
}

static void wire_to_surface_1(gfxc *g, buf *b)
{
	surface *s = get_surface(g, r_u16(b));
	uint16_t codec = r_u16(b);
	r_u8(b); /* pixel format: XRGB or ARGB, both 32 bits */
	int l = r_u16(b), t = r_u16(b), r = r_u16(b), bt = r_u16(b);
	uint32_t len = r_u32(b);
	const uint8_t *p = r_bytes(b, len);
	int w = r - l, h = bt - t;
	if (!s || !p || w <= 0 || h <= 0)
		return;
	dbg("gfx: codec 0x%x at %d,%d %dx%d, %u bytes", codec, l, t, w, h, len);
	switch (codec) {
	case CODEC_UNCOMPRESSED:
		if ((size_t)w * h * 4 <= len)
			put(g, s, l, t, p, (size_t)w * 4, w, h);
		break;
	case CODEC_PLANAR: {
		uint32_t *px = scratch(g, (size_t)w * h);
		if (planar_decode(p, len, w, h, 0, px, w))
			dbg("gfx: bad planar bitmap %dx%d", w, h);
		else
			put(g, s, l, t, (const uint8_t *)px, (size_t)w * 4, w, h);
		break;
	}
	case CODEC_AVC420:
		avc420(g, s, p, len);
		break;
	case CODEC_CLEARCODEC:
		clearcodec(g, s, l, t, w, h, p, len);
		break;
	default:
		note_codec(g, codec);
	}
}

/* ---- PDUs ------------------------------------------------------------- */

static int pdu(gfxc *g, uint16_t cmd, buf *b)
{
	switch (cmd) {
	case CAPS_CONFIRM: {
		uint32_t ver = r_u32(b), len = r_u32(b), flags = len >= 4 ? r_u32(b) : 0;
		msg("gfx: server confirmed caps 0x%08x flags 0x%x", ver, flags);
		break;
	}
	case RESET_GRAPHICS: {
		uint32_t w = r_u32(b), h = r_u32(b);
		dbg("gfx: reset graphics %ux%u", w, h);
		if (!b->err && w && h && w <= 8192 && h <= 8192)
			g->ops.reset(g->ops.arg, w, h);
		break;
	}
	case CREATE_SURFACE: {
		uint16_t id = r_u16(b), w = r_u16(b), h = r_u16(b);
		if (b->err || id >= MAX_SURFACES || !w || !h)
			break;
		surface_free(g->surf[id]);
		drop_contexts(g, id);
		surface *s = calloc(1, sizeof *s);
		s->w = w;
		s->h = h;
		s->px = calloc((size_t)w * h, 4);
		g->surf[id] = s;
		dbg("gfx: surface %u, %ux%u", id, w, h);
		break;
	}
	case DELETE_SURFACE: {
		uint16_t id = r_u16(b);
		if (id < MAX_SURFACES) {
			surface_free(g->surf[id]);
			g->surf[id] = NULL;
			drop_contexts(g, id);
		}
		break;
	}
	case MAP_SURFACE_TO_OUTPUT:
	case MAP_SURFACE_TO_SCALED_OUTPUT: {
		surface *s = get_surface(g, r_u16(b));
		r_u16(b);
		uint32_t x = r_u32(b), y = r_u32(b);
		if (s && !b->err) {
			s->mapped = 1;
			s->ox = x;
			s->oy = y;
			show(g, s, 0, 0, s->w, s->h);
		}
		break;
	}
	case START_FRAME:
		r_u32(b);
		g->frame_id = r_u32(b);
		break;
	case END_FRAME:
		return frame_ack(g, r_u32(b));
	case WIRE_TO_SURFACE_1:
		wire_to_surface_1(g, b);
		break;
	case WIRE_TO_SURFACE_2:
		wire_to_surface_2(g, b);
		break;
	case SOLID_FILL: {
		surface *s = get_surface(g, r_u16(b));
		uint8_t bl = r_u8(b), gr = r_u8(b), rd = r_u8(b);
		r_u8(b);
		uint32_t px = rd << 16 | gr << 8 | bl;
		uint16_t n = r_u16(b);
		for (int i = 0; i < n && !b->err; i++) {
			int l = r_u16(b), t = r_u16(b), r = r_u16(b), bt = r_u16(b);
			if (!s || b->err || !clip(s, &l, &t, &r, &bt))
				continue;
			dbg("gfx: fill at %d,%d %dx%d with %06x", l, t, r - l, bt - t, px);
			for (int y = t; y < bt; y++)
				for (int x = l; x < r; x++)
					s->px[(size_t)y * s->w + x] = px;
			show(g, s, l, t, r, bt);
		}
		break;
	}
	case SURFACE_TO_SURFACE: {
		surface *src = get_surface(g, r_u16(b)), *dst = get_surface(g, r_u16(b));
		int l = r_u16(b), t = r_u16(b), r = r_u16(b), bt = r_u16(b);
		uint16_t n = r_u16(b);
		uint32_t *p = src && dst && !b->err ? copy_out(g, src, &l, &t, &r, &bt) : NULL;
		for (int i = 0; i < n && p; i++) {
			int x = r_u16(b), y = r_u16(b);
			dbg("gfx: copy at %d,%d %dx%d from %d,%d", x, y, r - l, bt - t, l, t);
			if (!b->err)
				put(g, dst, x, y, (const uint8_t *)p, (size_t)(r - l) * 4, r - l, bt - t);
		}
		break;
	}
	case SURFACE_TO_CACHE: {
		surface *s = get_surface(g, r_u16(b));
		r_u32(b); /* cache key, 64 bits */
		r_u32(b);
		uint16_t slot = r_u16(b);
		int l = r_u16(b), t = r_u16(b), r = r_u16(b), bt = r_u16(b);
		uint32_t *p = s && !b->err && slot <= CACHE_SLOTS ? copy_out(g, s, &l, &t, &r, &bt) : NULL;
		if (!p)
			break;
		cached *c = &g->cache[slot];
		c->w = r - l;
		c->h = bt - t;
		c->px = realloc(c->px, (size_t)c->w * c->h * 4);
		memcpy(c->px, p, (size_t)c->w * c->h * 4);
		break;
	}
	case CACHE_TO_SURFACE: {
		uint16_t slot = r_u16(b);
		surface *s = get_surface(g, r_u16(b));
		uint16_t n = r_u16(b);
		cached *c = slot <= CACHE_SLOTS ? &g->cache[slot] : NULL;
		if (!s || !c || !c->px) {
			dbg("gfx: cache slot %u empty", slot);
			break;
		}
		for (int i = 0; i < n && !b->err; i++) {
			int x = r_u16(b), y = r_u16(b);
			dbg("gfx: cached at %d,%d %dx%d from slot %u", x, y, c->w, c->h, slot);
			if (!b->err)
				put(g, s, x, y, (const uint8_t *)c->px, (size_t)c->w * 4, c->w, c->h);
		}
		break;
	}
	case EVICT_CACHE_ENTRY: {
		uint16_t slot = r_u16(b);
		if (slot <= CACHE_SLOTS) {
			free(g->cache[slot].px);
			g->cache[slot].px = NULL;
		}
		break;
	}
	case DELETE_ENCODING_CONTEXT:
		/* Windows deletes a context after each image, then upgrades
		 * its tiles in the next one: the tiles stay (as FreeRDP's) */
		break;
	case CACHE_IMPORT_REPLY:
	case MAP_SURFACE_TO_WINDOW:
		break;
	default:
		dbg("gfx: pdu 0x%04x ignored", cmd);
	}
	return 0;
}

static int pdus(gfxc *g, buf *b)
{
	while (r_left(b) >= 8) {
		size_t start = b->pos;
		uint16_t cmd = r_u16(b);
		r_u16(b);
		uint32_t len = r_u32(b);
		if (len < 8 || start + len > b->len) {
			msg("gfx: bad PDU 0x%04x, %u bytes", cmd, len);
			return 0;
		}
		buf p = {.p = b->p + start + 8, .len = len - 8};
		if (pdu(g, cmd, &p))
			return -1;
		b->pos = start + len;
	}
	return 0;
}

/* ---- ZGFX ------------------------------------------------------------- */

/* Prefix codes, MSB first: literals (value base + vbits more bits) and
 * matches (distance base + vbits more bits). MS-RDPEGFX 2.2.5.2.1. */
static const struct {
	uint8_t len;
	uint16_t code;
	uint8_t vbits, match;
	uint32_t base;
} tokens[] = {
	{1, 0, 8, 0, 0},           {5, 17, 5, 1, 0},          {5, 18, 7, 1, 32},
	{5, 19, 9, 1, 160},        {5, 20, 10, 1, 672},       {5, 21, 12, 1, 1696},
	{5, 24, 0, 0, 0x00},       {5, 25, 0, 0, 0x01},       {6, 44, 14, 1, 5792},
	{6, 45, 15, 1, 22176},     {6, 52, 0, 0, 0x02},       {6, 53, 0, 0, 0x03},
	{6, 54, 0, 0, 0xff},       {7, 92, 18, 1, 54944},     {7, 93, 20, 1, 317088},
	{7, 110, 0, 0, 0x04},      {7, 111, 0, 0, 0x05},      {7, 112, 0, 0, 0x06},
	{7, 113, 0, 0, 0x07},      {7, 114, 0, 0, 0x08},      {7, 115, 0, 0, 0x09},
	{7, 116, 0, 0, 0x0a},      {7, 117, 0, 0, 0x0b},      {7, 118, 0, 0, 0x3a},
	{7, 119, 0, 0, 0x3b},      {7, 120, 0, 0, 0x3c},      {7, 121, 0, 0, 0x3d},
	{7, 122, 0, 0, 0x3e},      {7, 123, 0, 0, 0x3f},      {7, 124, 0, 0, 0x40},
	{7, 125, 0, 0, 0x80},      {8, 188, 20, 1, 1365664},  {8, 189, 21, 1, 2414240},
	{8, 252, 0, 0, 0x0c},      {8, 253, 0, 0, 0x38},      {8, 254, 0, 0, 0x39},
	{8, 255, 0, 0, 0x66},      {9, 380, 22, 1, 4511392},  {9, 381, 23, 1, 8705696},
	{9, 382, 24, 1, 17094304}, {0, 0, 0, 0, 0},
};

typedef struct {
	const uint8_t *p;
	size_t pos, end; /* in bits */
	int err;
} bits;

static uint32_t get(bits *b, int k)
{
	uint32_t v = 0;
	if (b->pos + k > b->end) {
		b->err = 1;
		return 0;
	}
	for (int i = 0; i < k; i++, b->pos++)
		v = v << 1 | (b->p[b->pos >> 3] >> (7 - (b->pos & 7)) & 1);
	return v;
}

static void hist_put(gfxc *g, const uint8_t *p, size_t n)
{
	while (n) {
		size_t k = HISTORY - g->hpos < n ? HISTORY - g->hpos : n;
		memcpy(g->hist + g->hpos, p, k);
		g->hpos = (g->hpos + k) % HISTORY;
		p += k;
		n -= k;
	}
}

/* One RDP8 bulk segment (header byte first) onto g->out. */
static int zgfx_segment(gfxc *g, const uint8_t *p, size_t n)
{
	if (!n || (p[0] & 0x0f) != 0x04)
		return -1;
	int compressed = p[0] & 0x20;
	p++;
	n--;
	if (!compressed) {
		w_bytes(&g->out, p, n);
		hist_put(g, p, n);
		return 0;
	}
	/* the last byte: how many bits of the one before are padding */
	if (!n || p[n - 1] > (n - 1) * 8)
		return -1;
	bits b = {p, 0, (n - 1) * 8 - p[n - 1], 0};
	while (b.pos < b.end && !b.err) {
		uint32_t code = 0;
		int have = 0, i;
		for (i = 0; tokens[i].len; i++) {
			while (have < tokens[i].len) {
				code = code << 1 | get(&b, 1);
				have++;
			}
			if (code == tokens[i].code)
				break;
		}
		if (!tokens[i].len || b.err)
			return -1;
		if (!tokens[i].match) {
			uint8_t c = tokens[i].base + get(&b, tokens[i].vbits);
			w_u8(&g->out, c);
			hist_put(g, &c, 1);
			continue;
		}
		uint32_t dist = tokens[i].base + get(&b, tokens[i].vbits);
		if (dist) {
			uint32_t count = 3;
			if (get(&b, 1)) {
				int extra = 2;
				count = 4;
				while (get(&b, 1) && !b.err) {
					count *= 2;
					extra++;
				}
				count += get(&b, extra);
			}
			if (dist > HISTORY || b.err)
				return -1;
			b_reserve(&g->out, count);
			size_t from = (g->hpos + HISTORY - dist) % HISTORY;
			for (uint32_t k = 0; k < count; k++) {
				uint8_t c = g->hist[from];
				from = from + 1 == HISTORY ? 0 : from + 1;
				g->out.p[g->out.len++] = c;
				g->hist[g->hpos] = c;
				g->hpos = g->hpos + 1 == HISTORY ? 0 : g->hpos + 1;
			}
		} else {
			/* bytes as they are, from the next whole byte */
			uint32_t count = get(&b, 15);
			b.pos = (b.pos + 7) & ~(size_t)7;
			if (b.err || b.pos / 8 + count > n - 1)
				return -1;
			w_bytes(&g->out, p + b.pos / 8, count);
			hist_put(g, p + b.pos / 8, count);
			b.pos += (size_t)count * 8;
		}
	}
	return b.err ? -1 : 0;
}

/* RDP_SEGMENTED_DATA: one segment or several, decompressed in order. */
static int segmented(gfxc *g, const uint8_t *p, size_t n)
{
	b_reset(&g->out);
	buf b = {.p = (uint8_t *)p, .len = n};
	uint8_t d = r_u8(&b);
	int bad = 0;
	if (d == 0xe0) {
		bad = zgfx_segment(g, p + 1, n - 1);
	} else if (d == 0xe1) {
		uint16_t count = r_u16(&b);
		uint32_t size = r_u32(&b);
		for (int i = 0; i < count && !bad; i++) {
			uint32_t len = r_u32(&b);
			const uint8_t *s = r_bytes(&b, len);
			bad = !s || zgfx_segment(g, s, len);
		}
		if (!bad && g->out.len != size)
			dbg("gfx: %zu bytes decompressed, header says %u", g->out.len, size);
	} else {
		bad = 1;
	}
	if (bad) {
		msg("gfx: cannot decompress a message (descriptor 0x%02x)", d);
		return -1;
	}
	if (g->rec) {
		uint32_t len = g->out.len;
		fwrite(&len, 4, 1, g->rec);
		fwrite(g->out.p, 1, len, g->rec);
		fflush(g->rec);
	}
	g->out.pos = 0;
	return pdus(g, &g->out);
}

int gfxc_replay(gfxc *g, const uint8_t *p, size_t n)
{
	buf b = {.p = (uint8_t *)p, .len = n};
	return pdus(g, &b);
}

/* ---- display control (MS-RDPEDISP) ------------------------------------- */

/* The desktop as w x h: one monitor, primary, 100% scale. */
static int send_layout(gfxc *g, int w, int h)
{
	buf o;
	b_init(&o, 64);
	dvc_header(&o, DVC_DATA, g->disp);
	w_u32(&o, 2); /* MONITOR_LAYOUT */
	w_u32(&o, 8 + 8 + 40);
	w_u32(&o, 40);
	w_u32(&o, 1);
	w_u32(&o, 1); /* primary */
	w_u32(&o, 0);
	w_u32(&o, 0);
	w_u32(&o, w);
	w_u32(&o, h);
	w_u32(&o, 0); /* physical size unknown */
	w_u32(&o, 0);
	w_u32(&o, 0); /* landscape */
	w_u32(&o, 100);
	w_u32(&o, 100);
	int r = g->ops.send(g->ops.arg, o.p, o.len);
	b_free(&o);
	msg("gfx: asking for a %dx%d desktop", w, h);
	return r;
}

static int disp_recv(gfxc *g, buf *b)
{
	uint32_t type = r_u32(b);
	r_u32(b);
	if (type != 5) /* CAPS */
		return 0;
	uint32_t mons = r_u32(b), fa = r_u32(b), fb = r_u32(b);
	dbg("disp: up to %u monitors, area %ux%u", mons, fa, fb);
	g->disp_ready = 1;
	if (g->want_w) {
		int w = g->want_w, h = g->want_h;
		g->want_w = 0;
		return send_layout(g, w, h);
	}
	return 0;
}

int gfxc_resize(gfxc *g, int w, int h)
{
	/* even widths, 200 to 8192 each way */
	w &= ~1;
	w = w < 200 ? 200 : w > 8192 ? 8192 : w;
	h = h < 200 ? 200 : h > 8192 ? 8192 : h;
	if (!g->disp_ready) {
		g->want_w = w;
		g->want_h = h;
		return 0;
	}
	return send_layout(g, w, h);
}

/* ---- dynamic channels ------------------------------------------------- */

static uint32_t r_var(buf *b, int code)
{
	return code == 0 ? r_u8(b) : code == 1 ? r_u16(b) : r_u32(b);
}

int gfxc_recv(gfxc *g, buf *b)
{
	uint8_t h = r_u8(b);
	int cmd = h >> 4, sp = h >> 2 & 3, cb = h & 3;
	if (b->err)
		return 0;
	if (verbose > 1)
		dbg("dvc: cmd %d, %zu bytes", cmd, b->len);
	switch (cmd) {
	case DVC_CAPS: {
		r_u8(b);
		uint16_t ver = r_u16(b);
		dbg("dvc: server caps version %u", ver);
		/* version 2 at most: no compressed DVC data */
		uint8_t rsp[4] = {DVC_CAPS << 4, 0, ver < 2 ? ver : 2, 0};
		return g->ops.send(g->ops.arg, rsp, sizeof rsp);
	}
	case DVC_CREATE: {
		uint32_t id = r_var(b, cb);
		size_t nl = strnlen((const char *)b->p + b->pos, r_left(b));
		char name[128];
		snprintf(name, sizeof name, "%.*s", (int)nl, b->p + b->pos);
		int gfx = !g->open && !strcmp(name, GFX_CHANNEL);
		int disp = !g->disp_open && !strcmp(name, DISP_CHANNEL);
		buf o;
		b_init(&o, 16);
		dvc_header(&o, DVC_CREATE, id);
		w_u32(&o, gfx || disp ? 0 : 0xc0000001);
		dbg("dvc: channel %u '%s' %s", id, name, gfx || disp ? "opened" : "refused");
		int e = g->ops.send(g->ops.arg, o.p, o.len);
		b_free(&o);
		if (e)
			return -1;
		if (disp) {
			g->disp_open = 1;
			g->disp = id;
		}
		if (!gfx)
			return 0;
		g->open = 1;
		g->chan = id;
		return caps_advertise(g);
	}
	case DVC_DATA_FIRST: {
		uint32_t id = r_var(b, cb), total = r_var(b, sp);
		if (!g->open || id != g->chan)
			return 0;
		g->in_total = total;
		b_reset(&g->in);
		w_bytes(&g->in, b->p + b->pos, r_left(b));
		break;
	}
	case DVC_DATA: {
		uint32_t id = r_var(b, cb);
		if (g->disp_open && id == g->disp)
			return disp_recv(g, b);
		if (!g->open || id != g->chan)
			return 0;
		if (!g->in_total) /* whole */
			return segmented(g, b->p + b->pos, r_left(b));
		w_bytes(&g->in, b->p + b->pos, r_left(b));
		break;
	}
	case DVC_CLOSE: {
		uint32_t id = r_var(b, cb);
		if (g->open && id == g->chan) {
			msg("gfx: server closed the channel");
			g->open = 0;
		}
		if (g->disp_open && id == g->disp)
			g->disp_open = g->disp_ready = 0;
		buf o;
		b_init(&o, 8);
		dvc_header(&o, DVC_CLOSE, id);
		int e = g->ops.send(g->ops.arg, o.p, o.len);
		b_free(&o);
		return e;
	}
	default:
		dbg("dvc: cmd %d ignored", cmd);
		return 0;
	}
	if (g->in_total && g->in.len >= g->in_total) {
		g->in_total = 0;
		return segmented(g, g->in.p, g->in.len);
	}
	return 0;
}
