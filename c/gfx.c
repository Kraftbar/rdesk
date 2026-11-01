/* gfx.c - the graphics pipeline (MS-RDPEGFX) on a dynamic virtual channel
 * (MS-RDPEDYC), frames as H.264 (AVC420) from x264, or RemoteFX for
 * clients with H.264 off (the iOS app). Server side.
 *
 * One surface the size of the desktop, mapped at 0,0. An H.264 frame is
 * the whole desktop encoded; its region rects say which parts the client
 * copies out of the decoded picture, so what didn't change stays as it
 * was. RemoteFX sends just the tiles the rects touch. The client
 * acknowledges frames, and no more than MAX_IN_FLIGHT go unacknowledged:
 * frames then come as fast as it decodes them. */
#include "gfx.h"
#include "rfx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x264.h>

#define GFX_CHANNEL "Microsoft::Windows::RDS::Graphics"
#define GFX_CHAN_ID 1
#define DVC_CHUNK 1600
#define MAX_IN_FLIGHT 2

/* DVC commands (high nibble of the header byte) */
#define DVC_CREATE 0x1
#define DVC_DATA_FIRST 0x2
#define DVC_DATA 0x3
#define DVC_CLOSE 0x4
#define DVC_CAPS 0x5

/* RDPGFX PDUs */
#define WIRE_TO_SURFACE_1 0x0001
#define WIRE_TO_SURFACE_2 0x0002
#define CREATE_SURFACE 0x0009
#define START_FRAME 0x000b
#define END_FRAME 0x000c
#define FRAME_ACK 0x000d
#define RESET_GRAPHICS 0x000e
#define MAP_SURFACE_TO_OUTPUT 0x000f
#define CACHE_IMPORT_OFFER 0x0010
#define CACHE_IMPORT_REPLY 0x0011
#define CAPS_ADVERTISE 0x0012
#define CAPS_CONFIRM 0x0013
#define QOE_FRAME_ACK 0x0016

#define CODEC_CAVIDEO 0x0003 /* RemoteFX */
#define CODEC_CAPROGRESSIVE 0x0009
#define CODEC_AVC420 0x000b
#define XRGB_8888 0x20
#define SUSPEND_ACK 0xffffffff

#define CAPVERSION_81 0x00080105
#define CAPS81_AVC420_ENABLED 0x10
#define CAPVERSION_10 0x000a0002
#define CAPS10_AVC_DISABLED 0x20
#define CAPVERSION_107 0x000a0701 /* the newest we know */

struct gfx {
	gfx_send_fn send;
	void *arg;
	int w, h;
	int state;
	int open; /* the channel is created */
	buf in;   /* a DVC message arriving in pieces */
	size_t in_total;
	buf msg; /* RDPGFX PDUs going out as one message */
	uint32_t frame_id, acked;
	int no_ack; /* the client suspended acknowledgements, or sends none */
	int64_t sent_ms;
	int avc;    /* the client takes H.264 */
	int codec;  /* CODEC_*: what frames go as */
	x264_t *enc;
	x264_picture_t pic;
	int64_t pts;
};

gfx *gfx_new(gfx_send_fn send, void *arg, int w, int h)
{
	gfx *g = calloc(1, sizeof *g);
	g->send = send;
	g->arg = arg;
	g->w = w;
	g->h = h;
	b_init(&g->in, 4096);
	b_init(&g->msg, 65536);
	return g;
}

void gfx_free(gfx *g)
{
	if (!g)
		return;
	if (g->enc) {
		x264_encoder_close(g->enc);
		x264_picture_clean(&g->pic);
	}
	b_free(&g->in);
	b_free(&g->msg);
	free(g);
}

int gfx_state(const gfx *g)
{
	return g->state;
}

static int64_t mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

int gfx_can_send(gfx *g)
{
	if (g->state != GFX_READY)
		return 0;
	if (g->no_ack || g->frame_id - g->acked <= MAX_IN_FLIGHT)
		return 1;
	/* mstsc acknowledges no RemoteFX frame after the first: after a
	 * second without, go by the socket's queue as with bitmaps */
	if (mono_ms() - g->sent_ms > 1000) {
		msg("gfx: no frame acknowledgements, pacing by the link");
		g->no_ack = 1;
		return 1;
	}
	return 0;
}

/* ---- dynamic channel ------------------------------------------------- */

int gfx_start(gfx *g)
{
	/* capabilities, version 2: no compressed data asked of anyone */
	uint8_t caps[12] = {DVC_CAPS << 4, 0, 2, 0};
	return g->send(g->arg, caps, sizeof caps);
}

static int dvc_create(gfx *g)
{
	uint8_t p[64] = {DVC_CREATE << 4, GFX_CHAN_ID};
	memcpy(p + 2, GFX_CHANNEL, sizeof GFX_CHANNEL);
	return g->send(g->arg, p, 2 + sizeof GFX_CHANNEL);
}

/* One DVC message on our channel, in as many PDUs as it takes. */
static int dvc_write(gfx *g, const uint8_t *p, size_t n)
{
	uint8_t pdu[DVC_CHUNK];
	size_t off = 0;
	if (n > DVC_CHUNK - 2) {
		pdu[0] = DVC_DATA_FIRST << 4 | 2 << 2; /* 32-bit length */
		pdu[1] = GFX_CHAN_ID;
		pdu[2] = n;
		pdu[3] = n >> 8;
		pdu[4] = n >> 16;
		pdu[5] = n >> 24;
		off = DVC_CHUNK - 6;
		memcpy(pdu + 6, p, off);
		if (g->send(g->arg, pdu, DVC_CHUNK))
			return -1;
	}
	while (off < n) {
		size_t k = n - off > DVC_CHUNK - 2 ? DVC_CHUNK - 2 : n - off;
		pdu[0] = DVC_DATA << 4;
		pdu[1] = GFX_CHAN_ID;
		memcpy(pdu + 2, p + off, k);
		if (g->send(g->arg, pdu, k + 2))
			return -1;
		off += k;
	}
	return 0;
}

/* g->msg as RDP_SEGMENTED_DATA, uncompressed, on the channel. */
static int gfx_flush(gfx *g)
{
	buf s;
	size_t n = g->msg.len;
	b_init(&s, n + 16 + n / 65535 * 5);
	if (n <= 65535) {
		w_u8(&s, 0xe0); /* single */
		w_u8(&s, 0x04); /* RDP8, not compressed */
		w_bytes(&s, g->msg.p, n);
	} else {
		w_u8(&s, 0xe1); /* multipart */
		w_u16(&s, (n + 65534) / 65535);
		w_u32(&s, n);
		for (size_t off = 0; off < n; off += 65535) {
			size_t k = n - off > 65535 ? 65535 : n - off;
			w_u32(&s, k + 1);
			w_u8(&s, 0x04);
			w_bytes(&s, g->msg.p + off, k);
		}
	}
	int r = dvc_write(g, s.p, s.len);
	b_free(&s);
	b_reset(&g->msg);
	return r;
}

/* Start an RDPGFX PDU in g->msg; gfx_end patches its length. */
static size_t gfx_begin(gfx *g, uint16_t cmd)
{
	size_t at = g->msg.len;
	w_u16(&g->msg, cmd);
	w_u16(&g->msg, 0);
	w_u32(&g->msg, 0);
	return at;
}

static void gfx_end(gfx *g, size_t at)
{
	put_u32(&g->msg, at + 4, g->msg.len - at);
}

/* ---- encoder --------------------------------------------------------- */

static int enc_open(gfx *g)
{
	x264_param_t p;
	if (x264_param_default_preset(&p, "ultrafast", "zerolatency"))
		return -1;
	p.i_width = g->w;
	p.i_height = g->h;
	p.i_csp = X264_CSP_I420;
	p.i_threads = 2;
	p.i_fps_num = 30;
	p.i_fps_den = 1;
	p.i_keyint_max = X264_KEYINT_MAX_INFINITE; /* keyframes when asked */
	p.rc.i_rc_method = X264_RC_CRF;
	p.rc.f_rf_constant = 20;
	/* full range BT.709, as the conversion below */
	p.vui.b_fullrange = 1;
	p.vui.i_colorprim = 1;
	p.vui.i_transfer = 1;
	p.vui.i_colmatrix = 1;
	p.b_repeat_headers = 1;
	p.b_annexb = 1;
	p.i_log_level = X264_LOG_WARNING;
	if (x264_param_apply_profile(&p, "baseline"))
		return -1;
	g->enc = x264_encoder_open(&p);
	if (!g->enc)
		return -1;
	x264_picture_alloc(&g->pic, X264_CSP_I420, g->w, g->h);
	return 0;
}

/* BGRX to I420 in a rect (even bounds), full range BT.709 as FreeRDP's:
 * clients decode AVC420 that way. */
static void to_yuv(gfx *g, const uint8_t *cur, int stride, int x0, int y0, int x1, int y1)
{
	x264_image_t *im = &g->pic.img;
	for (int y = y0; y < y1; y += 2) {
		const uint8_t *s0 = cur + (size_t)y * stride, *s1 = s0 + stride;
		uint8_t *Y0 = im->plane[0] + (size_t)y * im->i_stride[0], *Y1 = Y0 + im->i_stride[0];
		uint8_t *U = im->plane[1] + (size_t)(y / 2) * im->i_stride[1];
		uint8_t *V = im->plane[2] + (size_t)(y / 2) * im->i_stride[2];
		for (int x = x0; x < x1; x += 2) {
			const uint8_t *a = s0 + x * 4, *b = s1 + x * 4;
			Y0[x] = (54 * a[2] + 183 * a[1] + 18 * a[0]) >> 8;
			Y0[x + 1] = (54 * a[6] + 183 * a[5] + 18 * a[4]) >> 8;
			Y1[x] = (54 * b[2] + 183 * b[1] + 18 * b[0]) >> 8;
			Y1[x + 1] = (54 * b[6] + 183 * b[5] + 18 * b[4]) >> 8;
			int bl = a[0] + a[4] + b[0] + b[4], gr = a[1] + a[5] + b[1] + b[5], rd = a[2] + a[6] + b[2] + b[6];
			U[x / 2] = ((-29 * rd - 99 * gr + 128 * bl) >> 10) + 128;
			V[x / 2] = ((128 * rd - 116 * gr - 12 * bl) >> 10) + 128;
		}
	}
}

int gfx_frame(gfx *g, const uint8_t *cur, int stride, const gfx_rect *rects, int n, int idr)
{
	if (g->state != GFX_READY || (!n && !idr))
		return 0;
	gfx_rect all = {0, 0, g->w, g->h};
	if (!n) {
		rects = &all;
		n = 1;
	}
	x264_nal_t *nal = NULL;
	int nnal = 0, size = 0;
	if (g->avc) {
		for (int i = 0; i < n; i++) {
			const gfx_rect *r = &rects[i];
			to_yuv(g, cur, stride, r->x & ~1, r->y & ~1, (r->x + r->w + 1) & ~1, (r->y + r->h + 1) & ~1);
		}
		x264_picture_t out;
		g->pic.i_pts = g->pts++;
		g->pic.i_type = idr ? X264_TYPE_IDR : X264_TYPE_AUTO;
		size = x264_encoder_encode(g->enc, &nal, &nnal, &g->pic, &out);
		if (size < 0) {
			msg("gfx: x264 failed");
			return -1;
		}
		if (!size)
			return 0;
	}

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm;
	localtime_r(&ts.tv_sec, &tm);
	uint32_t stamp = ts.tv_nsec / 1000000 | tm.tm_sec << 10 | tm.tm_min << 16 | tm.tm_hour << 22;
	uint32_t id = ++g->frame_id;
	size_t at = gfx_begin(g, START_FRAME);
	w_u32(&g->msg, stamp);
	w_u32(&g->msg, id);
	gfx_end(g, at);

	size_t len_at;
	if (g->codec == CODEC_CAPROGRESSIVE) {
		/* progressive goes in the other wire-to-surface, with a
		 * context the client keeps the tiles in */
		at = gfx_begin(g, WIRE_TO_SURFACE_2);
		w_u16(&g->msg, 0); /* surface */
		w_u16(&g->msg, CODEC_CAPROGRESSIVE);
		w_u32(&g->msg, 1); /* codec context */
		w_u8(&g->msg, XRGB_8888);
		len_at = g->msg.len;
		w_u32(&g->msg, 0);
		rfx_progressive(&g->msg, cur, stride, g->w, g->h, rects, n, id);
	} else {
		at = gfx_begin(g, WIRE_TO_SURFACE_1);
		w_u16(&g->msg, 0); /* surface */
		w_u16(&g->msg, g->codec);
		w_u8(&g->msg, XRGB_8888);
		w_u16(&g->msg, 0);
		w_u16(&g->msg, 0);
		w_u16(&g->msg, g->w);
		w_u16(&g->msg, g->h);
		len_at = g->msg.len;
		w_u32(&g->msg, 0);
	}
	if (g->codec == CODEC_AVC420) {
		/* metablock: the rects the client takes, a quality for each */
		w_u32(&g->msg, n);
		for (int i = 0; i < n; i++) {
			w_u16(&g->msg, rects[i].x);
			w_u16(&g->msg, rects[i].y);
			w_u16(&g->msg, rects[i].x + rects[i].w);
			w_u16(&g->msg, rects[i].y + rects[i].h);
		}
		for (int i = 0; i < n; i++) {
			w_u8(&g->msg, 22);  /* qp */
			w_u8(&g->msg, 100); /* quality */
		}
		for (int i = 0; i < nnal; i++)
			w_bytes(&g->msg, nal[i].p_payload, nal[i].i_payload);
	} else if (g->codec == CODEC_CAVIDEO) {
		rfx_message(&g->msg, cur, stride, g->w, g->h, rects, n, id, id == 1);
	}
	size = g->msg.len - len_at - 4;
	put_u32(&g->msg, len_at, size);
	gfx_end(g, at);

	at = gfx_begin(g, END_FRAME);
	w_u32(&g->msg, id);
	gfx_end(g, at);
	dbg("gfx: frame %u, %d rects, %d bytes%s", id, n, size, idr ? ", keyframe" : "");
	g->sent_ms = mono_ms();
	return gfx_flush(g);
}

/* ---- client messages ------------------------------------------------- */

/* Pick the client's highest capability set that allows AVC420, else its
 * highest (RemoteFX then), of the versions we know; confirm it as it
 * came, and set up the surface. */
static int caps_advertise(gfx *g, buf *b)
{
	uint16_t count = r_u16(b);
	uint32_t best = 0;
	const uint8_t *best_data = NULL;
	uint32_t best_len = 0;
	for (int i = 0; i < count && !b->err; i++) {
		uint32_t ver = r_u32(b), len = r_u32(b);
		const uint8_t *d = r_bytes(b, len);
		if (!d)
			break;
		uint32_t flags = len >= 4 ? d[0] | d[1] << 8 | d[2] << 16 | (uint32_t)d[3] << 24 : 0;
		dbg("gfx: client caps 0x%08x flags 0x%x", ver, flags);
		if (ver > CAPVERSION_107)
			continue;
		int avc = ver == CAPVERSION_81 ? (flags & CAPS81_AVC420_ENABLED) != 0
			  : ver >= CAPVERSION_10 ? !(flags & CAPS10_AVC_DISABLED)
						 : 0;
		if (getenv("RDESK_OFF") && strstr(getenv("RDESK_OFF"), "avc"))
			avc = 0; /* RemoteFX for testing */
		if (avc > g->avc || (avc == g->avc && ver > best)) {
			g->avc = avc;
			best = ver;
			best_data = d;
			best_len = len;
		}
	}
	if (!best) {
		msg("gfx: no capability set we know");
		g->state = GFX_FAILED;
		return 0;
	}
	/* without H.264, RemoteFX Progressive: the iOS app closes the
	 * connection at plain RemoteFX (RDESK_RFX=1 for that, testing) */
	g->codec = g->avc ? CODEC_AVC420 : getenv("RDESK_RFX") ? CODEC_CAVIDEO : CODEC_CAPROGRESSIVE;
	size_t at = gfx_begin(g, CAPS_CONFIRM);
	w_u32(&g->msg, best);
	w_u32(&g->msg, best_len);
	w_bytes(&g->msg, best_data, best_len);
	gfx_end(g, at);

	at = gfx_begin(g, RESET_GRAPHICS);
	w_u32(&g->msg, g->w);
	w_u32(&g->msg, g->h);
	w_u32(&g->msg, 1);
	w_u32(&g->msg, 0);
	w_u32(&g->msg, 0);
	w_u32(&g->msg, g->w - 1);
	w_u32(&g->msg, g->h - 1);
	w_u32(&g->msg, 1); /* primary */
	w_zero(&g->msg, 340 - (g->msg.len - at)); /* the PDU is always 340 bytes */
	gfx_end(g, at);

	at = gfx_begin(g, CREATE_SURFACE);
	w_u16(&g->msg, 0);
	w_u16(&g->msg, g->w);
	w_u16(&g->msg, g->h);
	w_u8(&g->msg, XRGB_8888);
	gfx_end(g, at);

	at = gfx_begin(g, MAP_SURFACE_TO_OUTPUT);
	w_u16(&g->msg, 0);
	w_u16(&g->msg, 0);
	w_u32(&g->msg, 0);
	w_u32(&g->msg, 0);
	gfx_end(g, at);

	if (g->avc && enc_open(g)) {
		msg("gfx: cannot open the H.264 encoder");
		g->state = GFX_FAILED;
		b_reset(&g->msg);
		return 0;
	}
	msg("gfx: caps 0x%08x, surface %dx%d, %s", best, g->w, g->h,
	    g->codec == CODEC_AVC420 ? "H.264" : g->codec == CODEC_CAVIDEO ? "RemoteFX" : "RemoteFX Progressive");
	g->state = GFX_READY;
	return gfx_flush(g);
}

static int gfx_message(gfx *g, buf *b)
{
	while (r_left(b) >= 8) {
		size_t start = b->pos;
		uint16_t cmd = r_u16(b);
		r_u16(b);
		uint32_t len = r_u32(b);
		if (len < 8 || start + len > b->len)
			break;
		buf p = {.p = b->p + start + 8, .len = len - 8};
		switch (cmd) {
		case CAPS_ADVERTISE:
			if (g->state == GFX_PENDING && caps_advertise(g, &p))
				return -1;
			break;
		case FRAME_ACK: {
			uint32_t depth = r_u32(&p), id = r_u32(&p);
			dbg("gfx: ack %u, queue %u", id, depth);
			g->no_ack = depth == SUSPEND_ACK;
			if (id > g->acked)
				g->acked = id;
			break;
		}
		case CACHE_IMPORT_OFFER: {
			size_t at = gfx_begin(g, CACHE_IMPORT_REPLY);
			w_u16(&g->msg, 0);
			gfx_end(g, at);
			if (gfx_flush(g))
				return -1;
			break;
		}
		case QOE_FRAME_ACK:
			break;
		default:
			dbg("gfx: pdu 0x%04x ignored", cmd);
		}
		b->pos = start + len;
	}
	return 0;
}

static uint32_t r_var(buf *b, int code)
{
	return code == 0 ? r_u8(b) : code == 1 ? r_u16(b) : r_u32(b);
}

int gfx_recv(gfx *g, buf *b)
{
	uint8_t h = r_u8(b);
	int cmd = h >> 4, sp = h >> 2 & 3, cb = h & 3;
	if (b->err)
		return 0;
	switch (cmd) {
	case DVC_CAPS: {
		r_u8(b);
		uint16_t ver = r_u16(b);
		dbg("dvc: client caps version %u", ver);
		return g->open ? 0 : dvc_create(g);
	}
	case DVC_CREATE: {
		uint32_t id = r_var(b, cb), status = r_u32(b);
		if (id != GFX_CHAN_ID)
			return 0;
		if ((int32_t)status < 0) {
			msg("gfx: client refused the channel (0x%08x)", status);
			g->state = GFX_FAILED;
			return 0;
		}
		g->open = 1;
		dbg("gfx: channel open");
		return 0;
	}
	case DVC_DATA_FIRST: {
		if (r_var(b, cb) != GFX_CHAN_ID)
			return 0;
		g->in_total = r_var(b, sp);
		b_reset(&g->in);
		w_bytes(&g->in, b->p + b->pos, r_left(b));
		break;
	}
	case DVC_DATA:
		if (r_var(b, cb) != GFX_CHAN_ID)
			return 0;
		if (!g->in_total) { /* whole */
			buf m = {.p = b->p + b->pos, .len = r_left(b)};
			return gfx_message(g, &m);
		}
		w_bytes(&g->in, b->p + b->pos, r_left(b));
		break;
	case DVC_CLOSE:
		msg("gfx: client closed the channel");
		g->state = GFX_FAILED;
		return 0;
	default:
		dbg("dvc: cmd %d ignored", cmd);
		return 0;
	}
	if (g->in_total && g->in.len >= g->in_total) {
		g->in_total = 0;
		g->in.pos = 0;
		return gfx_message(g, &g->in);
	}
	return 0;
}
