/* rdp.c - buffers, transport framing, BER/PER, MCS and share headers. */
#include "rdp.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int verbose;

static void vlog(const char *fmt, va_list ap)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm;
	localtime_r(&ts.tv_sec, &tm);
	fprintf(stderr, "%02d:%02d:%02d.%03ld ", tm.tm_hour, tm.tm_min, tm.tm_sec,
		ts.tv_nsec / 1000000);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

void msg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(fmt, ap);
	va_end(ap);
}

void dbg(const char *fmt, ...)
{
	if (!verbose)
		return;
	va_list ap;
	va_start(ap, fmt);
	vlog(fmt, ap);
	va_end(ap);
}

void hexdump(const char *label, const uint8_t *p, size_t n)
{
	if (verbose < 2)
		return;
	fprintf(stderr, "%s (%zu):", label, n);
	for (size_t i = 0; i < n && i < 512; i++)
		fprintf(stderr, "%s%02x", i % 32 ? " " : "\n  ", p[i]);
	fputc('\n', stderr);
}

/* ---- buffer --------------------------------------------------------- */

void b_init(buf *b, size_t cap)
{
	memset(b, 0, sizeof *b);
	b_reserve(b, cap ? cap : 256);
}

void b_free(buf *b)
{
	free(b->p);
	memset(b, 0, sizeof *b);
}

void b_reset(buf *b)
{
	b->len = b->pos = 0;
	b->err = 0;
}

void b_reserve(buf *b, size_t n)
{
	if (b->len + n <= b->cap)
		return;
	size_t cap = b->cap ? b->cap : 256;
	while (cap < b->len + n)
		cap *= 2;
	uint8_t *p = realloc(b->p, cap);
	if (!p) {
		perror("realloc");
		abort();
	}
	b->p = p;
	b->cap = cap;
}

void w_u8(buf *b, uint8_t v)
{
	b_reserve(b, 1);
	b->p[b->len++] = v;
}

void w_u16(buf *b, uint16_t v)
{
	b_reserve(b, 2);
	b->p[b->len++] = v;
	b->p[b->len++] = v >> 8;
}

void w_u16be(buf *b, uint16_t v)
{
	b_reserve(b, 2);
	b->p[b->len++] = v >> 8;
	b->p[b->len++] = v;
}

void w_u32(buf *b, uint32_t v)
{
	w_u16(b, v);
	w_u16(b, v >> 16);
}

void w_u32be(buf *b, uint32_t v)
{
	w_u16be(b, v >> 16);
	w_u16be(b, v);
}

void w_bytes(buf *b, const void *p, size_t n)
{
	b_reserve(b, n);
	memcpy(b->p + b->len, p, n);
	b->len += n;
}

void w_zero(buf *b, size_t n)
{
	b_reserve(b, n);
	memset(b->p + b->len, 0, n);
	b->len += n;
}

/* UTF-8 -> UTF-16LE (BMP + surrogates). */
void w_utf16(buf *b, const char *s, int nul)
{
	const uint8_t *u = (const uint8_t *)s;
	while (*u) {
		uint32_t c = *u++;
		if (c >= 0xf0 && u[0] && u[1] && u[2]) {
			c = (c & 7) << 18 | (u[0] & 0x3f) << 12 | (u[1] & 0x3f) << 6 | (u[2] & 0x3f);
			u += 3;
		} else if (c >= 0xe0 && u[0] && u[1]) {
			c = (c & 15) << 12 | (u[0] & 0x3f) << 6 | (u[1] & 0x3f);
			u += 2;
		} else if (c >= 0xc0 && u[0]) {
			c = (c & 31) << 6 | (u[0] & 0x3f);
			u += 1;
		}
		if (c >= 0x10000) {
			c -= 0x10000;
			w_u16(b, 0xd800 | c >> 10);
			w_u16(b, 0xdc00 | (c & 0x3ff));
		} else {
			w_u16(b, c);
		}
	}
	if (nul)
		w_u16(b, 0);
}

void put_u16(buf *b, size_t at, uint16_t v)
{
	b->p[at] = v;
	b->p[at + 1] = v >> 8;
}

void put_u16be(buf *b, size_t at, uint16_t v)
{
	b->p[at] = v >> 8;
	b->p[at + 1] = v;
}

void put_u32(buf *b, size_t at, uint32_t v)
{
	put_u16(b, at, v);
	put_u16(b, at + 2, v >> 16);
}

size_t r_left(const buf *b)
{
	return b->err || b->pos > b->len ? 0 : b->len - b->pos;
}

const uint8_t *r_bytes(buf *b, size_t n)
{
	if (r_left(b) < n) {
		b->err = 1;
		b->pos = b->len;
		return NULL;
	}
	const uint8_t *p = b->p + b->pos;
	b->pos += n;
	return p;
}

void r_skip(buf *b, size_t n)
{
	r_bytes(b, n);
}

uint8_t r_u8(buf *b)
{
	const uint8_t *p = r_bytes(b, 1);
	return p ? p[0] : 0;
}

uint16_t r_u16(buf *b)
{
	const uint8_t *p = r_bytes(b, 2);
	return p ? p[0] | p[1] << 8 : 0;
}

uint16_t r_u16be(buf *b)
{
	const uint8_t *p = r_bytes(b, 2);
	return p ? p[0] << 8 | p[1] : 0;
}

uint32_t r_u32(buf *b)
{
	uint32_t lo = r_u16(b);
	return lo | (uint32_t)r_u16(b) << 16;
}

uint32_t r_u32be(buf *b)
{
	uint32_t hi = r_u16be(b);
	return hi << 16 | r_u16be(b);
}

/* UTF-16LE -> UTF-8, truncated to outsz-1. */
void r_utf16(buf *b, size_t nbytes, char *out, size_t outsz)
{
	const uint8_t *p = r_bytes(b, nbytes);
	size_t o = 0;
	if (!p) {
		if (outsz)
			out[0] = 0;
		return;
	}
	for (size_t i = 0; i + 1 < nbytes; i += 2) {
		uint32_t c = p[i] | p[i + 1] << 8;
		if (c >= 0xd800 && c < 0xdc00 && i + 3 < nbytes) {
			uint32_t lo = p[i + 2] | p[i + 3] << 8;
			if (lo >= 0xdc00 && lo < 0xe000) {
				c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
				i += 2;
			}
		}
		if (!c)
			break;
		char tmp[4];
		int k;
		if (c < 0x80) {
			tmp[0] = c;
			k = 1;
		} else if (c < 0x800) {
			tmp[0] = 0xc0 | c >> 6;
			tmp[1] = 0x80 | (c & 0x3f);
			k = 2;
		} else if (c < 0x10000) {
			tmp[0] = 0xe0 | c >> 12;
			tmp[1] = 0x80 | (c >> 6 & 0x3f);
			tmp[2] = 0x80 | (c & 0x3f);
			k = 3;
		} else {
			tmp[0] = 0xf0 | c >> 18;
			tmp[1] = 0x80 | (c >> 12 & 0x3f);
			tmp[2] = 0x80 | (c >> 6 & 0x3f);
			tmp[3] = 0x80 | (c & 0x3f);
			k = 4;
		}
		if (o + k >= outsz)
			break;
		memcpy(out + o, tmp, k);
		o += k;
	}
	if (outsz)
		out[o] = 0;
}

/* ---- connection ----------------------------------------------------- */

int c_read(conn *c, void *p, size_t n)
{
	uint8_t *q = p;
	while (n) {
		ssize_t r;
		if (c->ssl) {
			r = SSL_read(c->ssl, q, n > 0x7fffffff ? 0x7fffffff : (int)n);
			if (r <= 0) {
				int e = SSL_get_error(c->ssl, r);
				if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
					continue;
				if (e != SSL_ERROR_ZERO_RETURN)
					dbg("SSL_read: error %d errno %d", e, errno);
				return -1;
			}
		} else {
			r = read(c->fd, q, n);
			if (r < 0 && errno == EINTR)
				continue;
			if (r <= 0)
				return -1;
		}
		q += r;
		n -= r;
	}
	return 0;
}

int c_write(conn *c, const void *p, size_t n)
{
	const uint8_t *q = p;
	while (n) {
		ssize_t r;
		if (c->ssl) {
			r = SSL_write(c->ssl, q, n > 0x7fffffff ? 0x7fffffff : (int)n);
			if (r <= 0) {
				int e = SSL_get_error(c->ssl, r);
				if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
					continue;
				dbg("SSL_write: error %d errno %d", e, errno);
				return -1;
			}
		} else {
			r = write(c->fd, q, n);
			if (r < 0 && errno == EINTR)
				continue;
			if (r <= 0)
				return -1;
		}
		q += r;
		n -= r;
	}
	return 0;
}

int c_pending(conn *c)
{
	return c->ssl ? SSL_pending(c->ssl) : 0;
}

int read_pdu(conn *c, buf *b, int *fastpath)
{
	uint8_t h[4];
	size_t len, have;
	b_reset(b);
	if (c_read(c, h, 2))
		return -1;
	if (h[0] == 3) {
		if (c_read(c, h + 2, 2))
			return -1;
		len = h[2] << 8 | h[3];
		have = 4;
		*fastpath = 0;
	} else {
		*fastpath = 1;
		if (h[1] & 0x80) {
			if (c_read(c, h + 2, 1))
				return -1;
			len = (h[1] & 0x7f) << 8 | h[2];
			have = 3;
		} else {
			len = h[1];
			have = 2;
		}
	}
	if (len < have) {
		msg("bad PDU length %zu", len);
		return -1;
	}
	b_reserve(b, len);
	memcpy(b->p, h, have);
	if (c_read(c, b->p + have, len - have))
		return -1;
	b->len = len;
	hexdump(*fastpath ? "<- fp" : "<- tpkt", b->p, b->len);
	return 0;
}

/* ---- BER / PER ------------------------------------------------------ */

void w_ber_len(buf *b, size_t n)
{
	if (n < 0x80) {
		w_u8(b, n);
	} else if (n < 0x100) {
		w_u8(b, 0x81);
		w_u8(b, n);
	} else {
		w_u8(b, 0x82);
		w_u16be(b, n);
	}
}

int r_ber_len(buf *b, size_t *n)
{
	uint8_t v = r_u8(b);
	if (v < 0x80) {
		*n = v;
	} else if (v == 0x81) {
		*n = r_u8(b);
	} else if (v == 0x82) {
		*n = r_u16be(b);
	} else if (v == 0x83) {
		*n = (size_t)r_u8(b) << 16;
		*n |= r_u16be(b);
	} else {
		return -1;
	}
	return b->err ? -1 : 0;
}

int r_ber_tag(buf *b, unsigned tag, size_t *n)
{
	if (tag > 0xff) {
		if (r_u8(b) != tag >> 8)
			return -1;
	}
	if (r_u8(b) != (tag & 0xff))
		return -1;
	return r_ber_len(b, n);
}

void w_per_len(buf *b, size_t n)
{
	if (n < 0x80)
		w_u8(b, n);
	else
		w_u16be(b, 0x8000 | n);
}

size_t r_per_len(buf *b)
{
	uint8_t v = r_u8(b);
	if (v & 0x80)
		return (v & 0x7f) << 8 | r_u8(b);
	return v;
}

/* ---- MCS ------------------------------------------------------------ */

void mcs_put(buf *b, int indication, uint16_t user, uint16_t chan, const uint8_t *p, size_t n)
{
	size_t at = b->len;
	w_u8(b, 3);
	w_u8(b, 0);
	w_u16be(b, 0); /* patched */
	w_u8(b, 2);
	w_u8(b, 0xf0);
	w_u8(b, 0x80);
	w_u8(b, (indication ? MCS_SDIN : MCS_SDRQ) << 2);
	w_u16be(b, user - 1001);
	w_u16be(b, chan);
	w_u8(b, 0x70);
	w_per_len(b, n);
	w_bytes(b, p, n);
	put_u16be(b, at + 2, b->len - at);
}

int send_mcs(conn *c, int indication, uint16_t user, uint16_t chan,
	     const uint8_t *p, size_t n)
{
	buf b;
	b_init(&b, n + 20);
	mcs_put(&b, indication, user, chan, p, n);
	hexdump("-> mcs", b.p, b.len);
	int r = c_write(c, b.p, b.len);
	b_free(&b);
	return r;
}

int parse_mcs(buf *b, uint16_t *user, uint16_t *chan)
{
	b->pos = 4; /* TPKT */
	uint8_t li = r_u8(b);
	uint8_t code = r_u8(b);
	if (code != 0xf0) {
		msg("X.224: not a data TPDU (0x%02x)", code);
		return -1;
	}
	r_skip(b, li - 1);
	uint8_t choice = r_u8(b);
	int type = choice >> 2;
	if (type == MCS_SDRQ || type == MCS_SDIN) {
		*user = r_u16be(b) + 1001;
		*chan = r_u16be(b);
		r_u8(b); /* priority / segmentation */
		size_t n = r_per_len(b);
		if (b->err || r_left(b) < n)
			return -1;
		b->len = b->pos + n;
	}
	return b->err ? -1 : type;
}

/* ---- share headers --------------------------------------------------- */

int send_share(session *s, uint16_t type, const uint8_t *p, size_t n)
{
	buf b;
	b_init(&b, n + 6);
	w_u16(&b, n + 6);
	w_u16(&b, type | 0x10);
	w_u16(&b, s->user);
	w_bytes(&b, p, n);
	int r = send_mcs(s->c, s->server, s->user, MCS_IO_CHANNEL, b.p, b.len);
	b_free(&b);
	return r;
}

int send_data(session *s, uint8_t type2, const uint8_t *p, size_t n)
{
	buf b;
	b_init(&b, n + 12);
	w_u32(&b, s->share_id);
	w_u8(&b, 0);
	w_u8(&b, 1); /* STREAM_LOW */
	w_u16(&b, n + 4);
	w_u8(&b, type2);
	w_u8(&b, 0);
	w_u16(&b, 0);
	w_bytes(&b, p, n);
	int r = send_share(s, PDU_DATA, b.p, b.len);
	b_free(&b);
	return r;
}

int parse_share(buf *b, uint8_t *type2)
{
	size_t start = b->pos;
	uint16_t total = r_u16(b);
	if (total == 0x8000) /* flow PDU */
		return 0;
	int type = r_u16(b) & 0x0f;
	r_u16(b); /* source */
	if (total >= 6 && start + total <= b->len)
		b->len = start + total;
	if (type == PDU_DATA) {
		r_u32(b); /* share id */
		r_u8(b);
		r_u8(b);
		r_u16(b);
		*type2 = r_u8(b);
		uint8_t ctype = r_u8(b);
		r_u16(b);
		if (ctype & 0x20) {
			msg("compressed data PDU not supported");
			return -1;
		}
	}
	return b->err ? -1 : type;
}

void fp_header(buf *b, uint8_t hdr, size_t n)
{
	size_t total = n + 3;
	w_u8(b, hdr);
	w_u16be(b, 0x8000 | total);
}

/* ---- keyboard ---------------------------------------------------------- */

/* E0-prefixed set-1 scancodes <-> Linux evdev codes. Non-extended
 * scancodes 1..88 equal their evdev codes. */
static const struct { uint8_t sc, ev; } e0keys[] = {
	{0x1c, 96},  {0x1d, 97},  {0x35, 98},  {0x37, 99},  {0x38, 100},
	{0x46, 119}, {0x47, 102}, {0x48, 103}, {0x49, 104}, {0x4b, 105},
	{0x4d, 106}, {0x4f, 107}, {0x50, 108}, {0x51, 109}, {0x52, 110},
	{0x53, 111}, {0x5b, 125}, {0x5c, 126}, {0x5d, 127}, {0x20, 113},
	{0x2e, 114}, {0x30, 115}, {0x22, 164}, {0x24, 166}, {0x19, 163},
	{0x10, 165},
};

int sc_to_evdev(uint8_t sc, int ext)
{
	if (!ext)
		return sc;
	for (size_t i = 0; i < sizeof e0keys / sizeof *e0keys; i++)
		if (e0keys[i].sc == sc)
			return e0keys[i].ev;
	return 0;
}

int evdev_to_sc(int ev, int *ext)
{
	*ext = 0;
	if (ev >= 1 && ev <= 88)
		return ev;
	for (size_t i = 0; i < sizeof e0keys / sizeof *e0keys; i++)
		if (e0keys[i].ev == ev) {
			*ext = 1;
			return e0keys[i].sc;
		}
	return 0;
}

/* ---- static virtual channels ----------------------------------------- */

#define CHANNEL_FLAG_FIRST 0x01
#define CHANNEL_FLAG_LAST 0x02
#define CHANNEL_CHUNK 1600

int vc_send(conn *c, int indication, uint16_t user, uint16_t chan, const uint8_t *p, size_t n)
{
	size_t off = 0;
	do {
		size_t k = n - off > CHANNEL_CHUNK ? CHANNEL_CHUNK : n - off;
		uint32_t flags = (off == 0 ? CHANNEL_FLAG_FIRST : 0) | (off + k == n ? CHANNEL_FLAG_LAST : 0) |
				 0x10; /* SHOW_PROTOCOL: required for cliprdr */
		buf b;
		b_init(&b, k + 8);
		w_u32(&b, n);
		w_u32(&b, flags);
		w_bytes(&b, p + off, k);
		int r = send_mcs(c, indication, user, chan, b.p, b.len);
		b_free(&b);
		if (r)
			return -1;
		off += k;
	} while (off < n);
	return 0;
}

void vc_put(buf *out, uint16_t user, uint16_t chan, const uint8_t *p, size_t n)
{
	uint8_t chunk[CHANNEL_CHUNK + 8];
	size_t off = 0;
	do {
		size_t k = n - off > CHANNEL_CHUNK ? CHANNEL_CHUNK : n - off;
		uint32_t flags = (off == 0 ? CHANNEL_FLAG_FIRST : 0) | (off + k == n ? CHANNEL_FLAG_LAST : 0) | 0x10;
		for (int i = 0; i < 4; i++) {
			chunk[i] = n >> 8 * i;
			chunk[4 + i] = flags >> 8 * i;
		}
		memcpy(chunk + 8, p + off, k);
		mcs_put(out, 1, user, chan, chunk, k + 8);
		off += k;
	} while (off < n);
}

int vc_recv(buf *acc, buf *b)
{
	uint32_t total = r_u32(b), flags = r_u32(b);
	if (b->err)
		return 0;
	if (flags & CHANNEL_FLAG_FIRST)
		b_reset(acc);
	const uint8_t *p = r_bytes(b, r_left(b));
	if (p)
		w_bytes(acc, p, b->len - (p - b->p));
	if (!(flags & CHANNEL_FLAG_LAST))
		return 0;
	acc->pos = 0;
	if (acc->len != total)
		dbg("channel PDU %zu bytes, header says %u", acc->len, total);
	return 1;
}

/* One fast-path update, fragmented so no PDU exceeds 0x3FFF bytes
 * (FreeRDP's FASTPATH_MAX_PACKET_SIZE; mstsc rejects bigger ones). */
void fp_update(buf *out, uint8_t code, const uint8_t *p, size_t n)
{
	const size_t max = 0x3fff - 6;
	size_t off = 0;
	do {
		size_t k = n - off > max ? max : n - off;
		int frag = n <= max ? FP_FRAG_SINGLE
			   : off == 0 ? FP_FRAG_FIRST
			   : off + k == n ? FP_FRAG_LAST : FP_FRAG_NEXT;
		fp_header(out, 0, 3 + k);
		w_u8(out, code | frag << 4);
		w_u16(out, k);
		w_bytes(out, p + off, k);
		off += k;
	} while (off < n);
}
