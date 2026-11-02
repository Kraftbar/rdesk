/* client.c - rdesk-rdpc-client: RDP client for X11.
 *
 * Milestone 1: TLS security, slow-path connection sequence, raw bitmap
 * updates (fast-path and slow-path), pointer shapes, fast-path keyboard and
 * mouse input. The graphics pipeline (gfxc.c) when the server offers it:
 * H.264 and the rest; RDESK_OFF=gfx for bitmaps only. */
#define _GNU_SOURCE
#include "rdp.h"
#include "gfxc.h"
#include "nla.h"
#include "planar.h"
#include "clip.h"

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xcursor/Xcursor.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static struct {
	const char *host;
	const char *port;
	const char *user;
	const char *domain;
	char *pass;
	int w, h;
	const char *dump;   /* write a PPM of the screen after dump_ms, exit */
	int dump_ms;
	int no_nla;
	const char *type; /* typed as Unicode key events once connected */
} opt = {NULL, "3389", NULL, "", NULL, 1280, 800, NULL, 3000, 0, NULL};

static uint32_t selected_protocol;

/* ---- X11 window ----------------------------------------------------- */

static struct {
	Display *dpy;
	Window win;
	GC gc;
	XImage *img;
	uint32_t *fb;
	int w, h;
	Atom wm_delete;
	int dx0, dy0, dx1, dy1; /* dirty rect, dx1 == 0 when clean */
	Cursor cache[32];
	Cursor blank;
} x;

static void dirty(int l, int t, int r, int b)
{
	if (l < 0) l = 0;
	if (t < 0) t = 0;
	if (r > x.w) r = x.w;
	if (b > x.h) b = x.h;
	if (r <= l || b <= t)
		return;
	if (!x.dx1) {
		x.dx0 = l; x.dy0 = t; x.dx1 = r; x.dy1 = b;
		return;
	}
	if (l < x.dx0) x.dx0 = l;
	if (t < x.dy0) x.dy0 = t;
	if (r > x.dx1) x.dx1 = r;
	if (b > x.dy1) x.dy1 = b;
}

static void present(void)
{
	if (!x.dx1 || !x.img)
		return;
	XPutImage(x.dpy, x.win, x.gc, x.img, x.dx0, x.dy0, x.dx0, x.dy0, x.dx1 - x.dx0, x.dy1 - x.dy0);
	XFlush(x.dpy);
	x.dx1 = 0;
}

static int x_window(int w, int h)
{
	if (!x.dpy) {
		x.dpy = XOpenDisplay(NULL);
		if (!x.dpy) {
			msg("cannot open display");
			return -1;
		}
		x.wm_delete = XInternAtom(x.dpy, "WM_DELETE_WINDOW", False);
	}
	Visual *vis = DefaultVisual(x.dpy, DefaultScreen(x.dpy));
	int depth = DefaultDepth(x.dpy, DefaultScreen(x.dpy));
	if (depth < 24) {
		msg("need a 24/32 bit TrueColor display");
		return -1;
	}
	if (x.win && (w != x.w || h != x.h)) {
		XDestroyImage(x.img); /* frees fb */
		x.img = NULL;
		XResizeWindow(x.dpy, x.win, w, h);
	}
	x.w = w;
	x.h = h;
	if (!x.img) {
		x.fb = calloc((size_t)w * h, 4);
		x.img = XCreateImage(x.dpy, vis, depth, ZPixmap, 0, (char *)x.fb, w, h, 32, w * 4);
	}
	if (!x.win) {
		x.win = XCreateSimpleWindow(x.dpy, DefaultRootWindow(x.dpy), 0, 0, w, h, 0, 0, 0);
		char title[300];
		snprintf(title, sizeof title, "rdesk - %s", opt.host);
		XStoreName(x.dpy, x.win, title);
		XSizeHints *sh = XAllocSizeHints();
		sh->flags = PMinSize | PMaxSize;
		sh->min_width = sh->max_width = w;
		sh->min_height = sh->max_height = h;
		XSetWMNormalHints(x.dpy, x.win, sh);
		XFree(sh);
		XSelectInput(x.dpy, x.win, ExposureMask | KeyPressMask | KeyReleaseMask |
			     ButtonPressMask | ButtonReleaseMask | PointerMotionMask |
			     FocusChangeMask);
		XSetWMProtocols(x.dpy, x.win, &x.wm_delete, 1);
		x.gc = XCreateGC(x.dpy, x.win, 0, NULL);
		static char zero[8];
		Pixmap pm = XCreateBitmapFromData(x.dpy, x.win, zero, 1, 1);
		XColor c = {0};
		x.blank = XCreatePixmapCursor(x.dpy, pm, pm, &c, &c, 0, 0);
		XFreePixmap(x.dpy, pm);
		XMapWindow(x.dpy, x.win);
	}
	XFlush(x.dpy);
	return 0;
}

static void dump_ppm(void)
{
	FILE *f = fopen(opt.dump, "wb");
	if (!f) {
		perror(opt.dump);
		return;
	}
	fprintf(f, "P6\n%d %d\n255\n", x.w, x.h);
	for (int i = 0; i < x.w * x.h; i++) {
		uint32_t p = x.fb[i];
		uint8_t rgb[3] = {p >> 16, p >> 8, p};
		fwrite(rgb, 1, 3, f);
	}
	fclose(f);
	msg("wrote %s", opt.dump);
}

/* ---- connection ----------------------------------------------------- */

typedef struct {
	conn c;
	session s;
	uint16_t io;
	int nchan;
	uint16_t chan_id[31];
	int licensed;
	int active;
	buf frag; /* fast-path fragment reassembly */
	int frag_code;
	buf cliprdr_acc;
	clip *clip;
	buf drdynvc_acc;
	gfxc *gfx;
} rdp;

/* chan_id[] follows the order of CS_NET */
#define CHAN_CLIPRDR 0
#define CHAN_DRDYNVC 1

/* RDESK_OFF=gfx,dvc,conntype: switch parts off (diagnostics) */
static int off(const char *what)
{
	const char *e = getenv("RDESK_OFF");
	return e && strstr(e, what);
}

static int gfx_off(void)
{
	return off("gfx") || off("dvc");
}

static int clip_send(void *arg, const uint8_t *p, size_t n)
{
	rdp *r = arg;
	return r->nchan > CHAN_CLIPRDR ? vc_send(&r->c, 0, r->s.user, r->chan_id[CHAN_CLIPRDR], p, n) : -1;
}

static int dvc_send(void *arg, const uint8_t *p, size_t n)
{
	/* one chunk (client DVC messages are small), without SHOW_PROTOCOL:
	 * vc_send sets it, as cliprdr needs, but drdynvc doesn't ask for it */
	rdp *r = arg;
	uint8_t pdu[8 + 1600];
	if (r->nchan <= CHAN_DRDYNVC || n > 1600)
		return -1;
	for (int i = 0; i < 4; i++)
		pdu[i] = n >> 8 * i;
	pdu[4] = 0x03; /* FIRST | LAST */
	pdu[5] = pdu[6] = pdu[7] = 0;
	memcpy(pdu + 8, p, n);
	return send_mcs(&r->c, 0, r->s.user, r->chan_id[CHAN_DRDYNVC], pdu, n + 8);
}

static int tcp_connect(const char *host, const char *port)
{
	struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res, *ai;
	int e = getaddrinfo(host, port, &hints, &res);
	if (e) {
		msg("%s: %s", host, gai_strerror(e));
		return -1;
	}
	int fd = -1;
	for (ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		msg("connect %s:%s: %s", host, port, strerror(errno));
		return -1;
	}
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	return fd;
}

static int x224_connect(rdp *r)
{
	buf b;
	b_init(&b, 128);
	w_bytes(&b, "\x03\x00\x00\x00\x00\xe0\x00\x00\x00\x00\x00", 11);
	char cookie[300];
	snprintf(cookie, sizeof cookie, "Cookie: mstshash=%.200s\r\n", opt.user);
	w_bytes(&b, cookie, strlen(cookie));
	w_u8(&b, 1);
	w_u8(&b, 0);
	w_u16(&b, 8);
	w_u32(&b, opt.no_nla ? PROTOCOL_SSL : PROTOCOL_SSL | PROTOCOL_HYBRID);
	put_u16be(&b, 2, b.len);
	b.p[4] = b.len - 5;
	if (c_write(&r->c, b.p, b.len))
		return -1;
	int fp;
	if (read_pdu(&r->c, &b, &fp) || fp)
		return -1;
	b.pos = 5;
	if ((r_u8(&b) & 0xf0) != 0xd0) {
		msg("no X.224 connection confirm");
		return -1;
	}
	r_skip(&b, 5);
	if (r_left(&b) < 8) {
		msg("server does not negotiate (standard RDP security only?)");
		return -1;
	}
	uint8_t type = r_u8(&b);
	r_u8(&b);
	r_u16(&b);
	uint32_t v = r_u32(&b);
	b_free(&b);
	if (type == 3) {
		msg("negotiation failure, code %u%s", v, v == 5 ? " (server requires NLA)" : "");
		return -1;
	}
	if (type != 2 || (v != PROTOCOL_SSL && v != PROTOCOL_HYBRID)) {
		msg("server selected protocol %u, only TLS and NLA are implemented", v);
		return -1;
	}
	selected_protocol = v;
	dbg("selected protocol %s", v == PROTOCOL_HYBRID ? "NLA" : "TLS");
	return 0;
}

static int tls_connect(rdp *r)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	r->c.ssl = SSL_new(ctx);
	SSL_set_fd(r->c.ssl, r->c.fd);
	struct in6_addr a6;
	if (inet_pton(AF_INET, opt.host, &a6) != 1 && inet_pton(AF_INET6, opt.host, &a6) != 1)
		SSL_set_tlsext_host_name(r->c.ssl, opt.host); /* SNI only for names */
	if (SSL_connect(r->c.ssl) != 1) {
		msg("TLS handshake failed");
		ERR_print_errors_fp(stderr);
		return -1;
	}
	X509 *cert = SSL_get1_peer_certificate(r->c.ssl);
	if (cert) {
		uint8_t md[32];
		unsigned n;
		X509_digest(cert, EVP_sha256(), md, &n);
		char hex[3 * 32 + 1];
		for (unsigned i = 0; i < n; i++)
			sprintf(hex + 3 * i, "%02x%s", md[i], i + 1 < n ? ":" : "");
		msg("server certificate sha256 %s", hex);
		X509_free(cert);
	}
	return 0;
}

static int mcs_connect(rdp *r)
{
	buf ud;
	b_init(&ud, 512);
	/* CS_CORE */
	w_u16(&ud, 0xc001);
	w_u16(&ud, 216);
	w_u32(&ud, 0x00080004);
	w_u16(&ud, opt.w);
	w_u16(&ud, opt.h);
	w_u16(&ud, 0xca01);
	w_u16(&ud, 0xaa03);
	w_u32(&ud, 0x409);
	w_u32(&ud, 2600);
	size_t at = ud.len;
	w_utf16(&ud, "rdesk-c", 0);
	w_zero(&ud, 32 - (ud.len - at));
	w_u32(&ud, 4);
	w_u32(&ud, 0);
	w_u32(&ud, 12);
	w_zero(&ud, 64);
	w_u16(&ud, 0xca01);
	w_u16(&ud, 1);
	w_u32(&ud, 0);
	w_u16(&ud, 24);
	w_u16(&ud, 0x000f);
	/* SUPPORT_ERRINFO_PDU | WANT_32BPP_SESSION | VALID_CONNECTION_TYPE,
	 * and SUPPORT_DYNVC_GFX_PROTOCOL for the graphics pipeline */
	w_u16(&ud, 0x0001 | 0x0002 | (off("conntype") ? 0 : 0x0020) | (gfx_off() ? 0 : 0x0100));
	w_zero(&ud, 64);
	w_u8(&ud, off("conntype") ? 0 : 6); /* connection type LAN */
	w_u8(&ud, 0);
	w_u32(&ud, selected_protocol);
	/* CS_SECURITY */
	w_u16(&ud, 0xc002);
	w_u16(&ud, 12);
	w_u32(&ud, 0);
	w_u32(&ud, 0);
	/* CS_NET: cliprdr, drdynvc (dynamic channels: the graphics pipeline) */
	w_u16(&ud, 0xc003);
	int nchan = off("dvc") ? 1 : 2;
	w_u16(&ud, 8 + nchan * 12);
	w_u32(&ud, nchan);
	w_bytes(&ud, "cliprdr\0", 8);
	w_u32(&ud, 0xc0a00000); /* INITIALIZED | ENCRYPT_RDP | COMPRESS_RDP | SHOW_PROTOCOL */
	if (nchan > 1) {
		w_bytes(&ud, "drdynvc\0", 8);
		w_u32(&ud, 0xc0800000); /* INITIALIZED | ENCRYPT_RDP | COMPRESS_RDP */
	}

	buf gcc;
	b_init(&gcc, ud.len + 32);
	w_bytes(&gcc, "\x00\x05\x00\x14\x7c\x00\x01", 7);
	w_per_len(&gcc, 12 + (ud.len < 0x80 ? 1 : 2) + ud.len);
	w_bytes(&gcc, "\x00\x08\x00\x10\x00\x01\xc0\x00" "Duca", 12);
	w_per_len(&gcc, ud.len);
	w_bytes(&gcc, ud.p, ud.len);

	static const uint8_t params[] = {
		0x04, 0x01, 0x01, 0x04, 0x01, 0x01, 0x01, 0x01, 0xff,
		/* target */
		0x30, 0x1a, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03,
		0x00, 0xff, 0xff, 0x02, 0x01, 0x02,
		/* minimum */
		0x30, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
		0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02,
		0x04, 0x20, 0x02, 0x01, 0x02,
		/* maximum */
		0x30, 0x1f, 0x02, 0x03, 0x00, 0xff, 0xff, 0x02, 0x02, 0xfc, 0x17,
		0x02, 0x03, 0x00, 0xff, 0xff, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff, 0xff, 0x02, 0x01, 0x02};
	buf body;
	b_init(&body, gcc.len + 128);
	w_bytes(&body, params, sizeof params);
	w_u8(&body, 0x04);
	w_ber_len(&body, gcc.len);
	w_bytes(&body, gcc.p, gcc.len);

	buf o;
	b_init(&o, body.len + 16);
	w_bytes(&o, "\x03\x00\x00\x00\x02\xf0\x80\x7f\x65", 9);
	w_ber_len(&o, body.len);
	w_bytes(&o, body.p, body.len);
	put_u16be(&o, 2, o.len);
	int rc = c_write(&r->c, o.p, o.len);
	b_free(&o);
	b_free(&body);
	b_free(&gcc);
	b_free(&ud);
	if (rc)
		return -1;

	/* Connect-Response: find the server data after "McDn" */
	buf b;
	b_init(&b, 1024);
	int fp;
	if (read_pdu(&r->c, &b, &fp) || fp)
		return -1;
	size_t i;
	for (i = 7; i + 4 <= b.len; i++)
		if (!memcmp(b.p + i, "McDn", 4))
			break;
	if (i + 4 > b.len) {
		msg("bad MCS Connect-Response");
		return -1;
	}
	b.pos = i + 4;
	size_t n = r_per_len(&b), end = b.pos + n;
	if (end > b.len)
		return -1;
	r->io = MCS_IO_CHANNEL;
	while (b.pos + 4 <= end) {
		size_t start = b.pos;
		uint16_t type = r_u16(&b), len = r_u16(&b);
		if (len < 4)
			break;
		if (type == 0x0c01) {
			uint32_t ver = r_u32(&b);
			dbg("server version 0x%x", ver);
		} else if (type == 0x0c03) {
			r->io = r_u16(&b);
			r->nchan = r_u16(&b);
			for (int k = 0; k < r->nchan && k < 31; k++)
				r->chan_id[k] = r_u16(&b);
		} else if (type == 0x0c02) {
			uint32_t m = r_u32(&b);
			if (m)
				msg("server wants standard RDP encryption %u (unsupported)", m);
		}
		b.pos = start + len;
	}
	b_free(&b);
	return 0;
}

static int send_x224(rdp *r, const uint8_t *p, size_t n)
{
	uint8_t tmp[64] = {3, 0, (n + 7) >> 8, (n + 7) & 0xff, 2, 0xf0, 0x80};
	memcpy(tmp + 7, p, n);
	return c_write(&r->c, tmp, n + 7);
}

static int mcs_attach(rdp *r)
{
	static const uint8_t erect[] = {MCS_ERECT << 2, 1, 0, 1, 0};
	static const uint8_t aurq[] = {MCS_AURQ << 2};
	if (send_x224(r, erect, sizeof erect) || send_x224(r, aurq, sizeof aurq))
		return -1;
	dbg("erect domain, attach user sent");
	buf b;
	b_init(&b, 64);
	int fp;
	uint16_t u, c;
	if (read_pdu(&r->c, &b, &fp) || parse_mcs(&b, &u, &c) != MCS_AUCF || r_u8(&b) != 0) {
		msg("attach user failed");
		return -1;
	}
	r->s.user = r_u16be(&b) + 1001;
	dbg("user id %u", r->s.user);
	uint16_t join[33];
	int nj = 0;
	join[nj++] = r->s.user;
	join[nj++] = r->io;
	for (int k = 0; k < r->nchan; k++)
		join[nj++] = r->chan_id[k];
	for (int k = 0; k < nj; k++) {
		uint8_t d[5] = {MCS_CJRQ << 2, (r->s.user - 1001) >> 8, (r->s.user - 1001) & 0xff,
				join[k] >> 8, join[k] & 0xff};
		if (send_x224(r, d, 5))
			return -1;
		dbg("join channel %u", join[k]);
		if (read_pdu(&r->c, &b, &fp) || parse_mcs(&b, &u, &c) != MCS_CJCF ||
		    r_u8(&b) != 0) {
			msg("join channel %u failed", join[k]);
			return -1;
		}
	}
	b_free(&b);
	return 0;
}

static int send_client_info(rdp *r)
{
	buf b;
	b_init(&b, 1024);
	w_u16(&b, SEC_INFO_PKT);
	w_u16(&b, 0);
	w_u32(&b, 0);
	uint32_t flags = 0x0001 | 0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0100 | 0x00010000;
	if (opt.pass && *opt.pass)
		flags |= 0x0008; /* INFO_AUTOLOGON */
	w_u32(&b, flags);
	buf d, u, p;
	b_init(&d, 64);
	b_init(&u, 64);
	b_init(&p, 64);
	w_utf16(&d, opt.domain, 0);
	w_utf16(&u, opt.user, 0);
	w_utf16(&p, opt.pass ? opt.pass : "", 0);
	w_u16(&b, d.len);
	w_u16(&b, u.len);
	w_u16(&b, p.len);
	w_u16(&b, 0);
	w_u16(&b, 0);
	w_bytes(&b, d.p, d.len);
	w_u16(&b, 0);
	w_bytes(&b, u.p, u.len);
	w_u16(&b, 0);
	w_bytes(&b, p.p, p.len);
	w_u16(&b, 0);
	w_u16(&b, 0); /* alternate shell */
	w_u16(&b, 0); /* working dir */
	/* extended info */
	w_u16(&b, 2);
	size_t at = b.len;
	w_u16(&b, 0);
	w_utf16(&b, "0.0.0.0", 1);
	put_u16(&b, at, b.len - at - 2);
	at = b.len;
	w_u16(&b, 0);
	w_utf16(&b, "C:\\rdesk", 1);
	put_u16(&b, at, b.len - at - 2);
	w_zero(&b, 172); /* time zone */
	w_u32(&b, 0);    /* session id */
	w_u32(&b, 0x0100 | 0x0080); /* desktop composition, font smoothing */
	w_u16(&b, 0);    /* auto-reconnect cookie */
	int rc = send_mcs(&r->c, 0, r->s.user, r->io, b.p, b.len);
	memset(p.p, 0, p.len);
	memset(b.p, 0, b.len);
	b_free(&b);
	b_free(&d);
	b_free(&u);
	b_free(&p);
	return rc;
}

static void w_cap(buf *b, uint16_t type, const uint8_t *body, size_t n)
{
	w_u16(b, type);
	w_u16(b, n + 4);
	w_bytes(b, body, n);
}

static int send_confirm_active(rdp *r)
{
	buf caps, t;
	b_init(&caps, 1024);
	b_init(&t, 128);
	int ncaps = 0;

	/* general */
	w_u16(&t, 1); w_u16(&t, 3); w_u16(&t, 0x200); w_u16(&t, 0); w_u16(&t, 0);
	w_u16(&t, 0x0001 | 0x0004 | 0x0400);
	w_u16(&t, 0); w_u16(&t, 0); w_u16(&t, 0); w_u8(&t, 1); w_u8(&t, 1);
	w_cap(&caps, CAP_GENERAL, t.p, t.len); ncaps++; b_reset(&t);

	/* bitmap */
	w_u16(&t, 32); w_u16(&t, 1); w_u16(&t, 1); w_u16(&t, 1);
	w_u16(&t, x.w); w_u16(&t, x.h); w_u16(&t, 0); w_u16(&t, 1); w_u16(&t, 1);
	w_u8(&t, 0); w_u8(&t, 0); w_u16(&t, 1); w_u16(&t, 0);
	w_cap(&caps, CAP_BITMAP, t.p, t.len); ncaps++; b_reset(&t);

	/* order: none supported */
	w_zero(&t, 20); w_u16(&t, 1); w_u16(&t, 20); w_u16(&t, 0); w_u16(&t, 1);
	w_u16(&t, 0); w_u16(&t, 0x0002 | 0x0008); w_zero(&t, 32);
	w_u16(&t, 0); w_u16(&t, 0); w_u32(&t, 0); w_u32(&t, 0);
	w_u16(&t, 0); w_u16(&t, 0); w_u16(&t, 0); w_u16(&t, 0);
	w_cap(&caps, CAP_ORDER, t.p, t.len); ncaps++; b_reset(&t);

	/* bitmap cache rev1 (empty), brush, glyph cache, offscreen, sound */
	w_zero(&t, 36); w_cap(&caps, 4, t.p, t.len); ncaps++; b_reset(&t);
	w_zero(&t, 4); w_cap(&caps, 15, t.p, t.len); ncaps++; b_reset(&t);
	w_zero(&t, 48); w_cap(&caps, 16, t.p, t.len); ncaps++; b_reset(&t);
	w_zero(&t, 8); w_cap(&caps, 17, t.p, t.len); ncaps++; b_reset(&t);
	w_zero(&t, 4); w_cap(&caps, 12, t.p, t.len); ncaps++; b_reset(&t);

	/* pointer */
	w_u16(&t, 1); w_u16(&t, 32); w_u16(&t, 32);
	w_cap(&caps, CAP_POINTER, t.p, t.len); ncaps++; b_reset(&t);

	/* input */
	w_u16(&t, 0x0001 | 0x0004 | 0x0010 | 0x0020); w_u16(&t, 0);
	w_u32(&t, 0x409); w_u32(&t, 4); w_u32(&t, 0); w_u32(&t, 12); w_zero(&t, 64);
	w_cap(&caps, CAP_INPUT, t.p, t.len); ncaps++; b_reset(&t);

	/* virtual channel, share, font, multifragment */
	w_u32(&t, 0); w_u32(&t, 1600);
	w_cap(&caps, CAP_VC, t.p, t.len); ncaps++; b_reset(&t);
	w_u16(&t, 0); w_u16(&t, 0);
	w_cap(&caps, CAP_SHARE, t.p, t.len); ncaps++; b_reset(&t);
	w_u16(&t, 1); w_u16(&t, 0);
	w_cap(&caps, CAP_FONT, t.p, t.len); ncaps++; b_reset(&t);
	w_u32(&t, 0x00800000);
	w_cap(&caps, CAP_MULTIFRAG, t.p, t.len); ncaps++; b_reset(&t);

	buf b;
	b_init(&b, caps.len + 32);
	w_u32(&b, r->s.share_id);
	w_u16(&b, 1002);
	w_u16(&b, 6);
	w_u16(&b, caps.len + 4);
	w_bytes(&b, "MSTSC", 6);
	w_u16(&b, ncaps);
	w_u16(&b, 0);
	w_bytes(&b, caps.p, caps.len);
	int rc = send_share(&r->s, PDU_CONFIRM_ACTIVE, b.p, b.len);
	b_free(&b);
	b_free(&caps);
	b_free(&t);
	if (rc)
		return -1;

	uint8_t sync[4] = {1, 0, 0xea, 0x03};
	uint8_t coop[8] = {CTRL_COOPERATE, 0};
	uint8_t req[8] = {CTRL_REQUEST, 0};
	uint8_t fonts[8] = {0, 0, 0, 0, 3, 0, 0x32, 0};
	return send_data(&r->s, PDU2_SYNC, sync, 4) ||
	       send_data(&r->s, PDU2_CONTROL, coop, 8) ||
	       send_data(&r->s, PDU2_CONTROL, req, 8) ||
	       send_data(&r->s, PDU2_FONTLIST, fonts, 8);
}

static int demand_active(rdp *r, buf *b)
{
	r->s.share_id = r_u32(b);
	uint16_t lsrc = r_u16(b);
	r_u16(b);
	r_skip(b, lsrc);
	uint16_t n = r_u16(b);
	r_u16(b);
	int w = opt.w, h = opt.h, bpp = 32;
	for (int i = 0; i < n && !b->err; i++) {
		size_t start = b->pos;
		uint16_t type = r_u16(b), len = r_u16(b);
		if (len < 4)
			break;
		if (type == CAP_BITMAP) {
			bpp = r_u16(b);
			r_skip(b, 6);
			w = r_u16(b);
			h = r_u16(b);
		}
		b->pos = start + len;
	}
	msg("server desktop %dx%d, %d bpp", w, h, bpp);
	if (bpp != 32)
		msg("warning: only 32 bpp is implemented");
	if (x_window(w, h))
		return -1;
	if (!r->clip && r->nchan)
		r->clip = clip_new(x.dpy, 0, clip_send, r);
	return send_confirm_active(r);
}

/* ---- updates --------------------------------------------------------- */

static void blit(const uint32_t *src, int sw, int l, int t, int cw, int ch)
{
	for (int y = 0; y < ch; y++) {
		int dy = t + y;
		if (dy < 0 || dy >= x.h)
			continue;
		for (int c = 0; c < cw; c++) {
			int dx = l + c;
			if (dx >= 0 && dx < x.w)
				x.fb[(size_t)dy * x.w + dx] = src[(size_t)y * sw + c] & 0xffffff;
		}
	}
}

static void gfx_paint(void *arg, int l, int t, int w, int h, const uint32_t *px, int stride)
{
	blit(px, stride, l, t, w, h);
	dirty(l, t, l + w, t + h);
}

static void gfx_reset(void *arg, int w, int h)
{
	if (w != x.w || h != x.h)
		x_window(w, h);
}

static void bitmap_update(buf *b)
{
	static uint32_t *tmp;
	static size_t tmpn;
	uint16_t n = r_u16(b);
	for (int i = 0; i < n && !b->err; i++) {
		int l = r_u16(b), t = r_u16(b), rr = r_u16(b), bb = r_u16(b);
		int w = r_u16(b), h = r_u16(b), bpp = r_u16(b), flags = r_u16(b);
		int len = r_u16(b);
		const uint8_t *p = r_bytes(b, len); /* includes the compression header */
		if (!p || !w || !h)
			return;
		int cw = rr - l + 1, ch = bb - t + 1;
		if (cw > w) cw = w;
		if (ch > h) ch = h;
		if (cw <= 0 || ch <= 0)
			continue;
		if ((size_t)w * h > tmpn) {
			tmpn = (size_t)w * h;
			tmp = realloc(tmp, tmpn * 4);
		}
		if (flags & 0x0001) {
			if (!(flags & 0x0400)) {
				if (len < 8)
					continue;
				p += 8;
				len -= 8;
			}
			if (bpp != 32) {
				dbg("interleaved RLE (bpp %d) not supported yet", bpp);
				continue;
			}
			if (planar_decode(p, len, w, h, 1, tmp, w)) {
				dbg("bad planar bitmap %dx%d", w, h);
				continue;
			}
		} else {
			int bytespp = (bpp + 7) / 8;
			int stride = (w * bytespp + 3) & ~3;
			if ((bpp != 32 && bpp != 24) || (size_t)stride * h > (size_t)len) {
				dbg("raw bitmap bpp %d unsupported", bpp);
				continue;
			}
			for (int y = 0; y < h; y++) {
				const uint8_t *src = p + (size_t)(h - 1 - y) * stride;
				for (int c = 0; c < w; c++) {
					const uint8_t *q = src + c * bytespp;
					tmp[(size_t)y * w + c] = q[0] | q[1] << 8 | q[2] << 16;
				}
			}
		}
		blit(tmp, w, l, t, cw, ch);
		dirty(l, t, rr + 1, bb + 1);
	}
}

static Cursor make_cursor(int xorbpp, buf *b)
{
	uint16_t idx = r_u16(b);
	uint16_t hx = r_u16(b), hy = r_u16(b), w = r_u16(b), h = r_u16(b);
	uint16_t andlen = r_u16(b), xorlen = r_u16(b);
	const uint8_t *xm = r_bytes(b, xorlen), *am = r_bytes(b, andlen);
	if (!xm || !w || !h || idx >= 32)
		return None;
	int xstride = ((w * xorbpp + 15) / 16) * 2;
	int astride = ((w + 15) / 16) * 2;
	if ((size_t)xstride * h > xorlen)
		return None;
	XcursorImage *ci = XcursorImageCreate(w, h);
	ci->xhot = hx < w ? hx : 0;
	ci->yhot = hy < h ? hy : 0;
	int has_alpha = 0;
	if (xorbpp == 32)
		for (int i = 0; i < w * h && !has_alpha; i++)
			has_alpha = xm[(i / w) * xstride + (i % w) * 4 + 3] != 0;
	for (int y = 0; y < h; y++) {
		const uint8_t *row = xm + (size_t)(h - 1 - y) * xstride;
		const uint8_t *arow = am && andlen >= (size_t)astride * h ? am + (size_t)(h - 1 - y) * astride : NULL;
		for (int c = 0; c < w; c++) {
			uint32_t bb, g, rr, a;
			if (xorbpp == 32) {
				bb = row[c * 4]; g = row[c * 4 + 1]; rr = row[c * 4 + 2]; a = row[c * 4 + 3];
			} else if (xorbpp == 24) {
				bb = row[c * 3]; g = row[c * 3 + 1]; rr = row[c * 3 + 2]; a = 255;
			} else { /* 1 bpp */
				int bit = row[c / 8] >> (7 - c % 8) & 1;
				bb = g = rr = bit ? 255 : 0;
				a = 255;
			}
			if (!has_alpha) {
				int andbit = arow ? arow[c / 8] >> (7 - c % 8) & 1 : 0;
				if (andbit)
					a = (bb | g | rr) ? 255 : 0; /* invert: approximate black */
				if (andbit && a)
					bb = g = rr = 0;
				if (xorbpp == 32 && !andbit)
					a = 255;
			}
			ci->pixels[y * w + c] = a << 24 | (rr * a / 255) << 16 | (g * a / 255) << 8 | (bb * a / 255);
		}
	}
	Cursor cur = XcursorImageLoadCursor(x.dpy, ci);
	XcursorImageDestroy(ci);
	if (x.cache[idx])
		XFreeCursor(x.dpy, x.cache[idx]);
	x.cache[idx] = cur;
	return cur;
}

static void pointer_update(int code, buf *b)
{
	if (!x.win)
		return;
	Cursor c = None;
	switch (code) {
	case FP_UPD_PTR_NULL:
		XDefineCursor(x.dpy, x.win, x.blank);
		return;
	case FP_UPD_PTR_DEFAULT:
		XUndefineCursor(x.dpy, x.win);
		return;
	case FP_UPD_PTR_POSITION:
		return;
	case FP_UPD_COLOR:
		c = make_cursor(24, b);
		break;
	case FP_UPD_POINTER: {
		int bpp = r_u16(b);
		c = make_cursor(bpp, b);
		break;
	}
	case FP_UPD_CACHED: {
		uint16_t i = r_u16(b);
		c = i < 32 ? x.cache[i] : None;
		break;
	}
	}
	if (c)
		XDefineCursor(x.dpy, x.win, c);
}

static void on_fp_update(rdp *r, int code, buf *b)
{
	(void)r;
	switch (code) {
	case FP_UPD_BITMAP:
		r_u16(b); /* updateType */
		bitmap_update(b);
		break;
	case FP_UPD_PTR_NULL: case FP_UPD_PTR_DEFAULT: case FP_UPD_PTR_POSITION:
	case FP_UPD_COLOR: case FP_UPD_CACHED: case FP_UPD_POINTER:
		pointer_update(code, b);
		break;
	default:
		dbg("fast-path update %d ignored", code);
	}
}

static void fastpath(rdp *r, buf *b)
{
	b->pos = 1;
	if (r_u8(b) & 0x80)
		r_u8(b);
	while (r_left(b) >= 3) {
		uint8_t h = r_u8(b);
		int code = h & 0xf, frag = h >> 4 & 3, comp = h >> 6 & 3;
		if (comp & 2) {
			r_u8(b);
			msg("bulk-compressed fast-path update not supported");
		}
		uint16_t size = r_u16(b);
		const uint8_t *p = r_bytes(b, size);
		if (!p)
			return;
		if (frag == FP_FRAG_SINGLE) {
			buf u = {.p = (uint8_t *)p, .len = size};
			on_fp_update(r, code, &u);
		} else {
			if (frag == FP_FRAG_FIRST) {
				b_reset(&r->frag);
				r->frag_code = code;
			}
			w_bytes(&r->frag, p, size);
			if (frag == FP_FRAG_LAST) {
				r->frag.pos = 0;
				on_fp_update(r, r->frag_code, &r->frag);
				b_reset(&r->frag);
			}
		}
	}
}

static int slowpath(rdp *r, buf *b)
{
	uint16_t u, c;
	int t = parse_mcs(b, &u, &c);
	if (t == MCS_DPUM) {
		msg("server disconnected");
		return -1;
	}
	if (t == MCS_SDIN && r->nchan > CHAN_CLIPRDR && c == r->chan_id[CHAN_CLIPRDR]) {
		if (r->clip && vc_recv(&r->cliprdr_acc, b))
			return clip_recv(r->clip, &r->cliprdr_acc) < 0 ? -1 : 0;
		return 0;
	}
	if (t == MCS_SDIN && r->nchan > CHAN_DRDYNVC && c == r->chan_id[CHAN_DRDYNVC]) {
		if (r->gfx && vc_recv(&r->drdynvc_acc, b))
			return gfxc_recv(r->gfx, &r->drdynvc_acc) < 0 ? -1 : 0;
		return 0;
	}
	if (t != MCS_SDIN || c != r->io)
		return 0;
	if (!r->licensed) {
		size_t at = b->pos;
		uint16_t flags = r_u16(b);
		r_u16(b);
		if (flags & SEC_LICENSE_PKT) {
			uint8_t type = r_u8(b);
			r_u8(b);
			r_u16(b);
			if (type == 0xff) {
				uint32_t code = r_u32(b);
				dbg("license: error alert %u (7 = valid client)", code);
				if (code == 7)
					r->licensed = 1;
				else
					msg("license error %u", code);
			} else {
				msg("license message 0x%02x: license negotiation not implemented", type);
				return -1;
			}
			return 0;
		}
		b->pos = at;
	}
	uint8_t type2 = 0;
	int type = parse_share(b, &type2);
	if (type == PDU_DEMAND_ACTIVE) {
		r->licensed = 1;
		if (demand_active(r, b))
			return -1;
		r->active = 1;
		return 0;
	}
	if (type == PDU_DEACTIVATE_ALL) {
		dbg("deactivate all");
		r->active = 0;
		return 0;
	}
	if (type != PDU_DATA)
		return 0;
	switch (type2) {
	case PDU2_UPDATE: {
		uint16_t ut = r_u16(b);
		if (ut == 1) {
			bitmap_update(b);
		} else if (ut == 3) {
			dbg("server synchronize");
		}
		break;
	}
	case PDU2_POINTER: {
		uint16_t mt = r_u16(b);
		r_u16(b);
		if (mt == 1) {
			uint32_t sys = r_u32(b);
			pointer_update(sys == 0 ? FP_UPD_PTR_NULL : FP_UPD_PTR_DEFAULT, b);
		} else if (mt == 6) {
			pointer_update(FP_UPD_COLOR, b);
		} else if (mt == 7) {
			pointer_update(FP_UPD_CACHED, b);
		} else if (mt == 8) {
			pointer_update(FP_UPD_POINTER, b);
		}
		break;
	}
	case PDU2_SET_ERROR_INFO: {
		uint32_t e = r_u32(b);
		if (e)
			msg("server error info 0x%x", e);
		break;
	}
	case PDU2_FONTMAP:
		msg("connected");
		if (opt.type) {
			buf u;
			b_init(&u, 64);
			w_utf16(&u, opt.type, 0);
			for (size_t i = 0; i + 1 < u.len; i += 2) {
				for (int rel = 0; rel < 2; rel++) {
					uint8_t ev[3] = {FP_IN_UNICODE << 5 | (rel ? KBD_RELEASE : 0), u.p[i], u.p[i + 1]};
					uint8_t pdu[5] = {1 << 2, 5, ev[0], ev[1], ev[2]};
					if (c_write(&r->c, pdu, 5))
						return -1;
				}
			}
			b_free(&u);
		}
		break;
	default:
		dbg("data pdu 0x%02x", type2);
	}
	return 0;
}

/* ---- input ---------------------------------------------------------- */

static int send_input(rdp *r, const uint8_t *ev, size_t n)
{
	uint8_t p[32];
	p[0] = 1 << 2; /* one event */
	p[1] = n + 2;
	memcpy(p + 2, ev, n);
	return c_write(&r->c, p, n + 2);
}

static int mouse(rdp *r, uint16_t flags, int mx, int my)
{
	if (mx < 0) mx = 0;
	if (my < 0) my = 0;
	if (mx >= x.w) mx = x.w - 1;
	if (my >= x.h) my = x.h - 1;
	uint8_t ev[7] = {FP_IN_MOUSE << 5, flags, flags >> 8, mx, mx >> 8, my, my >> 8};
	return send_input(r, ev, 7);
}

static int x_events(rdp *r)
{
	while (XPending(x.dpy)) {
		XEvent e;
		XNextEvent(x.dpy, &e);
		if (clip_x_event(r->clip, &e) || !r->active)
			continue;
		switch (e.type) {
		case Expose:
			dirty(e.xexpose.x, e.xexpose.y, e.xexpose.x + e.xexpose.width,
			      e.xexpose.y + e.xexpose.height);
			break;
		case KeyPress:
		case KeyRelease: {
			/* skip autorepeat releases: X sends Release+Press pairs */
			if (e.type == KeyRelease && XEventsQueued(x.dpy, QueuedAfterReading)) {
				XEvent nx;
				XPeekEvent(x.dpy, &nx);
				if (nx.type == KeyPress && nx.xkey.time == e.xkey.time &&
				    nx.xkey.keycode == e.xkey.keycode)
					break;
			}
			int ext, sc = evdev_to_sc(e.xkey.keycode - 8, &ext);
			if (!sc) {
				dbg("unmapped keycode %u", e.xkey.keycode);
				break;
			}
			uint8_t ev[2] = {FP_IN_SCANCODE << 5 | (e.type == KeyRelease ? KBD_RELEASE : 0) |
					 (ext ? KBD_EXTENDED : 0), sc};
			if (send_input(r, ev, 2))
				return -1;
			break;
		}
		case MotionNotify: {
			/* coalesce */
			while (XCheckTypedWindowEvent(x.dpy, x.win, MotionNotify, &e))
				;
			if (mouse(r, PTR_MOVE, e.xmotion.x, e.xmotion.y))
				return -1;
			break;
		}
		case ButtonPress:
		case ButtonRelease: {
			int down = e.type == ButtonPress, b = e.xbutton.button;
			uint16_t f = 0;
			if (b == 1) f = PTR_BUTTON1;
			else if (b == 3) f = PTR_BUTTON2;
			else if (b == 2) f = PTR_BUTTON3;
			else if (b == 4 || b == 5) {
				if (!down) break;
				f = PTR_WHEEL | (b == 4 ? 120 : (PTR_WHEEL_NEG | (0x100 - 120)));
				if (mouse(r, f, e.xbutton.x, e.xbutton.y))
					return -1;
				break;
			} else if (b == 6 || b == 7) {
				if (!down) break;
				f = PTR_HWHEEL | (b == 7 ? 120 : (PTR_WHEEL_NEG | (0x100 - 120)));
				if (mouse(r, f, e.xbutton.x, e.xbutton.y))
					return -1;
				break;
			} else if (b == 8 || b == 9) {
				uint16_t xf = (b == 8 ? PTRX_BUTTON1 : PTRX_BUTTON2) | (down ? PTRX_DOWN : 0);
				int mx = e.xbutton.x, my = e.xbutton.y;
				uint8_t ev[7] = {FP_IN_MOUSEX << 5, xf, xf >> 8, mx, mx >> 8, my, my >> 8};
				if (send_input(r, ev, 7))
					return -1;
				break;
			} else {
				break;
			}
			if (mouse(r, f | (down ? PTR_DOWN : 0), e.xbutton.x, e.xbutton.y))
				return -1;
			break;
		}
		case FocusIn: {
			/* resync lock keys: none on */
			uint8_t ev[1] = {FP_IN_SYNC << 5};
			if (send_input(r, ev, 1))
				return -1;
			break;
		}
		case ClientMessage:
			if ((Atom)e.xclient.data.l[0] == x.wm_delete)
				return -1;
			break;
		}
	}
	return 0;
}

/* ---- main ------------------------------------------------------------- */

static char *read_password(const char *prompt)
{
	static char pw[512];
	struct termios t, o;
	fprintf(stderr, "%s", prompt);
	int tty = tcgetattr(0, &o) == 0;
	if (tty) {
		t = o;
		t.c_lflag &= ~ECHO;
		tcsetattr(0, TCSANOW, &t);
	}
	if (!fgets(pw, sizeof pw, stdin))
		pw[0] = 0;
	if (tty) {
		tcsetattr(0, TCSANOW, &o);
		fputc('\n', stderr);
	}
	pw[strcspn(pw, "\n")] = 0;
	return pw;
}

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static void usage(void)
{
	fprintf(stderr,
		"usage: rdesk-rdpc-client [options] HOST[:PORT]\n"
		"  -u USER          default: $USER\n"
		"  -d DOMAIN\n"
		"  -p PASSWORD      default: $RDP_PASSWORD, else prompt\n"
		"  -g WxH           requested size, default 1280x800\n"
		"  --no-nla         TLS only\n"
		"  --type TEXT      type TEXT as Unicode key events after connecting\n"
		"  --dump FILE.ppm  save the screen after --dump-ms (3000) and exit\n"
		"  -v, -vv          debug log, hex dumps\n");
	exit(2);
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "-u") && i + 1 < argc)
			opt.user = argv[++i];
		else if (!strcmp(a, "-d") && i + 1 < argc)
			opt.domain = argv[++i];
		else if (!strcmp(a, "-p") && i + 1 < argc)
			opt.pass = argv[++i];
		else if (!strcmp(a, "-g") && i + 1 < argc) {
			if (sscanf(argv[++i], "%dx%d", &opt.w, &opt.h) != 2)
				usage();
		} else if (!strcmp(a, "--dump") && i + 1 < argc)
			opt.dump = argv[++i];
		else if (!strcmp(a, "--dump-ms") && i + 1 < argc)
			opt.dump_ms = atoi(argv[++i]);
		else if (!strcmp(a, "--type") && i + 1 < argc)
			opt.type = argv[++i];
		else if (!strcmp(a, "--no-nla"))
			opt.no_nla = 1;
		else if (!strcmp(a, "-v"))
			verbose = 1;
		else if (!strcmp(a, "-vv"))
			verbose = 2;
		else if (a[0] != '-' && !opt.host)
			opt.host = a;
		else
			usage();
	}
	if (!opt.host)
		usage();
	static char host[256];
	snprintf(host, sizeof host, "%s", opt.host);
	char *colon = strrchr(host, ':');
	if (colon && !strchr(host, ']') && colon == strchr(host, ':')) {
		*colon = 0;
		opt.port = colon + 1;
	}
	opt.host = host;
	if (!opt.user) {
		struct passwd *pw = getpwuid(getuid());
		opt.user = getenv("USER") ? getenv("USER") : pw ? pw->pw_name : "user";
	}
	if (!opt.pass)
		opt.pass = getenv("RDP_PASSWORD");
	if (!opt.pass)
		opt.pass = read_password("Password: ");
	signal(SIGPIPE, SIG_IGN);

	rdp r = {0};
	r.s.c = &r.c;
	b_init(&r.frag, 65536);
	b_init(&r.cliprdr_acc, 4096);
	r.c.fd = tcp_connect(opt.host, opt.port);
	if (r.c.fd < 0)
		return 1;
	if (x224_connect(&r) || tls_connect(&r))
		return 1;
	if (selected_protocol == PROTOCOL_HYBRID &&
	    credssp_client(&r.c, opt.user, opt.domain, opt.pass)) {
		msg("NLA failed");
		return 1;
	}
	if (mcs_connect(&r) || mcs_attach(&r) || send_client_info(&r))
		return 1;
	b_init(&r.drdynvc_acc, 4096);
	if (r.nchan > CHAN_DRDYNVC && !gfx_off()) {
		gfxc_ops ops = {&r, dvc_send, gfx_paint, gfx_reset};
		r.gfx = gfxc_new(&ops);
	}

	buf b;
	b_init(&b, 65536);
	int64_t dump_at = opt.dump ? now_ms() + opt.dump_ms : 0;
	int rc = 0;
	for (;;) {
		if (x.dpy && x_events(&r))
			break;
		if (c_pending(&r.c) == 0) {
			present();
			struct pollfd p[2] = {{r.c.fd, POLLIN, 0}, {x.dpy ? ConnectionNumber(x.dpy) : -1, POLLIN, 0}};
			int to = dump_at ? (int)(dump_at - now_ms()) : -1;
			if (dump_at && to <= 0) {
				dump_ppm();
				break;
			}
			if (poll(p, 2, to) < 0 && errno != EINTR)
				break;
			if (!(p[0].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;
		}
		int fp;
		if (read_pdu(&r.c, &b, &fp)) {
			msg("connection closed");
			rc = 1;
			break;
		}
		if (fp)
			fastpath(&r, &b);
		else if (slowpath(&r, &b)) {
			rc = 1;
			break;
		}
	}
	static const uint8_t dpum[] = {MCS_DPUM << 2 | 1, 0x80};
	send_x224(&r, dpum, sizeof dpum);
	if (r.c.ssl)
		SSL_shutdown(r.c.ssl);
	close(r.c.fd);
	return rc;
}
