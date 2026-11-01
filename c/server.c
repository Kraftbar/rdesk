/* server.c - rdesk-rdpc: RDP server mirroring the live X11 desktop.
 *
 * Milestone 1: TLS security, slow-path connection sequence, raw 32 bpp
 * fast-path bitmap updates of changed 64x64 tiles, fast-path input via
 * XTest, XFixes cursor shapes. One client at a time. DAMAGE says which
 * tiles were drawn to; only those rows are grabbed and compared. */
#define _GNU_SOURCE
#include "rdp.h"
#include "nla.h"
#include "clip.h"
#include "planar.h"

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/XKBlib.h>
#include <X11/keysym.h>
#include <termios.h>
#include <X11/extensions/XShm.h>
#include <X11/extensions/Xfixes.h>
#include <X11/extensions/Xdamage.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* libXtst ships without headers here; the three calls we need. */
extern int XTestFakeKeyEvent(Display *, unsigned int, Bool, unsigned long);
extern int XTestFakeButtonEvent(Display *, unsigned int, Bool, unsigned long);
extern int XTestFakeMotionEvent(Display *, int, int, int, unsigned long);

#define TILE 64
#define OUTQ_MAX (512 * 1024) /* skip frames while this much is unsent */
#define MAX_POINTER 96

static struct {
	const char *bind;
	int port;
	int fps;
	const char *pass;
	char certdir[512];
	int no_nla;
} opt = {"0.0.0.0", 3390, 30, NULL, "", 0};

static char nthash_path[600];

/* RDESK_OFF=clip,cursor,frames: switch parts off (diagnostics). */
static int off(const char *what)
{
	const char *e = getenv("RDESK_OFF");
	return e && strstr(e, what);
}

/* NT hash for NLA: --pass, else the stored one. 0 when available. */
static int get_nthash(uint8_t h[16])
{
	if (opt.no_nla)
		return -1;
	if (opt.pass) {
		nt_hash(opt.pass, h);
		return 0;
	}
	return read_nthash(nthash_path, h);
}

/* ---- X11 ------------------------------------------------------------ */

static struct {
	Display *dpy;
	Window root;
	int w, h;
	XImage *img;
	XShmSegmentInfo shm;
	uint8_t *prev;   /* last frame sent, same stride as img */
	int fixes_ev;
	Damage damage;   /* 0: no DAMAGE, every tile is dirty every frame */
	XserverRegion region;
	int damage_ev, damaged;
	uint8_t *dirty;  /* per tile, tw x th */
	int tw, th;
} x;

static int x_open(void)
{
	x.dpy = XOpenDisplay(NULL);
	if (!x.dpy) {
		msg("cannot open display %s", getenv("DISPLAY") ? getenv("DISPLAY") : "(unset)");
		return -1;
	}
	x.root = DefaultRootWindow(x.dpy);
	int err;
	if (!XShmQueryExtension(x.dpy)) {
		msg("no MIT-SHM");
		return -1;
	}
	if (!XFixesQueryExtension(x.dpy, &x.fixes_ev, &err)) {
		msg("no XFIXES");
		return -1;
	}
	XFixesSelectCursorInput(x.dpy, x.root, XFixesDisplayCursorNotifyMask);
	if (!off("damage") && XDamageQueryExtension(x.dpy, &x.damage_ev, &err)) {
		x.damage = XDamageCreate(x.dpy, x.root, XDamageReportNonEmpty);
		x.region = XFixesCreateRegion(x.dpy, NULL, 0);
	} else {
		msg("no DAMAGE: grabbing whole frames");
	}
	return 0;
}

static void x_free_image(void)
{
	if (!x.img)
		return;
	XShmDetach(x.dpy, &x.shm);
	XDestroyImage(x.img);
	shmdt(x.shm.shmaddr);
	x.img = NULL;
	free(x.prev);
	x.prev = NULL;
	free(x.dirty);
	x.dirty = NULL;
}

static int x_alloc_image(void)
{
	XWindowAttributes wa;
	XGetWindowAttributes(x.dpy, x.root, &wa);
	x_free_image();
	x.w = wa.width;
	x.h = wa.height;
	x.img = XShmCreateImage(x.dpy, wa.visual, wa.depth, ZPixmap, NULL, &x.shm, x.w, x.h);
	if (!x.img || x.img->bits_per_pixel != 32) {
		msg("need a 32 bpp ZPixmap visual");
		return -1;
	}
	x.shm.shmid = shmget(IPC_PRIVATE, (size_t)x.img->bytes_per_line * x.h, IPC_CREAT | 0600);
	x.shm.shmaddr = x.img->data = shmat(x.shm.shmid, NULL, 0);
	shmctl(x.shm.shmid, IPC_RMID, NULL);
	x.shm.readOnly = False;
	XShmAttach(x.dpy, &x.shm);
	x.prev = calloc(1, (size_t)x.img->bytes_per_line * x.h);
	x.tw = (x.w + TILE - 1) / TILE;
	x.th = (x.h + TILE - 1) / TILE;
	x.dirty = malloc(x.tw * x.th);
	memset(x.dirty, 1, x.tw * x.th);
	XSync(x.dpy, False);
	return 0;
}

static int ctrl_down;
static int numpad_remap[2]; /* keycode numpad +/- were sent as, for the release */

static int keysym_code(KeySym ks, int *shift)
{
	KeyCode kc = XKeysymToKeycode(x.dpy, ks);
	if (kc && shift)
		*shift = XkbKeycodeToKeysym(x.dpy, kc, 0, 0) != ks;
	return kc;
}

static void in_key(uint8_t code, int flags)
{
	int down = !(flags & KBD_RELEASE), ext = flags & KBD_EXTENDED;
	if (code == 0x1d)
		ctrl_down = down;
	/* iOS Windows app: Ctrl + "+"/"-" arrive as Ctrl + numpad plus/minus,
	 * which browsers ignore for zoom; send the layout's main-row keys. */
	if (!ext && (code == 0x4e || code == 0x4a)) {
		int i = code == 0x4e, shift = 0, kc = 0;
		if (down && ctrl_down) {
			kc = keysym_code(i ? XK_plus : XK_minus, &shift);
			if (shift)
				kc = 0;
			numpad_remap[i] = kc;
		} else if (!down) {
			kc = numpad_remap[i];
			numpad_remap[i] = 0;
		}
		if (kc) {
			XTestFakeKeyEvent(x.dpy, kc, down, 0);
			return;
		}
	}
	int ev = sc_to_evdev(code, ext), kc = ev ? ev + 8 : 0;
	if (!kc) {
		dbg("unmapped scancode 0x%02x ext %d", code, !!ext);
		return;
	}
	XTestFakeKeyEvent(x.dpy, kc, down, 0);
}

/* A keycode with no keysyms, bound on the fly to characters the layout
 * lacks (emoji etc.), the way xdotool types them. */
static int spare_kc = -1;
static KeySym spare_bound;

static int bind_spare(KeySym ks)
{
	if (spare_kc < 0) {
		int min, max, per;
		XDisplayKeycodes(x.dpy, &min, &max);
		KeySym *m = XGetKeyboardMapping(x.dpy, min, max - min + 1, &per);
		spare_kc = 0;
		for (int kc = max; kc >= min && m; kc--) {
			int empty = 1;
			for (int j = 0; j < per; j++)
				empty &= m[(kc - min) * per + j] == NoSymbol;
			if (empty) {
				spare_kc = kc;
				break;
			}
		}
		if (m)
			XFree(m);
	}
	if (!spare_kc)
		return 0;
	if (spare_bound != ks) {
		KeySym syms[2] = {ks, ks};
		XChangeKeyboardMapping(x.dpy, spare_kc, 2, syms, 1);
		XSync(x.dpy, False);
		spare_bound = ks;
		usleep(20000); /* let clients pick up the MappingNotify */
	}
	return spare_kc;
}

/* Unicode key (on-screen keyboards): type through the layout, Shift if the
 * keysym sits in the shifted column, else via the spare keycode. */
static void in_unicode(uint16_t u, int release)
{
	KeySym ks = u >= 0x20 && u <= 0xff ? u : 0x01000000 | u;
	int shift = 0, kc = keysym_code(ks, &shift);
	if (!kc) {
		shift = 0;
		kc = bind_spare(ks);
	}
	if (!kc) {
		dbg("no keycode for U+%04x", u);
		return;
	}
	if (shift && !release)
		XTestFakeKeyEvent(x.dpy, 50, True, 0);
	XTestFakeKeyEvent(x.dpy, kc, !release, 0);
	if (shift && release)
		XTestFakeKeyEvent(x.dpy, 50, False, 0);
}

static void click(int button, int n)
{
	for (int i = 0; i < (n < 1 ? 1 : n); i++) {
		XTestFakeButtonEvent(x.dpy, button, True, 0);
		XTestFakeButtonEvent(x.dpy, button, False, 0);
	}
}

static void in_mouse(uint16_t f, uint16_t mx, uint16_t my)
{
	if (f & (PTR_WHEEL | PTR_HWHEEL)) {
		int rot = f & 0xff;
		if (f & PTR_WHEEL_NEG)
			rot = -(0x100 - rot);
		int n = abs(rot) / 120;
		if (f & PTR_WHEEL)
			click(rot > 0 ? 4 : 5, n);
		else
			click(rot > 0 ? 7 : 6, n);
		return;
	}
	if (f & PTR_MOVE || f & (PTR_BUTTON1 | PTR_BUTTON2 | PTR_BUTTON3))
		XTestFakeMotionEvent(x.dpy, -1, mx, my, 0);
	int down = !!(f & PTR_DOWN);
	if (f & PTR_BUTTON1)
		XTestFakeButtonEvent(x.dpy, 1, down, 0);
	if (f & PTR_BUTTON2)
		XTestFakeButtonEvent(x.dpy, 3, down, 0);
	if (f & PTR_BUTTON3)
		XTestFakeButtonEvent(x.dpy, 2, down, 0);
}

static void in_mousex(uint16_t f, uint16_t mx, uint16_t my)
{
	XTestFakeMotionEvent(x.dpy, -1, mx, my, 0);
	int down = !!(f & PTRX_DOWN);
	if (f & PTRX_BUTTON1)
		XTestFakeButtonEvent(x.dpy, 8, down, 0);
	if (f & PTRX_BUTTON2)
		XTestFakeButtonEvent(x.dpy, 9, down, 0);
}

/* ---- certificate / TLS ---------------------------------------------- */

static int ensure_cert(char *certp, char *keyp, size_t n)
{
	snprintf(certp, n, "%s/cert.pem", opt.certdir);
	snprintf(keyp, n, "%s/key.pem", opt.certdir);
	if (access(certp, R_OK) == 0 && access(keyp, R_OK) == 0)
		return 0;
	mkdir(opt.certdir, 0700);
	EVP_PKEY *pk = EVP_RSA_gen(2048);
	X509 *c = X509_new();
	X509_set_version(c, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(c), time(NULL));
	X509_gmtime_adj(X509_getm_notBefore(c), 0);
	X509_gmtime_adj(X509_getm_notAfter(c), 10L * 365 * 86400);
	X509_set_pubkey(c, pk);
	X509_NAME *nm = X509_get_subject_name(c);
	X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"rdesk", -1, -1, 0);
	X509_set_issuer_name(c, nm);
	X509_sign(c, pk, EVP_sha256());
	FILE *f = fopen(keyp, "w");
	if (!f)
		return -1;
	fchmod(fileno(f), 0600);
	PEM_write_PrivateKey(f, pk, NULL, NULL, 0, NULL, NULL);
	fclose(f);
	f = fopen(certp, "w");
	if (!f)
		return -1;
	PEM_write_X509(f, c);
	fclose(f);
	X509_free(c);
	EVP_PKEY_free(pk);
	msg("wrote self-signed certificate %s", certp);
	return 0;
}

static SSL_CTX *tls_ctx(void)
{
	char certp[600], keyp[600];
	if (ensure_cert(certp, keyp, sizeof certp))
		return NULL;
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
	if (SSL_CTX_use_certificate_file(ctx, certp, SSL_FILETYPE_PEM) != 1 ||
	    SSL_CTX_use_PrivateKey_file(ctx, keyp, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	return ctx;
}

/* ---- login ---------------------------------------------------------- */

static int check_password(const char *user, const char *pass)
{
	struct passwd *pw = getpwuid(getuid());
	const char *me = pw ? pw->pw_name : "";
	const char *u = strrchr(user, '\\');
	u = u ? u + 1 : user;
	if (opt.pass)
		return strcmp(pass, opt.pass) == 0;
	if (strcasecmp(u, me) != 0) {
		msg("login as '%s' refused: server runs as '%s'", u, me);
		return 0;
	}
	if (!*pass) {
		msg("no password in client info (mstsc sends only a saved one without NLA)");
		return 0;
	}
	int fd[2];
	if (pipe(fd))
		return 0;
	pid_t pid = fork();
	if (pid == 0) {
		dup2(fd[0], 0);
		close(fd[0]);
		close(fd[1]);
		execl("/sbin/unix_chkpwd", "unix_chkpwd", me, "nullok", (char *)NULL);
		_exit(127);
	}
	close(fd[0]);
	(void)!write(fd[1], pass, strlen(pass) + 1);
	close(fd[1]);
	int st = 0;
	waitpid(pid, &st, 0);
	int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
	if (ok && write_nthash(nthash_path, pass) == 1)
		msg("stored NT hash in %s: NLA enabled", nthash_path);
	return ok;
}

/* ---- connection state ------------------------------------------------ */

#define MAX_CHANNELS 31

typedef struct {
	conn c;
	session s;
	uint16_t user;          /* client's MCS user id */
	uint32_t req_protocols;
	uint32_t selected;
	int nla_ok;
	uint16_t cw, ch;        /* client desktop size request */
	int nchan;
	char chan_name[MAX_CHANNELS][9];
	uint32_t max_request;   /* multifragment max size from client */
	int fastpath_out;
	int suppress;           /* suppress output (minimized) */
	int full;               /* send every tile next frame */
	int cursor_dirty;
	char username[256];
	uint16_t cliprdr;       /* channel id, 0 if not offered */
	buf cliprdr_acc;
	clip *clip;
} client;

static int clip_send(void *arg, const uint8_t *p, size_t n)
{
	client *cl = arg;
	return vc_send(&cl->c, 1, cl->s.user, cl->cliprdr, p, n);
}

static buf out; /* batched fast-path output */

static int flush_out(client *cl)
{
	if (!out.len)
		return 0;
	int r = c_write(&cl->c, out.p, out.len);
	b_reset(&out);
	return r;
}

/* ---- connection sequence -------------------------------------------- */

static int x224_connect(client *cl, buf *b)
{
	int fp;
	if (read_pdu(&cl->c, b, &fp) || fp)
		return -1;
	b->pos = 4;
	uint8_t li = r_u8(b);
	uint8_t code = r_u8(b);
	if ((code & 0xf0) != 0xe0 || li + 5u > b->len) {
		msg("not an X.224 connection request");
		return -1;
	}
	size_t end = 5 + li;
	b->pos = 11;
	/* optional cookie / routing token, terminated by CRLF */
	const uint8_t *p = b->p + b->pos;
	size_t n = end - b->pos;
	if (n >= 2 && (p[0] == 'C' || p[0] == 'T')) {
		for (size_t i = 0; i + 1 < n; i++) {
			if (p[i] == '\r' && p[i + 1] == '\n') {
				dbg("cookie: %.*s", (int)i, p);
				b->pos += i + 2;
				break;
			}
		}
	}
	cl->req_protocols = 0;
	if (end - b->pos >= 8 && r_u8(b) == 1) {
		r_u8(b);
		r_u16(b);
		cl->req_protocols = r_u32(b);
	}
	msg("client requested protocols 0x%x", cl->req_protocols);

	buf o;
	b_init(&o, 32);
	w_bytes(&o, "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00", 11);
	uint8_t h[16];
	int have_hash = get_nthash(h) == 0;
	cl->selected = (cl->req_protocols & PROTOCOL_HYBRID) && have_hash ? PROTOCOL_HYBRID
		       : cl->req_protocols & PROTOCOL_SSL ? PROTOCOL_SSL : 0;
	int ok = cl->selected != 0;
	if (ok) {
		w_u8(&o, 2);    /* TYPE_RDP_NEG_RSP */
		w_u8(&o, 0x01); /* EXTENDED_CLIENT_DATA_SUPPORTED */
		w_u16(&o, 8);
		w_u32(&o, cl->selected);
	} else {
		w_u8(&o, 3); /* TYPE_RDP_NEG_FAILURE */
		w_u8(&o, 0);
		w_u16(&o, 8);
		w_u32(&o, 1); /* SSL_REQUIRED_BY_SERVER */
	}
	int r = c_write(&cl->c, o.p, o.len);
	b_free(&o);
	if (!ok) {
		msg("client offers neither TLS nor NLA we can do (NLA needs %s or --pass)", nthash_path);
		return -1;
	}
	return r;
}

static int parse_gcc_client(client *cl, buf *b)
{
	/* find the H.221 key "Duca", then the PER length of the user data */
	const uint8_t *p = b->p + b->pos;
	size_t n = r_left(b), i;
	for (i = 0; i + 4 <= n; i++)
		if (!memcmp(p + i, "Duca", 4))
			break;
	if (i + 4 > n)
		return -1;
	b->pos += i + 4;
	size_t ulen = r_per_len(b);
	if (r_left(b) < ulen)
		return -1;
	size_t end = b->pos + ulen;
	while (b->pos + 4 <= end) {
		size_t start = b->pos;
		uint16_t type = r_u16(b), len = r_u16(b);
		if (len < 4 || start + len > end)
			return -1;
		buf blk = {.p = b->p + start + 4, .len = len - 4};
		if (type == 0xc001) { /* CS_CORE */
			r_u32(&blk);
			cl->cw = r_u16(&blk);
			cl->ch = r_u16(&blk);
			r_skip(&blk, 2 + 2 + 4 + 4);
			char name[40];
			r_utf16(&blk, 32, name, sizeof name);
			r_skip(&blk, 12 + 64);
			r_skip(&blk, 2 + 2 + 4);
			uint16_t high = r_u16(&blk), supported = r_u16(&blk), early = r_u16(&blk);
			msg("client '%s' %ux%u highColor %u supported 0x%x early 0x%x", name,
			    cl->cw, cl->ch, high, supported, early);
			if (!blk.err && !(early & 0x0002))
				msg("warning: client does not ask for a 32 bpp session");
		} else if (type == 0xc003) { /* CS_NET */
			uint32_t cnt = r_u32(&blk);
			for (uint32_t k = 0; k < cnt && cl->nchan < MAX_CHANNELS; k++) {
				const uint8_t *nm = r_bytes(&blk, 8);
				r_u32(&blk);
				if (!nm)
					break;
				memcpy(cl->chan_name[cl->nchan], nm, 8);
				cl->chan_name[cl->nchan][8] = 0;
				dbg("static channel %d: %s", 1004 + cl->nchan, cl->chan_name[cl->nchan]);
				if (!strcmp(cl->chan_name[cl->nchan], "cliprdr"))
					cl->cliprdr = 1004 + cl->nchan;
				cl->nchan++;
			}
		}
		b->pos = start + len;
	}
	return 0;
}

static int mcs_connect(client *cl, buf *b)
{
	int fp;
	if (read_pdu(&cl->c, b, &fp) || fp)
		return -1;
	b->pos = 7;
	size_t n;
	if (r_ber_tag(b, 0x7f65, &n)) {
		msg("not an MCS Connect-Initial");
		return -1;
	}
	/* skip calling/called selector, upward flag, 3 domain parameter sets */
	for (int i = 0; i < 6; i++) {
		r_u8(b);
		if (r_ber_len(b, &n))
			return -1;
		r_skip(b, n);
	}
	if (r_ber_tag(b, 0x04, &n) || r_left(b) < n)
		return -1;
	buf ud = {.p = b->p + b->pos, .len = n};
	if (parse_gcc_client(cl, &ud)) {
		msg("bad GCC conference create request");
		return -1;
	}

	/* server data blocks */
	buf sd;
	b_init(&sd, 64);
	w_u16(&sd, 0x0c01);
	w_u16(&sd, 16);
	w_u32(&sd, 0x00080004);
	w_u32(&sd, cl->req_protocols);
	w_u32(&sd, 0);
	w_u16(&sd, 0x0c02);
	w_u16(&sd, 12);
	w_u32(&sd, 0);
	w_u32(&sd, 0);
	w_u16(&sd, 0x0c03);
	w_u16(&sd, 8 + 2 * cl->nchan + (cl->nchan & 1 ? 2 : 0));
	w_u16(&sd, MCS_IO_CHANNEL);
	w_u16(&sd, cl->nchan);
	for (int i = 0; i < cl->nchan; i++)
		w_u16(&sd, 1004 + i);
	if (cl->nchan & 1)
		w_u16(&sd, 0);

	/* GCC Conference Create Response */
	buf gcc;
	b_init(&gcc, sd.len + 32);
	w_bytes(&gcc, "\x00\x05\x00\x14\x7c\x00\x01", 7);
	w_per_len(&gcc, 14 + (sd.len < 0x80 ? 1 : 2) + sd.len);
	w_bytes(&gcc, "\x14\x76\x0a\x01\x01\x00\x01\xc0\x00McDn", 13);
	w_per_len(&gcc, sd.len);
	w_bytes(&gcc, sd.p, sd.len);

	/* MCS Connect-Response */
	buf body;
	b_init(&body, gcc.len + 64);
	w_bytes(&body, "\x0a\x01\x00\x02\x01\x00", 6);
	static const uint8_t dp[] = {0x30, 0x1a, 0x02, 0x01, 0x22, 0x02, 0x01, 0x03,
				     0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01,
				     0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff,
				     0xf8, 0x02, 0x01, 0x02};
	w_bytes(&body, dp, sizeof dp);
	w_u8(&body, 0x04);
	w_ber_len(&body, gcc.len);
	w_bytes(&body, gcc.p, gcc.len);

	buf o;
	b_init(&o, body.len + 16);
	w_bytes(&o, "\x03\x00\x00\x00\x02\xf0\x80\x7f\x66", 9);
	w_ber_len(&o, body.len);
	w_bytes(&o, body.p, body.len);
	put_u16be(&o, 2, o.len);
	int r = c_write(&cl->c, o.p, o.len);
	b_free(&o);
	b_free(&body);
	b_free(&gcc);
	b_free(&sd);
	return r;
}

static int send_raw_mcs(client *cl, const uint8_t *p, size_t n)
{
	uint8_t h[7] = {3, 0, 0, 0, 2, 0xf0, 0x80};
	h[2] = (n + 7) >> 8;
	h[3] = n + 7;
	uint8_t tmp[64];
	memcpy(tmp, h, 7);
	memcpy(tmp + 7, p, n);
	return c_write(&cl->c, tmp, n + 7);
}

static int send_license(client *cl)
{
	static const uint8_t lic[] = {
		0x80, 0x00, 0x00, 0x00,             /* SEC_LICENSE_PKT */
		0xff, 0x03, 0x10, 0x00,             /* ERROR_ALERT, v3, size 16 */
		0x07, 0x00, 0x00, 0x00,             /* STATUS_VALID_CLIENT */
		0x02, 0x00, 0x00, 0x00,             /* ST_NO_TRANSITION */
		0x04, 0x00, 0x00, 0x00};            /* BB_ERROR_BLOB, empty */
	return send_mcs(&cl->c, 1, cl->s.user, MCS_IO_CHANNEL, lic, sizeof lic);
}

static int send_demand_active(client *cl)
{
	buf caps;
	b_init(&caps, 512);
	int ncaps = 0;

	/* general */
	w_u16(&caps, CAP_GENERAL); w_u16(&caps, 24);
	w_u16(&caps, 1); w_u16(&caps, 3); w_u16(&caps, 0x200); w_u16(&caps, 0);
	w_u16(&caps, 0);
	w_u16(&caps, 0x0001 | 0x0004 | 0x0400); /* FASTPATH_OUTPUT, LONG_CREDENTIALS, NO_BITMAP_COMPRESSION_HDR */
	w_u16(&caps, 0); w_u16(&caps, 0); w_u16(&caps, 0);
	w_u8(&caps, 1); w_u8(&caps, 1);
	ncaps++;

	/* bitmap */
	w_u16(&caps, CAP_BITMAP); w_u16(&caps, 28);
	w_u16(&caps, 32); w_u16(&caps, 1); w_u16(&caps, 1); w_u16(&caps, 1);
	w_u16(&caps, x.w); w_u16(&caps, x.h);
	w_u16(&caps, 0); w_u16(&caps, 1); w_u16(&caps, 1);
	w_u8(&caps, 0); w_u8(&caps, 0);
	w_u16(&caps, 1); w_u16(&caps, 0);
	ncaps++;

	/* order: no orders */
	w_u16(&caps, CAP_ORDER); w_u16(&caps, 88);
	w_zero(&caps, 16 + 4);
	w_u16(&caps, 1); w_u16(&caps, 20); w_u16(&caps, 0);
	w_u16(&caps, 1); w_u16(&caps, 0);
	w_u16(&caps, 0x0002 | 0x0008 | 0x0020);
	w_zero(&caps, 32);
	w_u16(&caps, 0); w_u16(&caps, 0); w_u32(&caps, 0);
	w_u32(&caps, 480 * 480); w_u16(&caps, 0); w_u16(&caps, 0);
	w_u16(&caps, 0); w_u16(&caps, 0);
	ncaps++;

	/* pointer */
	w_u16(&caps, CAP_POINTER); w_u16(&caps, 10);
	w_u16(&caps, 1); w_u16(&caps, 25); w_u16(&caps, 25);
	ncaps++;

	/* input */
	w_u16(&caps, CAP_INPUT); w_u16(&caps, 88);
	w_u16(&caps, 0x0001 | 0x0004 | 0x0008 | 0x0010 | 0x0020);
	w_u16(&caps, 0);
	w_zero(&caps, 16 + 64);
	ncaps++;

	/* virtual channel */
	w_u16(&caps, CAP_VC); w_u16(&caps, 12);
	w_u32(&caps, 0); w_u32(&caps, 1600);
	ncaps++;

	/* share, font */
	w_u16(&caps, CAP_SHARE); w_u16(&caps, 8); w_u16(&caps, 1002); w_u16(&caps, 0);
	ncaps++;
	w_u16(&caps, CAP_FONT); w_u16(&caps, 8); w_u16(&caps, 1); w_u16(&caps, 0);
	ncaps++;

	/* multifragment update */
	w_u16(&caps, CAP_MULTIFRAG); w_u16(&caps, 8); w_u32(&caps, 0x3f0000);
	ncaps++;

	buf b;
	b_init(&b, caps.len + 32);
	w_u32(&b, cl->s.share_id);
	w_u16(&b, 4);
	w_u16(&b, caps.len + 4);
	w_bytes(&b, "RDP", 4);
	w_u16(&b, ncaps);
	w_u16(&b, 0);
	w_bytes(&b, caps.p, caps.len);
	w_u32(&b, 0); /* session id */
	int r = send_share(&cl->s, PDU_DEMAND_ACTIVE, b.p, b.len);
	b_free(&b);
	b_free(&caps);
	return r;
}

static void parse_confirm_active(client *cl, buf *b)
{
	r_u32(b);
	r_u16(b);
	uint16_t lsrc = r_u16(b);
	r_u16(b);
	r_skip(b, lsrc);
	uint16_t n = r_u16(b);
	r_u16(b);
	cl->max_request = 0;
	for (int i = 0; i < n && !b->err; i++) {
		size_t start = b->pos;
		uint16_t type = r_u16(b), len = r_u16(b);
		if (len < 4)
			break;
		buf c = {.p = b->p + start + 4, .len = len - 4};
		switch (type) {
		case CAP_GENERAL:
			r_skip(&c, 10);
			cl->fastpath_out = r_u16(&c) & 1;
			break;
		case CAP_BITMAP: {
			uint16_t bpp = r_u16(&c);
			r_skip(&c, 6);
			uint16_t w = r_u16(&c), h = r_u16(&c);
			msg("client bitmap caps: %u bpp, %ux%u", bpp, w, h);
			break;
		}
		case CAP_MULTIFRAG:
			cl->max_request = r_u32(&c);
			break;
		case CAP_INPUT:
			dbg("client input flags 0x%x", r_u16(&c));
			break;
		}
		b->pos = start + len;
	}
	msg("confirm active: fastpath output %d, multifrag %u", cl->fastpath_out, cl->max_request);
}

static int send_sync(client *cl)
{
	uint8_t d[4] = {1, 0, cl->user & 0xff, cl->user >> 8};
	return send_data(&cl->s, PDU2_SYNC, d, 4);
}

static int send_control(client *cl, uint16_t action)
{
	buf b;
	b_init(&b, 8);
	w_u16(&b, action);
	w_u16(&b, action == CTRL_GRANTED ? cl->user : 0);
	w_u32(&b, action == CTRL_GRANTED ? 1002 : 0);
	int r = send_data(&cl->s, PDU2_CONTROL, b.p, b.len);
	b_free(&b);
	return r;
}

static int send_fontmap(client *cl)
{
	static const uint8_t d[] = {0, 0, 0, 0, 3, 0, 4, 0};
	return send_data(&cl->s, PDU2_FONTMAP, d, sizeof d);
}

/* Domain PDUs up to and including the Client Info PDU. */
static int mcs_domain(client *cl, buf *b)
{
	int fp, joined = 0, need = 2 + cl->nchan;
	cl->user = 1004 + cl->nchan;
	for (;;) {
		if (read_pdu(&cl->c, b, &fp))
			return -1;
		if (fp)
			continue;
		uint16_t user, chan;
		int t = parse_mcs(b, &user, &chan);
		if (t == MCS_ERECT) {
			dbg("erect domain");
		} else if (t == MCS_AURQ) {
			uint8_t d[4] = {MCS_AUCF << 2 | 2, 0, (cl->user - 1001) >> 8, (cl->user - 1001) & 0xff};
			if (send_raw_mcs(cl, d, 4))
				return -1;
			dbg("attach user -> %u", cl->user);
		} else if (t == MCS_CJRQ) {
			r_u16be(b);
			uint16_t ch = r_u16be(b);
			uint8_t d[8] = {MCS_CJCF << 2 | 2, 0, (cl->user - 1001) >> 8,
					(cl->user - 1001) & 0xff, ch >> 8, ch & 0xff, ch >> 8, ch & 0xff};
			if (send_raw_mcs(cl, d, 8))
				return -1;
			dbg("join channel %u", ch);
			joined++;
		} else if (t == MCS_SDRQ) {
			uint16_t flags = r_u16(b);
			r_u16(b);
			if (!(flags & SEC_INFO_PKT)) {
				dbg("ignoring pre-info PDU flags 0x%x on %u", flags, chan);
				continue;
			}
			if (joined < need)
				dbg("info after %d of %d joins", joined, need);
			r_u32(b); /* code page */
			uint32_t iflags = r_u32(b);
			uint16_t cbd = r_u16(b), cbu = r_u16(b), cbp = r_u16(b);
			r_u16(b);
			r_u16(b);
			char dom[256], pass[512];
			r_utf16(b, cbd + 2, dom, sizeof dom);
			r_utf16(b, cbu + 2, cl->username, sizeof cl->username);
			r_utf16(b, cbp + 2, pass, sizeof pass);
			msg("client info: user '%s' domain '%s' flags 0x%x password %s", cl->username,
			    dom, iflags, cbp ? "given" : "empty");
			int ok = !b->err && (cl->nla_ok || check_password(cl->username, pass));
			memset(pass, 0, sizeof pass);
			if (!ok) {
				msg("login failed");
				return -1;
			}
			return 0;
		} else if (t == MCS_DPUM) {
			msg("client disconnected during handshake");
			return -1;
		} else {
			dbg("mcs pdu %d ignored", t);
		}
	}
}

/* ---- updates --------------------------------------------------------- */

/* One tile as a bitmap update: planar with the compression header (like
 * Windows), or raw with RDESK_RAW=1. Width padded to 4. */
static void queue_tile(int tx, int ty, int w, int h)
{
	static uint8_t tile[TILE * TILE * 4], enc[planar_max(TILE, TILE) + 16];
	static buf u;
	static int raw = -1;
	if (raw < 0)
		raw = getenv("RDESK_RAW") && *getenv("RDESK_RAW") == '1';
	int w4 = (w + 3) & ~3;
	int stride = x.img->bytes_per_line;
	for (int r = 0; r < h; r++) {
		/* raw bitmaps are bottom-up */
		uint8_t *dst = tile + (raw ? h - 1 - r : r) * w4 * 4;
		memcpy(dst, x.img->data + (size_t)(ty + r) * stride + tx * 4, w * 4);
		memset(dst + w * 4, 0, (w4 - w) * 4);
	}
	b_reset(&u);
	w_u16(&u, 1); /* UPDATETYPE_BITMAP */
	w_u16(&u, 1);
	w_u16(&u, tx);
	w_u16(&u, ty);
	w_u16(&u, tx + w - 1);
	w_u16(&u, ty + h - 1);
	w_u16(&u, w4);
	w_u16(&u, h);
	w_u16(&u, 32);
	if (raw) {
		w_u16(&u, 0);
		w_u16(&u, w4 * h * 4);
		w_bytes(&u, tile, w4 * h * 4);
	} else {
		size_t n = planar_encode(tile, w4 * 4, w4, h, 1, enc);
		w_u16(&u, 0x0001); /* BITMAP_COMPRESSION */
		w_u16(&u, 8 + n);
		w_u16(&u, 0);                         /* cbCompFirstRowSize */
		w_u16(&u, n);                         /* cbCompMainBodySize */
		w_u16(&u, w4 * 4);                    /* cbScanWidth: bytes, not pixels */
		w_u16(&u, w4 * h * 4);                /* cbUncompressedSize */
		w_bytes(&u, enc, n);
	}
	fp_update(&out, FP_UPD_BITMAP, u.p, u.len);
}

/* Mark the tiles drawn to since the last call. */
static void collect_damage(void)
{
	if (!x.damage) {
		memset(x.dirty, 1, x.tw * x.th);
		return;
	}
	if (!x.damaged)
		return;
	x.damaged = 0;
	XDamageSubtract(x.dpy, x.damage, None, x.region);
	int n;
	XRectangle *r = XFixesFetchRegion(x.dpy, x.region, &n);
	for (int i = 0; i < n; i++) {
		int x0 = r[i].x < 0 ? 0 : r[i].x / TILE;
		int y0 = r[i].y < 0 ? 0 : r[i].y / TILE;
		int x1 = (r[i].x + r[i].width - 1) / TILE;
		int y1 = (r[i].y + r[i].height - 1) / TILE;
		if (x1 >= x.tw)
			x1 = x.tw - 1;
		if (y1 >= x.th)
			y1 = x.th - 1;
		for (int ty = y0; ty <= y1; ty++)
			memset(x.dirty + ty * x.tw + x0, 1, x1 >= x0 ? x1 - x0 + 1 : 0);
	}
	if (r)
		XFree(r);
}

/* Grab rows y..y+h into the same rows of x.img: a view into the shared
 * segment, which Xlib sends to the server as an offset. */
static int grab_rows(int y, int h)
{
	XImage band = *x.img;
	band.height = h;
	band.data = x.img->data + (size_t)y * x.img->bytes_per_line;
	return !XShmGetImage(x.dpy, x.root, &band, 0, y, AllPlanes);
}

static int send_frame(client *cl)
{
	int sz;
	if (ioctl(cl->c.fd, SIOCOUTQ, &sz) == 0 && sz > OUTQ_MAX)
		return 0; /* link is behind: drop this frame */
	collect_damage();
	if (cl->full)
		memset(x.dirty, 1, x.tw * x.th);
	for (int r = 0; r < x.th;) {
		if (!memchr(x.dirty + r * x.tw, 1, x.tw)) {
			r++;
			continue;
		}
		int r1 = r + 1;
		while (r1 < x.th && memchr(x.dirty + r1 * x.tw, 1, x.tw))
			r1++;
		int y1 = r1 * TILE > x.h ? x.h : r1 * TILE;
		if (grab_rows(r * TILE, y1 - r * TILE))
			return -1;
		r = r1;
	}
	int stride = x.img->bytes_per_line, tiles = 0;
	for (int ty = 0; ty < x.h; ty += TILE) {
		int h = ty + TILE > x.h ? x.h - ty : TILE;
		for (int tx = 0; tx < x.w; tx += TILE) {
			int w = tx + TILE > x.w ? x.w - tx : TILE;
			uint8_t *d = x.dirty + ty / TILE * x.tw + tx / TILE;
			if (!*d)
				continue;
			*d = 0;
			int changed = cl->full;
			for (int r = 0; r < h && !changed; r++) {
				size_t o = (size_t)(ty + r) * stride + tx * 4;
				changed = memcmp(x.img->data + o, x.prev + o, w * 4) != 0;
			}
			if (!changed)
				continue;
			for (int r = 0; r < h; r++) {
				size_t o = (size_t)(ty + r) * stride + tx * 4;
				memcpy(x.prev + o, x.img->data + o, w * 4);
			}
			queue_tile(tx, ty, w, h);
			tiles++;
			if (out.len > 256 * 1024 && flush_out(cl))
				return -1;
		}
	}
	cl->full = 0;
	if (tiles)
		dbg("frame: %d tiles", tiles);
	return flush_out(cl);
}

static int send_cursor(client *cl)
{
	XFixesCursorImage *ci = XFixesGetCursorImage(x.dpy);
	if (!ci)
		return 0;
	int w = ci->width > MAX_POINTER ? MAX_POINTER : ci->width;
	int h = ci->height > MAX_POINTER ? MAX_POINTER : ci->height;
	int hx = ci->xhot < w ? ci->xhot : w - 1, hy = ci->yhot < h ? ci->yhot : h - 1;
	size_t xorlen = (size_t)w * h * 4, andlen = 0; /* alpha cursor: no AND mask */
	static buf u;
	b_reset(&u);
	w_u16(&u, 32); /* xorBpp */
	w_u16(&u, 0);  /* cache index */
	w_u16(&u, hx);
	w_u16(&u, hy);
	w_u16(&u, w);
	w_u16(&u, h);
	w_u16(&u, andlen);
	w_u16(&u, xorlen);
	for (int r = h - 1; r >= 0; r--) {
		for (int c = 0; c < w; c++) {
			unsigned long px = ci->pixels[r * ci->width + c];
			uint32_t a = px >> 24 & 0xff, rr = px >> 16 & 0xff, g = px >> 8 & 0xff, bb = px & 0xff;
			if (a && a < 255) { /* XFixes is premultiplied; RDP wants straight */
				rr = rr * 255 / a;
				g = g * 255 / a;
				bb = bb * 255 / a;
			}
			w_u8(&u, bb);
			w_u8(&u, g);
			w_u8(&u, rr);
			w_u8(&u, a);
		}
	}
	XFree(ci);
	fp_update(&out, FP_UPD_POINTER, u.p, u.len);
	cl->cursor_dirty = 0;
	return flush_out(cl);
}

/* ---- input ---------------------------------------------------------- */

static void fastpath_input(buf *b)
{
	b->pos = 0;
	uint8_t h = r_u8(b);
	if (r_u8(b) & 0x80)
		r_u8(b);
	int n = h >> 2 & 0xf;
	if (!n)
		n = r_u8(b);
	for (int i = 0; i < n && !b->err; i++) {
		uint8_t eh = r_u8(b);
		int code = eh >> 5, flags = eh & 0x1f;
		switch (code) {
		case FP_IN_SCANCODE:
			in_key(r_u8(b), flags);
			break;
		case FP_IN_MOUSE: {
			uint16_t f = r_u16(b), mx = r_u16(b), my = r_u16(b);
			in_mouse(f, mx, my);
			break;
		}
		case FP_IN_MOUSEX: {
			uint16_t f = r_u16(b), mx = r_u16(b), my = r_u16(b);
			in_mousex(f, mx, my);
			break;
		}
		case FP_IN_SYNC:
			break;
		case FP_IN_UNICODE:
			in_unicode(r_u16(b), flags & KBD_RELEASE);
			break;
		case FP_IN_QOE:
			r_u32(b);
			break;
		default:
			dbg("unknown fast-path input event %d", code);
			return;
		}
	}
	XFlush(x.dpy);
}

static void slowpath_input(buf *b)
{
	uint16_t n = r_u16(b);
	r_u16(b);
	for (int i = 0; i < n && !b->err; i++) {
		r_u32(b); /* event time */
		uint16_t type = r_u16(b);
		uint16_t f = r_u16(b), a = r_u16(b), c = r_u16(b);
		switch (type) {
		case 0x0004: /* scancode */
			in_key(a, (f & 0x8000 ? KBD_RELEASE : 0) | (f & 0x0100 ? KBD_EXTENDED : 0));
			break;
		case 0x0005: /* unicode */
			in_unicode(a, f & 0x8000);
			break;
		case 0x8001:
			in_mouse(f, a, c);
			break;
		case 0x8002:
			in_mousex(f, a, c);
			break;
		}
	}
	XFlush(x.dpy);
}

/* ---- session ---------------------------------------------------------- */

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static int handle_slowpath(client *cl, buf *b, int *active)
{
	uint16_t user, chan;
	int t = parse_mcs(b, &user, &chan);
	if (t == MCS_DPUM) {
		msg("client disconnected");
		return -1;
	}
	if (t != MCS_SDRQ)
		return 0;
	if (chan != MCS_IO_CHANNEL) {
		if (chan == cl->cliprdr && cl->clip) {
			if (vc_recv(&cl->cliprdr_acc, b))
				return clip_recv(cl->clip, &cl->cliprdr_acc);
			return 0;
		}
		dbg("%zu bytes on channel %u ignored", r_left(b), chan);
		return 0;
	}
	uint8_t type2 = 0;
	int type = parse_share(b, &type2);
	if (type < 0)
		return 0;
	if (type == PDU_CONFIRM_ACTIVE) {
		parse_confirm_active(cl, b);
		return 0;
	}
	if (type != PDU_DATA)
		return 0;
	switch (type2) {
	case PDU2_SYNC:
		return send_sync(cl);
	case PDU2_CONTROL: {
		uint16_t action = r_u16(b);
		if (action == CTRL_COOPERATE)
			return send_control(cl, CTRL_COOPERATE);
		if (action == CTRL_REQUEST)
			return send_control(cl, CTRL_GRANTED);
		return 0;
	}
	case PDU2_FONTLIST:
		if (send_fontmap(cl))
			return -1;
		*active = 1;
		cl->full = 1;
		cl->cursor_dirty = 1;
		if (cl->cliprdr && !cl->clip && !off("clip")) {
			cl->clip = clip_new(x.dpy, 1, clip_send, cl);
			if (clip_start(cl->clip))
				return -1;
		}
		msg("session active, %dx%d", x.w, x.h);
		return 0;
	case PDU2_INPUT:
		slowpath_input(b);
		return 0;
	case PDU2_REFRESH_RECT:
		cl->full = 1;
		return 0;
	case PDU2_SUPPRESS_OUTPUT:
		cl->suppress = r_u8(b) == 0;
		dbg("suppress output %d", cl->suppress);
		if (!cl->suppress)
			cl->full = 1;
		return 0;
	case PDU2_SHUTDOWN_REQ:
		msg("client shutdown request");
		return -1;
	case PDU2_PERSIST_KEYS:
		return 0;
	default:
		dbg("data pdu 0x%02x ignored", type2);
		return 0;
	}
}

static void serve(int fd, SSL_CTX *ctx)
{
	client cl = {0};
	cl.c.fd = fd;
	cl.s.c = &cl.c;
	cl.s.server = 1;
	cl.s.user = 1002;
	cl.s.share_id = 0x000103ea;
	buf b;
	b_init(&b, 65536);
	b_init(&cl.cliprdr_acc, 4096);
	int active = 0;

	if (x224_connect(&cl, &b))
		goto done;
	cl.c.ssl = SSL_new(ctx);
	SSL_set_fd(cl.c.ssl, fd);
	if (SSL_accept(cl.c.ssl) != 1) {
		msg("TLS handshake failed");
		ERR_print_errors_fp(stderr);
		goto done;
	}
	dbg("TLS %s", SSL_get_version(cl.c.ssl));
	if (cl.selected == PROTOCOL_HYBRID) {
		uint8_t h[16];
		nla_creds cr;
		if (get_nthash(h) || credssp_server(&cl.c, h, &cr)) {
			msg("NLA failed");
			goto done;
		}
		int ok = check_password(cr.user, cr.pass);
		memset(cr.pass, 0, sizeof cr.pass);
		if (!ok) {
			msg("NLA: delegated password rejected (stale NT hash?)");
			goto done;
		}
		msg("NLA: '%s' authenticated", cr.user);
		cl.nla_ok = 1;
	}
	if (mcs_connect(&cl, &b) || mcs_domain(&cl, &b))
		goto done;
	if (x_alloc_image())
		goto done;
	if (send_license(&cl) || send_demand_active(&cl))
		goto done;

	int64_t next = now_ms();
	int xfd = ConnectionNumber(x.dpy);
	for (;;) {
		while (XPending(x.dpy)) {
			XEvent ev;
			XNextEvent(x.dpy, &ev);
			if (clip_x_event(cl.clip, &ev))
				continue;
			if (ev.type == x.fixes_ev + XFixesCursorNotify)
				cl.cursor_dirty = 1;
			else if (x.damage && ev.type == x.damage_ev + XDamageNotify)
				x.damaged = 1;
		}
		int64_t t = now_ms();
		if (active && t >= next) {
			next += 1000 / opt.fps;
			if (next < t)
				next = t + 1000 / opt.fps;
			if (cl.cursor_dirty && !off("cursor") && send_cursor(&cl))
				break;
			if (!cl.suppress && !off("frames") && send_frame(&cl))
				break;
		}
		if (c_pending(&cl.c) == 0) {
			struct pollfd p[2] = {{fd, POLLIN, 0}, {xfd, POLLIN, 0}};
			int to = active ? (int)(next - now_ms()) : 1000;
			if (to < 0)
				to = 0;
			if (poll(p, 2, to) < 0 && errno != EINTR)
				break;
			if (p[0].revents & (POLLERR | POLLHUP)) {
				msg("connection closed");
				break;
			}
			if (!(p[0].revents & POLLIN))
				continue;
		}
		int fp;
		if (read_pdu(&cl.c, &b, &fp)) {
			msg("connection closed");
			break;
		}
		if (fp) {
			if (active)
				fastpath_input(&b);
		} else if (handle_slowpath(&cl, &b, &active)) {
			break;
		}
	}
done:
	if (cl.c.ssl) {
		SSL_shutdown(cl.c.ssl);
		SSL_free(cl.c.ssl);
	}
	close(fd);
	b_free(&b);
	clip_free(cl.clip);
	b_free(&cl.cliprdr_acc);
	msg("session ended");
}

/* ---- main ------------------------------------------------------------- */

static void usage(void)
{
	fprintf(stderr,
		"usage: rdesk-rdpc [options]\n"
		"  --bind ADDR:PORT   default 0.0.0.0:3390\n"
		"  --fps N            default 30\n"
		"  --pass PASSWORD    fixed password instead of the Linux one\n"
		"  --certdir DIR      default ~/.config/rdesk (also holds nthash)\n"
		"  --no-nla           TLS only, password from the client info\n"
		"  --set-password     store the NT hash of your Linux password (enables NLA), exit\n"
		"  -v, -vv            debug log, hex dumps\n");
	exit(2);
}

static int store_password(void)
{
	struct passwd *pw = getpwuid(getuid());
	char pass[512];
	struct termios t, o;
	fprintf(stderr, "Linux password for %s: ", pw ? pw->pw_name : "?");
	int tty = tcgetattr(0, &o) == 0;
	if (tty) {
		t = o;
		t.c_lflag &= ~ECHO;
		tcsetattr(0, TCSANOW, &t);
	}
	if (!fgets(pass, sizeof pass, stdin))
		pass[0] = 0;
	if (tty) {
		tcsetattr(0, TCSANOW, &o);
		fputc('\n', stderr);
	}
	pass[strcspn(pass, "\n")] = 0;
	mkdir(opt.certdir, 0700);
	int ok = pw && check_password(pw->pw_name, pass);
	memset(pass, 0, sizeof pass);
	if (!ok) {
		msg("wrong password");
		return 1;
	}
	msg("NT hash in %s is current", nthash_path);
	return 0;
}

int main(int argc, char **argv)
{
	int set_password = 0;
	snprintf(opt.certdir, sizeof opt.certdir, "%s/.config/rdesk", getenv("HOME") ? getenv("HOME") : ".");
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "--bind") && i + 1 < argc) {
			static char host[256];
			snprintf(host, sizeof host, "%s", argv[++i]);
			char *c = strrchr(host, ':');
			if (!c)
				usage();
			*c = 0;
			opt.bind = host;
			opt.port = atoi(c + 1);
		} else if (!strcmp(a, "--fps") && i + 1 < argc) {
			opt.fps = atoi(argv[++i]);
			if (opt.fps < 1)
				opt.fps = 1;
		} else if (!strcmp(a, "--pass") && i + 1 < argc) {
			opt.pass = argv[++i];
		} else if (!strcmp(a, "--certdir") && i + 1 < argc) {
			snprintf(opt.certdir, sizeof opt.certdir, "%s", argv[++i]);
		} else if (!strcmp(a, "--set-password")) {
			set_password = 1;
		} else if (!strcmp(a, "--no-nla")) {
			opt.no_nla = 1;
		} else if (!strcmp(a, "-v")) {
			verbose = 1;
		} else if (!strcmp(a, "-vv")) {
			verbose = 2;
		} else {
			usage();
		}
	}
	snprintf(nthash_path, sizeof nthash_path, "%s/nthash", opt.certdir);
	if (set_password)
		return store_password();
	signal(SIGPIPE, SIG_IGN);
	if (x_open())
		return 1;
	SSL_CTX *ctx = tls_ctx();
	if (!ctx)
		return 1;
	b_init(&out, 1 << 20);

	int ls = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(opt.port)};
	if (inet_pton(AF_INET, opt.bind, &sa.sin_addr) != 1) {
		msg("bad bind address %s", opt.bind);
		return 1;
	}
	if (bind(ls, (struct sockaddr *)&sa, sizeof sa) || listen(ls, 4)) {
		perror("bind");
		return 1;
	}
	msg("listening on %s:%d", opt.bind, opt.port);
	for (;;) {
		struct sockaddr_in peer;
		socklen_t pl = sizeof peer;
		int fd = accept(ls, (struct sockaddr *)&peer, &pl);
		if (fd < 0)
			continue;
		char ip[64];
		inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
		msg("connection from %s", ip);
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
		int idle = 10, intvl = 5, cnt = 3, uto = 20000;
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
		setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &uto, sizeof uto);
		serve(fd, ctx);
	}
}
