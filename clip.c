/* clip.c - text clipboard: cliprdr (MS-RDPECLIP) <-> X11 CLIPBOARD.
 *
 * Same code for server and client; only who sends Monitor Ready differs.
 * A copy on this side is announced as CF_UNICODETEXT; a copy on the peer
 * makes us the CLIPBOARD owner and data is fetched when someone pastes.
 * Newlines are CRLF on the wire, LF in X. */
#include "clip.h"

#include <X11/Xatom.h>
#include <X11/extensions/Xfixes.h>
#include <stdlib.h>
#include <string.h>

#define CB_MONITOR_READY 1
#define CB_FORMAT_LIST 2
#define CB_FORMAT_LIST_RESPONSE 3
#define CB_FORMAT_DATA_REQUEST 4
#define CB_FORMAT_DATA_RESPONSE 5
#define CB_CLIP_CAPS 7
#define CB_RESPONSE_OK 1
#define CB_RESPONSE_FAIL 2
#define CB_USE_LONG_FORMAT_NAMES 2

#define CF_TEXT 1
#define CF_UNICODETEXT 13

#define MAX_PENDING 16

typedef struct {
	Window requestor;
	Atom property, target;
	Time time;
} pending;

struct clip {
	Display *dpy;
	Window win;
	int server, ready, fixes_ev;
	clip_send_fn send;
	void *arg;
	Atom CLIPBOARD, TARGETS, UTF8, TEXT, PROP, INCR;
	int peer_long;        /* peer uses long format names */
	uint32_t remote_fmt;  /* text format the peer offers, 0 none */
	char *cache;          /* peer's text, UTF-8, once fetched */
	size_t cache_len;
	int requested;        /* data request to the peer outstanding */
	pending pend[MAX_PENDING];
	int npend;
	int converting;       /* our XConvertSelection for the peer is out */
};

static int send_pdu(clip *c, uint16_t type, uint16_t flags, const buf *body)
{
	buf b;
	b_init(&b, 8 + (body ? body->len : 0));
	w_u16(&b, type);
	w_u16(&b, flags);
	w_u32(&b, body ? body->len : 0);
	if (body)
		w_bytes(&b, body->p, body->len);
	int r = c->send(c->arg, b.p, b.len);
	b_free(&b);
	return r;
}

static int send_caps(clip *c)
{
	buf b;
	b_init(&b, 16);
	w_u16(&b, 1); /* cCapabilitiesSets */
	w_u16(&b, 0);
	w_u16(&b, 1); /* CB_CAPSTYPE_GENERAL */
	w_u16(&b, 12);
	w_u32(&b, 2); /* CB_CAPS_VERSION_2 */
	w_u32(&b, CB_USE_LONG_FORMAT_NAMES);
	int r = send_pdu(c, CB_CLIP_CAPS, 0, &b);
	b_free(&b);
	return r;
}

static int send_format_list(clip *c, int have_text)
{
	buf b;
	b_init(&b, 64);
	if (have_text) {
		w_u32(&b, CF_UNICODETEXT);
		if (c->peer_long)
			w_u16(&b, 0);
		else
			w_zero(&b, 32);
	}
	int r = send_pdu(c, CB_FORMAT_LIST, 0, &b);
	b_free(&b);
	dbg("clip: announced %s", have_text ? "text" : "nothing");
	return r;
}

clip *clip_new(Display *dpy, int server, clip_send_fn send, void *arg)
{
	int err;
	clip *c = calloc(1, sizeof *c);
	c->dpy = dpy;
	c->server = server;
	c->send = send;
	c->arg = arg;
	c->CLIPBOARD = XInternAtom(dpy, "CLIPBOARD", False);
	c->TARGETS = XInternAtom(dpy, "TARGETS", False);
	c->UTF8 = XInternAtom(dpy, "UTF8_STRING", False);
	c->TEXT = XInternAtom(dpy, "TEXT", False);
	c->PROP = XInternAtom(dpy, "RDESK_CLIP", False);
	c->INCR = XInternAtom(dpy, "INCR", False);
	c->win = XCreateWindow(dpy, DefaultRootWindow(dpy), -10, -10, 1, 1, 0, 0, InputOnly,
			       CopyFromParent, 0, NULL);
	if (!XFixesQueryExtension(dpy, &c->fixes_ev, &err)) {
		msg("clip: no XFIXES, clipboard disabled");
		c->fixes_ev = -1;
	} else {
		XFixesSelectSelectionInput(dpy, c->win, c->CLIPBOARD, XFixesSetSelectionOwnerNotifyMask);
	}
	XFlush(dpy);
	return c;
}

void clip_free(clip *c)
{
	if (!c)
		return;
	if (XGetSelectionOwner(c->dpy, c->CLIPBOARD) == c->win)
		XSetSelectionOwner(c->dpy, c->CLIPBOARD, None, CurrentTime);
	XDestroyWindow(c->dpy, c->win);
	XFlush(c->dpy);
	free(c->cache);
	free(c);
}

static int local_has_owner(clip *c)
{
	Window o = XGetSelectionOwner(c->dpy, c->CLIPBOARD);
	return o != None && o != c->win;
}

int clip_start(clip *c)
{
	if (send_caps(c))
		return -1;
	c->ready = 1;
	if (send_pdu(c, CB_MONITOR_READY, 0, NULL))
		return -1;
	return local_has_owner(c) ? send_format_list(c, 1) : 0;
}

/* ---- X side ---------------------------------------------------------- */

static void notify(clip *c, pending *p, Atom prop)
{
	XEvent e = {0};
	e.xselection.type = SelectionNotify;
	e.xselection.requestor = p->requestor;
	e.xselection.selection = c->CLIPBOARD;
	e.xselection.target = p->target;
	e.xselection.property = prop;
	e.xselection.time = p->time;
	XSendEvent(c->dpy, p->requestor, False, 0, &e);
}

static void answer(clip *c, pending *p)
{
	if (p->target == c->TARGETS) {
		Atom t[] = {c->TARGETS, c->UTF8, XA_STRING, c->TEXT};
		XChangeProperty(c->dpy, p->requestor, p->property, XA_ATOM, 32, PropModeReplace,
				(unsigned char *)t, 4);
		notify(c, p, p->property);
		return;
	}
	if (!c->cache) {
		notify(c, p, None);
		return;
	}
	if (p->target == XA_STRING) {
		/* Latin-1, '?' for the rest */
		char *s = malloc(c->cache_len + 1);
		size_t n = 0;
		const uint8_t *u = (const uint8_t *)c->cache;
		for (size_t i = 0; i < c->cache_len;) {
			uint32_t cp = u[i];
			int k = cp < 0x80 ? 1 : cp >= 0xf0 ? 4 : cp >= 0xe0 ? 3 : cp >= 0xc0 ? 2 : 1;
			if (k == 2 && i + 1 < c->cache_len)
				cp = (cp & 31) << 6 | (u[i + 1] & 63);
			s[n++] = k == 1 ? (char)cp : cp < 0x100 && k == 2 ? (char)cp : '?';
			i += k;
		}
		XChangeProperty(c->dpy, p->requestor, p->property, XA_STRING, 8, PropModeReplace,
				(unsigned char *)s, n);
		free(s);
	} else {
		XChangeProperty(c->dpy, p->requestor, p->property, c->UTF8, 8, PropModeReplace,
				(unsigned char *)c->cache, c->cache_len);
	}
	notify(c, p, p->property);
}

static void flush_pending(clip *c)
{
	for (int i = 0; i < c->npend; i++)
		answer(c, &c->pend[i]);
	c->npend = 0;
	XFlush(c->dpy);
}

static int request_data(clip *c)
{
	if (c->requested)
		return 0;
	buf b;
	b_init(&b, 4);
	w_u32(&b, c->remote_fmt);
	c->requested = 1;
	int r = send_pdu(c, CB_FORMAT_DATA_REQUEST, 0, &b);
	b_free(&b);
	return r;
}

static void selection_request(clip *c, XSelectionRequestEvent *r)
{
	pending p = {r->requestor, r->property ? r->property : r->target, r->target, r->time};
	if (r->selection != c->CLIPBOARD ||
	    (p.target != c->TARGETS && p.target != c->UTF8 && p.target != XA_STRING && p.target != c->TEXT)) {
		notify(c, &p, None);
		XFlush(c->dpy);
		return;
	}
	if (p.target == c->TEXT)
		p.target = c->UTF8;
	if (p.target == c->TARGETS || c->cache || !c->remote_fmt) {
		answer(c, &p);
		XFlush(c->dpy);
		return;
	}
	if (c->npend == MAX_PENDING) {
		notify(c, &p, None);
		return;
	}
	c->pend[c->npend++] = p;
	request_data(c);
}

/* Our local paste for the peer arrived (or failed). */
static void selection_notify(clip *c, XSelectionEvent *s)
{
	c->converting = 0;
	buf body;
	b_init(&body, 256);
	int ok = 0;
	if (s->property != None) {
		Atom type;
		int fmt;
		unsigned long n, after;
		unsigned char *data = NULL;
		if (XGetWindowProperty(c->dpy, c->win, c->PROP, 0, 0x4000000, True, AnyPropertyType, &type,
				       &fmt, &n, &after, &data) == Success && data && fmt == 8 &&
		    type != c->INCR) {
			/* LF -> CRLF, UTF-8 (or Latin-1 STRING) -> UTF-16 */
			buf t;
			b_init(&t, n * 2 + 2);
			for (unsigned long i = 0; i < n; i++) {
				if (data[i] == '\n' && (i == 0 || data[i - 1] != '\r'))
					w_u8(&t, '\r');
				w_u8(&t, data[i]);
			}
			w_u8(&t, 0);
			if (type == XA_STRING) {
				for (size_t i = 0; i + 1 < t.len; i++)
					w_u16(&body, (uint8_t)t.p[i]);
				w_u16(&body, 0);
			} else {
				w_utf16(&body, (char *)t.p, 1);
			}
			b_free(&t);
			ok = 1;
		} else if (type == c->INCR) {
			msg("clip: local selection too large (INCR), not sent");
		}
		if (data)
			XFree(data);
	}
	send_pdu(c, CB_FORMAT_DATA_RESPONSE, ok ? CB_RESPONSE_OK : CB_RESPONSE_FAIL, ok ? &body : NULL);
	b_free(&body);
}

int clip_x_event(clip *c, XEvent *ev)
{
	if (!c)
		return 0;
	if (c->fixes_ev >= 0 && ev->type == c->fixes_ev + XFixesSelectionNotify) {
		XFixesSelectionNotifyEvent *se = (XFixesSelectionNotifyEvent *)ev;
		if (se->selection == c->CLIPBOARD && se->owner != c->win && se->owner != None) {
			free(c->cache);
			c->cache = NULL;
			c->remote_fmt = 0;
			if (c->ready)
				send_format_list(c, 1);
		}
		return 1;
	}
	switch (ev->type) {
	case SelectionRequest:
		if (ev->xselectionrequest.owner != c->win)
			return 0;
		selection_request(c, &ev->xselectionrequest);
		return 1;
	case SelectionNotify:
		if (ev->xselection.requestor != c->win)
			return 0;
		selection_notify(c, &ev->xselection);
		return 1;
	case SelectionClear:
		return ev->xselectionclear.window == c->win;
	}
	return 0;
}

/* ---- cliprdr side ----------------------------------------------------- */

static void format_list(clip *c, buf *b, uint16_t flags, uint32_t len)
{
	uint32_t found = 0;
	size_t end = b->pos + len;
	if (end > b->len)
		end = b->len;
	while (b->pos + 4 <= end) {
		uint32_t id = r_u32(b);
		if (c->peer_long) {
			while (b->pos + 2 <= end && r_u16(b))
				;
		} else {
			r_skip(b, 32);
		}
		if (id == CF_UNICODETEXT)
			found = id;
		else if (id == CF_TEXT && !found)
			found = id;
	}
	send_pdu(c, CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, NULL);
	free(c->cache);
	c->cache = NULL;
	c->requested = 0;
	c->remote_fmt = found;
	dbg("clip: peer offers %s", found ? "text" : "no text");
	if (found) {
		XSetSelectionOwner(c->dpy, c->CLIPBOARD, c->win, CurrentTime);
		XFlush(c->dpy);
	}
}

static void data_response(clip *c, buf *b, uint16_t flags, uint32_t len)
{
	c->requested = 0;
	free(c->cache);
	c->cache = NULL;
	if (flags & CB_RESPONSE_OK) {
		if (len > r_left(b))
			len = r_left(b);
		const uint8_t *p = r_bytes(b, len);
		char *s = malloc((size_t)len * 2 + 1);
		size_t n = 0;
		if (c->remote_fmt == CF_UNICODETEXT) {
			buf t = {.p = (uint8_t *)p, .len = len};
			r_utf16(&t, len, s, (size_t)len * 2 + 1);
			n = strlen(s);
		} else {
			for (uint32_t i = 0; i < len && p[i]; i++) {
				if (p[i] < 0x80) {
					s[n++] = p[i];
				} else {
					s[n++] = 0xc0 | p[i] >> 6;
					s[n++] = 0x80 | (p[i] & 0x3f);
				}
			}
			s[n] = 0;
		}
		/* CRLF -> LF */
		size_t o = 0;
		for (size_t i = 0; i < n; i++)
			if (!(s[i] == '\r' && i + 1 < n && s[i + 1] == '\n'))
				s[o++] = s[i];
		s[o] = 0;
		c->cache = s;
		c->cache_len = o;
		dbg("clip: got %zu bytes from peer", o);
	}
	flush_pending(c);
}

int clip_recv(clip *c, buf *b)
{
	uint16_t type = r_u16(b), flags = r_u16(b);
	uint32_t len = r_u32(b);
	if (b->err)
		return 0;
	switch (type) {
	case CB_MONITOR_READY: /* client side */
		if (send_caps(c))
			return -1;
		c->ready = 1;
		return send_format_list(c, local_has_owner(c));
	case CB_CLIP_CAPS: {
		uint16_t n = r_u16(b);
		r_u16(b);
		for (int i = 0; i < n && !b->err; i++) {
			size_t at = b->pos;
			uint16_t t = r_u16(b), l = r_u16(b);
			if (t == 1) {
				r_u32(b);
				c->peer_long = (r_u32(b) & CB_USE_LONG_FORMAT_NAMES) != 0;
			}
			b->pos = at + (l < 4 ? 4 : l);
		}
		return 0;
	}
	case CB_FORMAT_LIST:
		format_list(c, b, flags, len);
		return 0;
	case CB_FORMAT_LIST_RESPONSE:
		return 0;
	case CB_FORMAT_DATA_REQUEST: {
		uint32_t fmt = r_u32(b);
		if (fmt != CF_UNICODETEXT || !local_has_owner(c) || c->converting)
			return send_pdu(c, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, NULL);
		c->converting = 1;
		XConvertSelection(c->dpy, c->CLIPBOARD, c->UTF8, c->PROP, c->win, CurrentTime);
		XFlush(c->dpy);
		return 0;
	}
	case CB_FORMAT_DATA_RESPONSE:
		data_response(c, b, flags, len);
		return 0;
	default:
		dbg("clip: message %u ignored", type);
		return 0;
	}
}
