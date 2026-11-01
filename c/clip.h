/* clip.h - text clipboard over cliprdr <-> X11 CLIPBOARD, either role. */
#pragma once
#include <X11/Xlib.h>
#include "rdp.h"

typedef struct clip clip;

/* send: deliver one whole cliprdr PDU to the peer. */
typedef int (*clip_send_fn)(void *arg, const uint8_t *p, size_t n);

clip *clip_new(Display *dpy, int server, clip_send_fn send, void *arg);
void clip_free(clip *c);
/* Server: announce capabilities and Monitor Ready. */
int clip_start(clip *c);
/* A reassembled cliprdr PDU from the peer. */
int clip_recv(clip *c, buf *b);
/* Offer an X event; returns 1 if it was clipboard business. */
int clip_x_event(clip *c, XEvent *ev);
