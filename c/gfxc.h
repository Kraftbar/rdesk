/* gfxc.h - the graphics pipeline (MS-RDPEGFX), client side. */
#pragma once
#include "rdp.h"

typedef struct gfxc gfxc;

typedef struct {
	void *arg;
	/* one DVC PDU for the drdynvc static channel */
	int (*send)(void *arg, const uint8_t *p, size_t n);
	/* a mapped surface changed: w x h pixels (BGRX, stride in pixels)
	 * now at x,y on the desktop */
	void (*paint)(void *arg, int x, int y, int w, int h, const uint32_t *px, int stride);
	/* the desktop is now w x h */
	void (*reset)(void *arg, int w, int h);
} gfxc_ops;

gfxc *gfxc_new(const gfxc_ops *ops);
void gfxc_free(gfxc *g);
/* One whole drdynvc channel PDU. Returns -1 to drop the connection. */
int gfxc_recv(gfxc *g, buf *b);

/* RDESK_GFX_RECORD=FILE saves the server's PDUs, decompressed, each with
 * its length (32 bits) first; gfxc_replay() takes them back, one at a
 * time (gfxreplay.c). */
int gfxc_replay(gfxc *g, const uint8_t *p, size_t n);
