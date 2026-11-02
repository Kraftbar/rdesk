/* gfx.h - the graphics pipeline (MS-RDPEGFX) on a dynamic virtual channel
 * (MS-RDPEDYC), frames as H.264 (AVC420). Server side. */
#pragma once
#include "rdp.h"

typedef struct gfx gfx;

/* send: one drdynvc static channel PDU (at most 1600 bytes) to the client */
typedef int (*gfx_send_fn)(void *arg, const uint8_t *p, size_t n);

enum { GFX_PENDING, GFX_READY, GFX_FAILED };

/* A surface of w x h (both even) for the whole desktop. */
gfx *gfx_new(gfx_send_fn send, void *arg, int w, int h);
void gfx_free(gfx *g);
/* Open the dynamic channels: once the session is active. */
int gfx_start(gfx *g);
/* A reassembled drdynvc PDU from the client. */
int gfx_recv(gfx *g, buf *b);
int gfx_state(const gfx *g);
/* Frames sent and not acknowledged are few enough for another. */
int gfx_can_send(gfx *g);

typedef struct {
	uint16_t x, y, w, h;
} gfx_rect;

/* Encode the BGRX desktop (cur, stride) as one frame; rects are what
 * changed and all the client takes from it. idr: a keyframe. */
int gfx_frame(gfx *g, const uint8_t *cur, int stride, const gfx_rect *rects, int n, int idr);
