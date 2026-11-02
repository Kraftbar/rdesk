/* rfx.h - RemoteFX (MS-RDPRFX) encoder: the bitmap data of the graphics
 * pipeline's CAVIDEO and CAPROGRESSIVE codecs, for clients without H.264. */
#pragma once
#include "gfx.h"

/* An RFX message onto out: the 64x64 tiles of the w x h BGRX picture
 * (cur, stride) that rects touch, with rects as the region to update.
 * headers: the stream's first message. */
void rfx_message(buf *out, const uint8_t *cur, int stride, int w, int h, const gfx_rect *rects, int n,
		 uint32_t frame, int headers);

/* The same tiles as a RemoteFX Progressive message (MS-RDPEGFX 2.2.4.2),
 * each sent whole in one pass: what the iOS app takes. */
void rfx_progressive(buf *out, const uint8_t *cur, int stride, int w, int h, const gfx_rect *rects, int n,
		     uint32_t frame);
