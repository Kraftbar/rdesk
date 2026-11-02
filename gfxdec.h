/* gfxdec.h - graphics pipeline codecs, decoding: RemoteFX Progressive and
 * ClearCodec (with its NSCodec and RLEX subcodecs). Pixels are BGRX
 * (0x00RRGGBB) in a w x h buffer, stride w. */
#pragma once
#include <stddef.h>
#include <stdint.h>

/* Progressive keeps each tile's coefficients between messages: later
 * passes refine them. One per surface. */
typedef struct prog prog;
prog *prog_new(int w, int h);
void prog_free(prog *p);
/* A Progressive message onto px; done() for each rect that changed.
 * Returns 0, or -1 for a malformed message (what came before it stays). */
int prog_decode(prog *p, const uint8_t *data, size_t n, uint32_t *px,
		void (*done)(void *arg, int x, int y, int w, int h), void *arg);

/* ClearCodec keeps bar and glyph caches across messages. One per
 * connection. */
typedef struct clear clear;
clear *clear_new(void);
void clear_free(clear *c);
/* A w x h ClearCodec bitmap onto px, which holds what is there now
 * (layers may leave parts as they were). Returns 0 or -1. */
int clear_decode(clear *c, const uint8_t *data, size_t n, uint32_t *px, int w, int h);
