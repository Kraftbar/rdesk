/* gfxreplay: decode a graphics pipeline recording (RDESK_GFX_RECORD) as
 * the client would, without a server or a display.
 *
 *   gfxreplay FILE OUTDIR [EVERY]
 *
 * writes the desktop as OUTDIR/frame-NNNNN.ppm after every EVERY'th frame
 * (default 50) and after the last. */
#include "gfxc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t *fb;
static int fw, fh, frames, every = 50;
static const char *outdir;

static void dump(void)
{
	char name[512];
	snprintf(name, sizeof name, "%s/frame-%05d.ppm", outdir, frames);
	FILE *f = fopen(name, "wb");
	if (!f) {
		perror(name);
		return;
	}
	fprintf(f, "P6\n%d %d\n255\n", fw, fh);
	for (int i = 0; i < fw * fh; i++) {
		uint8_t rgb[3] = {fb[i] >> 16, fb[i] >> 8, fb[i]};
		fwrite(rgb, 1, 3, f);
	}
	fclose(f);
}

/* the client's only PDU while replaying: frame acknowledgements */
static int on_send(void *arg, const uint8_t *p, size_t n)
{
	frames++;
	if (verbose)
		fprintf(stderr, "== frame %d\n", frames);
	if (fb && frames % every == 0)
		dump();
	return 0;
}

static void on_paint(void *arg, int x, int y, int w, int h, const uint32_t *px, int stride)
{
	for (int r = 0; r < h; r++)
		if (y + r < fh && x < fw)
			memcpy(fb + (size_t)(y + r) * fw + x, px + (size_t)r * stride,
			       (size_t)(x + w > fw ? fw - x : w) * 4);
}

static void on_reset(void *arg, int w, int h)
{
	free(fb);
	fw = w;
	fh = h;
	fb = calloc((size_t)w * h, 4);
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: gfxreplay FILE OUTDIR [EVERY]\n");
		return 2;
	}
	outdir = argv[2];
	if (argc > 3)
		every = atoi(argv[3]) > 0 ? atoi(argv[3]) : 1;
	if (getenv("V"))
		verbose = atoi(getenv("V"));
	FILE *f = fopen(argv[1], "rb");
	if (!f) {
		perror(argv[1]);
		return 1;
	}
	gfxc_ops ops = {NULL, on_send, on_paint, on_reset};
	gfxc *g = gfxc_new(&ops);
	uint32_t len;
	size_t msgs = 0;
	while (fread(&len, 4, 1, f) == 1) {
		uint8_t *p = malloc(len);
		if (fread(p, 1, len, f) != len) {
			free(p);
			break;
		}
		gfxc_replay(g, p, len);
		free(p);
		msgs++;
	}
	if (fb)
		dump();
	fprintf(stderr, "%zu messages, %d frames\n", msgs, frames);
	gfxc_free(g);
	return 0;
}
