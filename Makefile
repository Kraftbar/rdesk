CFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
LDLIBS_SSL = -lssl -lcrypto

all: rdesk-rdpc rdesk-rdpc-client

rdesk-rdpc: server.o rdp.o nla.o clip.o planar.o gfx.o rfx.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS_SSL) -lX11 -lXext -lXfixes -lXdamage -lXrandr -l:libXtst.so.6 -lx264 -lm -pthread

rdesk-rdpc-client: client.o rdp.o nla.o planar.o clip.o gfxc.o gfxdec.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS_SSL) -lX11 -lXcursor -lXfixes -lavcodec -lavutil -pthread

%.o: %.c rdp.h nla.h planar.h clip.h gfx.h gfxc.h gfxdec.h rfx.h
	$(CC) $(CFLAGS) -c $<

gfxreplay: gfxreplay.o gfxc.o gfxdec.o rdp.o planar.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS_SSL) -lavcodec -lavutil -pthread

clean:
	rm -f *.o rdesk-rdpc rdesk-rdpc-client gfxreplay
