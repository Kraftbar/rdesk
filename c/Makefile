CFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
LDLIBS_SSL = -lssl -lcrypto

all: rdesk-rdpc rdesk-rdpc-client

rdesk-rdpc: server.o rdp.o nla.o clip.o planar.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS_SSL) -lX11 -lXext -lXfixes -lXdamage -l:libXtst.so.6

rdesk-rdpc-client: client.o rdp.o nla.o planar.o clip.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS_SSL) -lX11 -lXcursor -lXfixes

%.o: %.c rdp.h nla.h planar.h clip.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o rdesk-rdpc rdesk-rdpc-client
