/* rdesk-greeter: LightDM's greeter, wrapped, so an RDP client's login
 * starts the session as on Windows: NLA's password, no login screen.
 *
 *     rdesk-greeter --user NAME -- /usr/sbin/slick-greeter
 *
 * LightDM runs it as the greeter (as lightdm, on the login screen's X
 * server). It starts the real greeter on pipes of its own and passes the
 * greeter protocol (LightDM's src/greeter.c) through, except while a
 * remote login has it. It also lets NAME onto the X server, so rdesk-rdpc
 * running as NAME shows the login screen without LightDM's cookie.
 *
 * rdesk-rdpc, NAME only (SO_PEERCRED), sends on SOCK
 *     u32 len, user, u32 len, password   (big-endian)
 * and reads one byte: 0 session starting, 1 refused, 2 PAM wants more
 * than a password, 3 busy, timed out or gone. One request a connection.
 *
 * Anything going wrong leaves the local login as it was. */

#define _GNU_SOURCE
#include <X11/Xlib.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SOCK "/run/rdesk-login/greeter.sock"
static const char *sock = SOCK; /* RDESK_GREETER_SOCK for tests */
#define MAX_PACKET 65536

/* greeter -> LightDM */
enum { G_CONNECT, G_AUTH, G_AUTH_GUEST, G_CONTINUE, G_START, G_CANCEL, G_LANGUAGE, G_AUTH_REMOTE };
/* LightDM -> greeter */
enum { D_CONNECTED, D_PROMPT, D_END, D_SESSION_RESULT, D_SHARED_DIR, D_IDLE, D_RESET, D_CONNECTED_V2 };
/* PAM message styles */
enum { PAM_ECHO_OFF = 1, PAM_ECHO_ON, PAM_ERROR, PAM_INFO };

static int to_daemon, from_daemon, to_child, from_child;
static const char *user;
static uid_t user_uid;

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static void write_all(int fd, const void *p, size_t n)
{
	while (n) {
		ssize_t k = write(fd, p, n);
		if (k < 0 && errno == EINTR)
			continue;
		if (k <= 0)
			exit(1);
		p = (const char *)p + k;
		n -= k;
	}
}

/* A packet: kind, then the body from up to three pieces (u32 or string). */
static void send_packet(int fd, uint32_t kind, const void *body, size_t n)
{
	uint8_t h[8];
	put32(h, kind);
	put32(h + 4, n);
	write_all(fd, h, 8);
	if (n)
		write_all(fd, body, n);
}

/* ---- reading LightDM's bodies -------------------------------------------- */

typedef struct {
	const uint8_t *p;
	size_t n, at;
	int err;
} rd;

static uint32_t r32(rd *r)
{
	if (r->at + 4 > r->n) {
		r->err = 1;
		return 0;
	}
	r->at += 4;
	return get32(r->p + r->at - 4);
}

/* A string, pointed at, not copied; its length in *len. */
static const uint8_t *rstr(rd *r, uint32_t *len)
{
	*len = r32(r);
	if (r->err || r->at + *len > r->n) {
		r->err = 1;
		*len = 0;
		return NULL;
	}
	r->at += *len;
	return r->p + r->at - *len;
}

/* ---- the conversation ---------------------------------------------------- */

static struct {
	uint32_t serial;      /* our sequence numbers towards LightDM */
	int have_local;       /* the greeter has asked to authenticate */
	uint32_t local_seq;   /* its sequence number, for answers to it */
	uint32_t local_kind;  /* and what it asked, to ask again */
	uint8_t local_body[1024];
	size_t local_len;
	int remote;           /* a remote login has LightDM */
	char pass[2048];
	int answered, starting, started, ready;
} cv;

static int client = -1;
static time_t deadline;

static void reply(int status)
{
	if (client >= 0) {
		uint8_t b = status;
		(void)!write(client, &b, 1);
		close(client);
		client = -1;
	}
}

/* An authentication request under our own sequence number. */
static void authenticate(uint32_t kind, const uint8_t *rest, size_t n)
{
	uint8_t b[4 + sizeof cv.local_body];
	cv.serial++;
	put32(b, cv.serial);
	memcpy(b + 4, rest, n);
	send_packet(to_daemon, kind, b, 4 + n);
}

static void forget_pass(void)
{
	explicit_bzero(cv.pass, sizeof cv.pass);
}

static void fail(int status)
{
	if (!cv.remote)
		return;
	forget_pass();
	cv.remote = cv.starting = 0;
	send_packet(to_daemon, G_CANCEL, NULL, 0);
	reply(status);
	/* the greeter's own conversation back, after a bad password or a
	 * client gone; never with its password, it asks again */
	if (cv.have_local)
		authenticate(cv.local_kind, cv.local_body, cv.local_len);
}

static void from_greeter(uint32_t kind, const uint8_t *body, size_t n)
{
	if (cv.started)
		return;
	if (kind == G_AUTH || kind == G_AUTH_GUEST || kind == G_AUTH_REMOTE) {
		if (n < 4 || n - 4 > sizeof cv.local_body)
			exit(1);
		cv.have_local = 1;
		cv.local_seq = get32(body);
		cv.local_kind = kind;
		cv.local_len = n - 4;
		memcpy(cv.local_body, body + 4, n - 4);
		if (!cv.remote)
			authenticate(kind, cv.local_body, cv.local_len);
	} else if (!cv.remote) {
		if (kind == G_START)
			cv.started = 1;
		send_packet(to_daemon, kind, body, n);
	}
}

static void begin(const char *u, const char *pass)
{
	if (!cv.ready || cv.remote || cv.started) {
		reply(3);
		return;
	}
	if (strcmp(u, user) || !*pass) {
		reply(1);
		return;
	}
	cv.remote = 1;
	cv.answered = cv.starting = 0;
	snprintf(cv.pass, sizeof cv.pass, "%s", pass);
	/* AUTHENTICATE ends whatever LightDM was doing for the greeter */
	uint8_t b[4 + 256];
	size_t ul = strlen(user);
	put32(b, ul);
	memcpy(b + 4, user, ul);
	authenticate(G_AUTH, b, 4 + ul);
}

static void from_lightdm(uint32_t kind, const uint8_t *body, size_t n)
{
	if (kind == D_CONNECTED || kind == D_CONNECTED_V2)
		cv.ready = 1;
	if (kind == D_PROMPT || kind == D_END) {
		rd r = {body, n, 0, 0};
		uint32_t seq = r32(&r), ulen;
		const uint8_t *u = rstr(&r, &ulen);
		if (r.err)
			exit(1);
		if (seq != cv.serial)
			return; /* an answer to a conversation since replaced */
		if (!cv.remote) {
			if (cv.have_local) {
				uint8_t *b = malloc(n);
				memcpy(b, body, n);
				put32(b, cv.local_seq);
				send_packet(to_child, kind, b, n);
				free(b);
			}
			return;
		}
		if (ulen != strlen(user) || memcmp(u, user, ulen)) {
			fail(1);
			return;
		}
		if (kind == D_PROMPT) {
			uint32_t count = r32(&r), secret = 0, other = 0;
			for (uint32_t i = 0; i < count && !r.err; i++) {
				uint32_t style = r32(&r), tl;
				rstr(&r, &tl);
				if (style == PAM_ECHO_OFF)
					secret++;
				else if (style != PAM_ERROR && style != PAM_INFO)
					other++;
			}
			if (r.err)
				exit(1);
			if (!secret && !other)
				return; /* messages only: LightDM carries on */
			/* exactly one password: not for OTPs or a new password */
			if (secret != 1 || other || cv.answered) {
				fail(2);
				return;
			}
			cv.answered = 1;
			size_t pl = strlen(cv.pass);
			uint8_t *b = malloc(8 + pl);
			put32(b, 1);
			put32(b + 4, pl);
			memcpy(b + 8, cv.pass, pl);
			send_packet(to_daemon, G_CONTINUE, b, 8 + pl);
			explicit_bzero(b, 8 + pl);
			free(b);
			forget_pass();
		} else if (r32(&r) != 0 || !cv.answered) {
			/* a real password check, even for nopasswdlogin */
			fail(1);
		} else {
			cv.starting = 1;
			/* LightDM may stop us while handling START, before the
			 * result comes: answer first. "" is the user's own session. */
			reply(0);
			uint8_t b[4] = {0};
			send_packet(to_daemon, G_START, b, 4);
		}
	} else if (kind == D_SESSION_RESULT && cv.remote && cv.starting) {
		rd r = {body, n, 0, 0};
		if (r32(&r) != 0) {
			fail(1);
		} else {
			cv.remote = cv.starting = 0;
			cv.started = 1;
		}
	} else if (!cv.remote) {
		send_packet(to_child, kind, body, n);
	}
}

/* ---- the remote side ----------------------------------------------------- */

static uint8_t req[4096];
static size_t req_len;

static void client_accept(int ls)
{
	int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
	if (c < 0)
		return;
	struct ucred cr;
	socklen_t l = sizeof cr;
	if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &l) || cr.uid != user_uid || client >= 0 || cv.started) {
		close(c);
		return;
	}
	client = c;
	req_len = 0;
	deadline = time(NULL) + 20;
}

static void client_read(void)
{
	ssize_t k = read(client, req + req_len, sizeof req - req_len);
	if (k <= 0 || cv.remote) {
		/* gone, or more than one request */
		if (cv.remote)
			fail(3);
		else
			reply(3);
		return;
	}
	req_len += k;
	if (req_len < 4)
		return;
	uint32_t ul = get32(req);
	if (ul > 256 || 8 + ul > sizeof req) {
		reply(1);
		return;
	}
	if (req_len < 8 + ul)
		return;
	uint32_t pl = get32(req + 4 + ul);
	if (pl >= sizeof cv.pass || 8 + ul + pl > sizeof req) {
		reply(1);
		return;
	}
	if (req_len < 8 + ul + pl)
		return;
	char u[257], p[sizeof cv.pass];
	memcpy(u, req + 4, ul);
	u[ul] = 0;
	memcpy(p, req + 8 + ul, pl);
	p[pl] = 0;
	int bad = req_len != 8 + ul + pl || memchr(u, 0, ul) || memchr(p, 0, pl);
	explicit_bzero(req, sizeof req);
	req_len = 0;
	if (bad)
		reply(1);
	else
		begin(u, p);
	explicit_bzero(p, sizeof p);
}

/* ---- plumbing ------------------------------------------------------------ */

typedef struct {
	uint8_t *p;
	size_t n;
} inbuf;

/* Read what's there and hand over each whole packet; 0 at EOF. */
static int pipe_read(int fd, inbuf *in, void (*each)(uint32_t, const uint8_t *, size_t))
{
	uint8_t tmp[8192];
	ssize_t k = read(fd, tmp, sizeof tmp);
	if (k < 0 && errno == EINTR)
		return 1;
	if (k <= 0)
		return 0;
	in->p = realloc(in->p, in->n + k);
	memcpy(in->p + in->n, tmp, k);
	in->n += k;
	size_t at = 0;
	while (in->n - at >= 8) {
		uint32_t kind = get32(in->p + at), size = get32(in->p + at + 4);
		if (size > MAX_PACKET)
			exit(1);
		if (in->n - at - 8 < size)
			break;
		each(kind, in->p + at + 8, size);
		at += 8 + size;
	}
	memmove(in->p, in->p + at, in->n - at);
	in->n -= at;
	return 1;
}

/* NAME onto this X server (xhost +SI:localuser:NAME), so rdesk-rdpc sees
 * the login screen; the session that follows has a cookie of its own. */
static void let_user_in(void)
{
	Display *d = XOpenDisplay(NULL);
	if (!d) {
		fprintf(stderr, "rdesk-greeter: no X display, rdesk-rdpc won't see the login screen\n");
		return;
	}
	XServerInterpretedAddress si = {9, (int)strlen(user), "localuser", (char *)user};
	XHostAddress h = {FamilyServerInterpreted, sizeof si, (char *)&si};
	XAddHost(d, &h);
	XCloseDisplay(d);
}

static int listen_sock(void)
{
	int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct sockaddr_un sa = {.sun_family = AF_UNIX};
	snprintf(sa.sun_path, sizeof sa.sun_path, "%s", sock);
	unlink(sock); /* its directory is lightdm's alone */
	if (s < 0 || bind(s, (struct sockaddr *)&sa, sizeof sa) || chmod(sock, 0666) || listen(s, 4)) {
		fprintf(stderr, "rdesk-greeter: no %s, local login only\n", sock);
		if (s >= 0)
			close(s);
		return -1;
	}
	return s;
}

int main(int argc, char **argv)
{
	struct rlimit no = {0, 0};
	setrlimit(RLIMIT_CORE, &no); /* passwords pass through here */
	if (argc < 4 || strcmp(argv[1], "--user") || strcmp(argv[3], "--")) {
		fprintf(stderr, "usage: rdesk-greeter --user NAME -- GREETER [ARGS]\n");
		return 2;
	}
	user = argv[2];
	char **greeter = argv + 4;
	struct passwd *pw = getpwnam(user);
	if (!*greeter || !pw || strlen(user) > 256) {
		fprintf(stderr, "rdesk-greeter: no greeter, or no user %s\n", user);
		return 2;
	}
	user_uid = pw->pw_uid;
	if (getenv("RDESK_GREETER_SOCK"))
		sock = getenv("RDESK_GREETER_SOCK");
	let_user_in();

	const char *t = getenv("LIGHTDM_TO_SERVER_FD"), *f = getenv("LIGHTDM_FROM_SERVER_FD");
	if (!t || !f) {
		/* not pipes: this LightDM is another kind; the plain greeter */
		fprintf(stderr, "rdesk-greeter: LightDM gave no pipes, plain greeter\n");
		execvp(greeter[0], greeter);
		return 1;
	}
	to_daemon = atoi(t);
	from_daemon = atoi(f);
	fcntl(to_daemon, F_SETFD, FD_CLOEXEC);
	fcntl(from_daemon, F_SETFD, FD_CLOEXEC);

	int down[2], up[2]; /* to the greeter, from it */
	if (pipe2(down, O_CLOEXEC) || pipe2(up, O_CLOEXEC))
		return 1;
	pid_t pid = fork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		char a[16], b[16];
		fcntl(down[0], F_SETFD, 0);
		fcntl(up[1], F_SETFD, 0);
		snprintf(a, sizeof a, "%d", up[1]);
		snprintf(b, sizeof b, "%d", down[0]);
		setenv("LIGHTDM_TO_SERVER_FD", a, 1);
		setenv("LIGHTDM_FROM_SERVER_FD", b, 1);
		execvp(greeter[0], greeter);
		_exit(127);
	}
	close(down[0]);
	close(up[1]);
	to_child = down[1];
	from_child = up[0];
	signal(SIGPIPE, SIG_IGN);

	int ls = listen_sock();
	inbuf din = {0}, cin = {0};
	for (;;) {
		if (waitpid(pid, NULL, WNOHANG) == pid)
			break;
		struct pollfd p[4] = {{from_daemon, POLLIN, 0}, {from_child, POLLIN, 0}, {ls, POLLIN, 0}, {client, POLLIN, 0}};
		if (poll(p, 4, 250) < 0 && errno != EINTR)
			break;
		if (p[0].revents && !pipe_read(from_daemon, &din, from_lightdm))
			break;
		if (p[1].revents && !pipe_read(from_child, &cin, from_greeter))
			break;
		if (ls >= 0 && p[2].revents)
			client_accept(ls);
		if (client >= 0 && p[3].revents)
			client_read();
		if ((client >= 0 || cv.remote) && time(NULL) >= deadline) {
			if (cv.remote)
				fail(3);
			else
				reply(3);
		}
	}
	reply(3);
	forget_pass();
	if (ls >= 0)
		unlink(sock);
	kill(pid, SIGTERM);
	for (int i = 0; i < 20 && waitpid(pid, NULL, WNOHANG) == 0; i++)
		usleep(100000);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return 0;
}
