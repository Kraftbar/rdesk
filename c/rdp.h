/* rdp.h - shared RDP wire code for rdesk-c (server and client). */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>

/* ---- byte buffer ---------------------------------------------------- */

typedef struct {
	uint8_t *p;
	size_t len; /* bytes written / valid */
	size_t cap;
	size_t pos; /* read cursor */
	int err;    /* read past end or alloc failure */
} buf;

void b_init(buf *b, size_t cap);
void b_free(buf *b);
void b_reset(buf *b);
void b_reserve(buf *b, size_t n);
void w_u8(buf *b, uint8_t v);
void w_u16(buf *b, uint16_t v);   /* little endian */
void w_u16be(buf *b, uint16_t v);
void w_u32(buf *b, uint32_t v);
void w_u32be(buf *b, uint32_t v);
void w_bytes(buf *b, const void *p, size_t n);
void w_zero(buf *b, size_t n);
void w_utf16(buf *b, const char *s, int nul); /* ASCII/UTF-8 -> UTF-16LE */
void put_u16(buf *b, size_t at, uint16_t v);
void put_u16be(buf *b, size_t at, uint16_t v);
void put_u32(buf *b, size_t at, uint32_t v);

uint8_t r_u8(buf *b);
uint16_t r_u16(buf *b);
uint16_t r_u16be(buf *b);
uint32_t r_u32(buf *b);
uint32_t r_u32be(buf *b);
const uint8_t *r_bytes(buf *b, size_t n);
void r_skip(buf *b, size_t n);
size_t r_left(const buf *b);
void r_utf16(buf *b, size_t nbytes, char *out, size_t outsz); /* -> UTF-8 */

/* ---- connection ----------------------------------------------------- */

typedef struct {
	int fd;
	SSL *ssl;
} conn;

int c_read(conn *c, void *p, size_t n);        /* exact, 0 ok / -1 */
int c_write(conn *c, const void *p, size_t n); /* exact, 0 ok / -1 */
int c_pending(conn *c);
/* Read one TPKT or fast-path PDU into b (whole PDU, b->pos at 0).
 * *fastpath = 1 for fast-path. Returns 0 / -1. */
int read_pdu(conn *c, buf *b, int *fastpath);

/* ---- encoding helpers ------------------------------------------------ */

void w_ber_len(buf *b, size_t n);
int r_ber_len(buf *b, size_t *n);
int r_ber_tag(buf *b, unsigned tag, size_t *n); /* tag may be 2-byte 0x7fXX */
void w_per_len(buf *b, size_t n);
size_t r_per_len(buf *b);

/* TPKT + X.224 data + MCS send data (request if from client) */
int send_mcs(conn *c, int indication, uint16_t user, uint16_t chan,
	     const uint8_t *p, size_t n);
/* The same PDU appended to b, unsent. */
void mcs_put(buf *b, int indication, uint16_t user, uint16_t chan, const uint8_t *p, size_t n);
/* Parse TPKT+X224 data+MCS domain PDU header. Returns MCS type (choice>>2),
 * fills user/chan for send-data PDUs and leaves b->pos at the payload. */
int parse_mcs(buf *b, uint16_t *user, uint16_t *chan);

/* ---- protocol constants ---------------------------------------------- */

#define PROTOCOL_RDP 0
#define PROTOCOL_SSL 1
#define PROTOCOL_HYBRID 2

#define MCS_ERECT 1
#define MCS_DPUM 8
#define MCS_AURQ 10
#define MCS_AUCF 11
#define MCS_CJRQ 14
#define MCS_CJCF 15
#define MCS_SDRQ 25
#define MCS_SDIN 26

#define MCS_IO_CHANNEL 1003

#define SEC_INFO_PKT 0x0040
#define SEC_LICENSE_PKT 0x0080

#define PDU_DEMAND_ACTIVE 1
#define PDU_CONFIRM_ACTIVE 3
#define PDU_DEACTIVATE_ALL 6
#define PDU_DATA 7

#define PDU2_UPDATE 0x02
#define PDU2_CONTROL 0x14
#define PDU2_POINTER 0x1B
#define PDU2_INPUT 0x1C
#define PDU2_SYNC 0x1F
#define PDU2_REFRESH_RECT 0x21
#define PDU2_SUPPRESS_OUTPUT 0x23
#define PDU2_SHUTDOWN_REQ 0x24
#define PDU2_SHUTDOWN_DENIED 0x25
#define PDU2_SAVE_SESSION_INFO 0x26
#define PDU2_FONTLIST 0x27
#define PDU2_FONTMAP 0x28
#define PDU2_SET_KBD_INDICATORS 0x29
#define PDU2_PERSIST_KEYS 0x2B
#define PDU2_SET_ERROR_INFO 0x2F

#define CTRL_REQUEST 1
#define CTRL_GRANTED 2
#define CTRL_DETACH 3
#define CTRL_COOPERATE 4

#define CAP_GENERAL 1
#define CAP_BITMAP 2
#define CAP_ORDER 3
#define CAP_POINTER 8
#define CAP_SHARE 9
#define CAP_INPUT 13
#define CAP_FONT 14
#define CAP_VC 20
#define CAP_MULTIFRAG 26

/* fast-path output */
#define FP_UPD_ORDERS 0x0
#define FP_UPD_BITMAP 0x1
#define FP_UPD_PTR_NULL 0x5
#define FP_UPD_PTR_DEFAULT 0x6
#define FP_UPD_PTR_POSITION 0x8
#define FP_UPD_COLOR 0x9
#define FP_UPD_CACHED 0xA
#define FP_UPD_POINTER 0xB
#define FP_FRAG_SINGLE 0
#define FP_FRAG_LAST 1
#define FP_FRAG_FIRST 2
#define FP_FRAG_NEXT 3

/* fast-path input */
#define FP_IN_SCANCODE 0
#define FP_IN_MOUSE 1
#define FP_IN_MOUSEX 2
#define FP_IN_SYNC 3
#define FP_IN_UNICODE 4
#define FP_IN_QOE 6
#define KBD_RELEASE 0x01
#define KBD_EXTENDED 0x02

#define PTR_WHEEL_NEG 0x0100
#define PTR_WHEEL 0x0200
#define PTR_HWHEEL 0x0400
#define PTR_MOVE 0x0800
#define PTR_BUTTON1 0x1000
#define PTR_BUTTON2 0x2000
#define PTR_BUTTON3 0x4000
#define PTR_DOWN 0x8000
#define PTRX_DOWN 0x8000
#define PTRX_BUTTON1 0x0001
#define PTRX_BUTTON2 0x0002

/* Build a share control header + data PDU and send on the IO channel. */
typedef struct {
	conn *c;
	int server;       /* 1: we are the server (send indications) */
	uint16_t user;    /* MCS user id (initiator) */
	uint32_t share_id;
} session;

int send_share(session *s, uint16_t type, const uint8_t *p, size_t n);
int send_data(session *s, uint8_t type2, const uint8_t *p, size_t n);
/* Parse the share control header: returns pdu type, b->pos after header.
 * For data PDUs also reads the share data header and sets *type2. */
int parse_share(buf *b, uint8_t *type2);

/* Fast-path: write header for a PDU of n payload bytes. */
void fp_header(buf *b, uint8_t hdr, size_t n);

extern int verbose;
void msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void dbg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void hexdump(const char *label, const uint8_t *p, size_t n);

/* Set-1 scancode (ext = E0 prefix) <-> Linux evdev code; 0 if unmapped. */
int sc_to_evdev(uint8_t sc, int ext);
int evdev_to_sc(int ev, int *ext);

/* Static virtual channel: send one PDU in 1600-byte chunks; reassemble
 * chunks into acc, returning 1 when a whole PDU is in acc. */
int vc_send(conn *c, int indication, uint16_t user, uint16_t chan, const uint8_t *p, size_t n);
/* The same, appended to out (server to client), unsent. */
void vc_put(buf *out, uint16_t user, uint16_t chan, const uint8_t *p, size_t n);
int vc_recv(buf *acc, buf *b);
void fp_update(buf *out, uint8_t code, const uint8_t *p, size_t n);
