/* nla.c - CredSSP over TLS: TSRequest (DER), SPNEGO, NTLMv2 with
 * extended session security, key exchange and MIC. MD4 and RC4 are here
 * because OpenSSL 3 only has them in the legacy provider. */
#include "nla.h"

#include <ctype.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- MD4, RC4, MD5, HMAC-MD5 ------------------------------------------ */

#define ROL(x, s) ((x) << (s) | (x) >> (32 - (s)))

static void md4_block(uint32_t st[4], const uint8_t *p)
{
	static const uint8_t k2[16] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
	static const uint8_t k3[16] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
	static const uint8_t s1[4] = {3, 7, 11, 19}, s2[4] = {3, 5, 9, 13}, s3[4] = {3, 9, 11, 15};
	uint32_t X[16], a = st[0], b = st[1], c = st[2], d = st[3], t;
	for (int i = 0; i < 16; i++)
		X[i] = p[4 * i] | p[4 * i + 1] << 8 | p[4 * i + 2] << 16 | (uint32_t)p[4 * i + 3] << 24;
	for (int i = 0; i < 16; i++) {
		t = a + ((b & c) | (~b & d)) + X[i];
		t = ROL(t, s1[i % 4]);
		a = d; d = c; c = b; b = t;
	}
	for (int i = 0; i < 16; i++) {
		t = a + ((b & c) | (b & d) | (c & d)) + X[k2[i]] + 0x5a827999;
		t = ROL(t, s2[i % 4]);
		a = d; d = c; c = b; b = t;
	}
	for (int i = 0; i < 16; i++) {
		t = a + (b ^ c ^ d) + X[k3[i]] + 0x6ed9eba1;
		t = ROL(t, s3[i % 4]);
		a = d; d = c; c = b; b = t;
	}
	st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

void md4(const uint8_t *p, size_t n, uint8_t out[16])
{
	uint32_t st[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
	size_t i;
	for (i = 0; i + 64 <= n; i += 64)
		md4_block(st, p + i);
	uint8_t tail[128] = {0};
	size_t r = n - i;
	memcpy(tail, p + i, r);
	tail[r] = 0x80;
	size_t tl = r + 9 <= 64 ? 64 : 128;
	uint64_t bits = (uint64_t)n * 8;
	for (int k = 0; k < 8; k++)
		tail[tl - 8 + k] = bits >> (8 * k);
	md4_block(st, tail);
	if (tl == 128)
		md4_block(st, tail + 64);
	for (int k = 0; k < 4; k++)
		for (int j = 0; j < 4; j++)
			out[4 * k + j] = st[k] >> (8 * j);
}

typedef struct {
	uint8_t s[256];
	uint8_t i, j;
} rc4;

static void rc4_init(rc4 *r, const uint8_t *key, size_t n)
{
	for (int i = 0; i < 256; i++)
		r->s[i] = i;
	uint8_t j = 0;
	for (int i = 0; i < 256; i++) {
		j += r->s[i] + key[i % n];
		uint8_t t = r->s[i];
		r->s[i] = r->s[j];
		r->s[j] = t;
	}
	r->i = r->j = 0;
}

static void rc4_xor(rc4 *r, const uint8_t *in, uint8_t *out, size_t n)
{
	for (size_t k = 0; k < n; k++) {
		r->i++;
		r->j += r->s[r->i];
		uint8_t t = r->s[r->i];
		r->s[r->i] = r->s[r->j];
		r->s[r->j] = t;
		out[k] = in[k] ^ r->s[(uint8_t)(r->s[r->i] + r->s[r->j])];
	}
}

static void md5_2(const void *a, size_t an, const void *b, size_t bn, uint8_t out[16])
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	EVP_DigestInit_ex(c, EVP_md5(), NULL);
	EVP_DigestUpdate(c, a, an);
	if (bn)
		EVP_DigestUpdate(c, b, bn);
	EVP_DigestFinal_ex(c, out, NULL);
	EVP_MD_CTX_free(c);
}

/* HMAC-MD5 over up to three concatenated parts. */
static void hmac_md5(const uint8_t key[16], const void *a, size_t an, const void *b, size_t bn,
		     const void *c, size_t cn, uint8_t out[16])
{
	uint8_t ipad[64], opad[64], inner[16];
	memset(ipad, 0x36, 64);
	memset(opad, 0x5c, 64);
	for (int i = 0; i < 16; i++) {
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}
	EVP_MD_CTX *x = EVP_MD_CTX_new();
	EVP_DigestInit_ex(x, EVP_md5(), NULL);
	EVP_DigestUpdate(x, ipad, 64);
	if (an)
		EVP_DigestUpdate(x, a, an);
	if (bn)
		EVP_DigestUpdate(x, b, bn);
	if (cn)
		EVP_DigestUpdate(x, c, cn);
	EVP_DigestFinal_ex(x, inner, NULL);
	EVP_MD_CTX_free(x);
	md5_2(opad, 64, inner, 16, out);
}

void nt_hash(const char *pass, uint8_t out[16])
{
	buf b;
	b_init(&b, 128);
	w_utf16(&b, pass, 0);
	md4(b.p, b.len, out);
	memset(b.p, 0, b.len);
	b_free(&b);
}

int read_nthash(const char *path, uint8_t out[16])
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	char hex[64] = {0};
	if (!fgets(hex, sizeof hex, f))
		hex[0] = 0;
	fclose(f);
	for (int i = 0; i < 16; i++) {
		unsigned v;
		if (!isxdigit((unsigned char)hex[2 * i]) || !isxdigit((unsigned char)hex[2 * i + 1]) ||
		    sscanf(hex + 2 * i, "%2x", &v) != 1)
			return -1;
		out[i] = v;
	}
	return 0;
}

int write_nthash(const char *path, const char *pass)
{
	uint8_t h[16], old[16];
	nt_hash(pass, h);
	if (read_nthash(path, old) == 0 && !memcmp(h, old, 16))
		return 0;
	char tmp[600], hex[34];
	snprintf(tmp, sizeof tmp, "%s.tmp%d", path, (int)getpid());
	for (int i = 0; i < 16; i++)
		sprintf(hex + 2 * i, "%02x", h[i]);
	hex[32] = '\n';
	unlink(tmp);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -1;
	int ok = write(fd, hex, 33) == 33;
	close(fd);
	if (!ok || rename(tmp, path)) {
		unlink(tmp);
		return -1;
	}
	return 1;
}

/* ---- DER -------------------------------------------------------------- */

static size_t der_begin(buf *b, uint8_t tag)
{
	w_u8(b, tag);
	size_t at = b->len;
	w_zero(b, 4);
	return at;
}

static void der_end(buf *b, size_t at)
{
	size_t n = b->len - at - 4;
	uint8_t l[4];
	int k;
	if (n < 0x80) {
		l[0] = n; k = 1;
	} else if (n < 0x100) {
		l[0] = 0x81; l[1] = n; k = 2;
	} else if (n < 0x10000) {
		l[0] = 0x82; l[1] = n >> 8; l[2] = n; k = 3;
	} else {
		l[0] = 0x83; l[1] = n >> 16; l[2] = n >> 8; l[3] = n; k = 4;
	}
	memcpy(b->p + at, l, k);
	memmove(b->p + at + k, b->p + at + 4, n);
	b->len -= 4 - k;
}

/* INTEGER, minimal two's complement of a signed 32-bit value (errorCode
 * 0xC000006D goes out as 02 04 c0 00 00 6d, like Windows and FreeRDP). */
static void der_int(buf *b, uint32_t v)
{
	uint8_t t[4] = {v >> 24, v >> 16, v >> 8, v};
	int i = 0;
	while (i < 3 && ((t[i] == 0 && !(t[i + 1] & 0x80)) || (t[i] == 0xff && (t[i + 1] & 0x80))))
		i++;
	w_u8(b, 0x02);
	w_u8(b, 4 - i);
	w_bytes(b, t + i, 4 - i);
}

static void der_octets(buf *b, const uint8_t *p, size_t n)
{
	size_t at = der_begin(b, 0x04);
	w_bytes(b, p, n);
	der_end(b, at);
}

/* [ctx] { OCTET STRING } */
static void der_ctx_octets(buf *b, uint8_t ctx, const uint8_t *p, size_t n)
{
	size_t at = der_begin(b, 0xa0 | ctx);
	der_octets(b, p, n);
	der_end(b, at);
}

/* Read tag + length; *in becomes the contents; b advances past it. */
static int der_get(buf *b, uint8_t tag, buf *in)
{
	if (r_left(b) < 2 || b->p[b->pos] != tag)
		return -1;
	r_u8(b);
	size_t n;
	if (r_ber_len(b, &n) || r_left(b) < n)
		return -1;
	in->p = b->p + b->pos;
	in->len = n;
	in->pos = 0;
	in->err = 0;
	in->cap = 0;
	b->pos += n;
	return 0;
}

static int der_peek(const buf *b)
{
	return r_left(b) ? b->p[b->pos] : -1;
}

static uint32_t der_uint(buf *in)
{
	uint32_t v = 0;
	while (r_left(in))
		v = v << 8 | r_u8(in);
	return v;
}

/* ---- TSRequest ---------------------------------------------------------- */

typedef struct {
	uint32_t version;
	buf token, auth, pubkey, nonce;
	int has_token, has_auth, has_pubkey, has_nonce, has_error;
	uint32_t error;
} tsreq;

static int read_der_pdu(conn *c, buf *b)
{
	uint8_t h[6];
	b_reset(b);
	if (c_read(c, h, 2))
		return -1;
	if (h[0] != 0x30) {
		msg("CredSSP: expected TSRequest, got 0x%02x", h[0]);
		return -1;
	}
	size_t n, have = 2;
	if (h[1] < 0x80) {
		n = h[1];
	} else {
		int k = h[1] & 0x7f;
		if (k < 1 || k > 3 || c_read(c, h + 2, k))
			return -1;
		n = 0;
		for (int i = 0; i < k; i++)
			n = n << 8 | h[2 + i];
		have += k;
	}
	b_reserve(b, have + n);
	memcpy(b->p, h, have);
	if (c_read(c, b->p + have, n))
		return -1;
	b->len = have + n;
	hexdump("<- tsrequest", b->p, b->len);
	return 0;
}

static int parse_tsreq(buf *b, tsreq *t)
{
	memset(t, 0, sizeof *t);
	buf seq, f, x;
	b->pos = 0;
	if (der_get(b, 0x30, &seq))
		return -1;
	while (r_left(&seq)) {
		int tag = der_peek(&seq);
		if (der_get(&seq, tag, &f))
			return -1;
		switch (tag) {
		case 0xa0:
			if (der_get(&f, 0x02, &x))
				return -1;
			t->version = der_uint(&x);
			break;
		case 0xa1: { /* SEQUENCE OF SEQUENCE { [0] OCTET STRING } */
			buf s1, s2, c0;
			if (der_get(&f, 0x30, &s1) || der_get(&s1, 0x30, &s2) ||
			    der_get(&s2, 0xa0, &c0) || der_get(&c0, 0x04, &t->token))
				return -1;
			t->has_token = 1;
			break;
		}
		case 0xa2:
			if (der_get(&f, 0x04, &t->auth))
				return -1;
			t->has_auth = 1;
			break;
		case 0xa3:
			if (der_get(&f, 0x04, &t->pubkey))
				return -1;
			t->has_pubkey = 1;
			break;
		case 0xa4:
			if (der_get(&f, 0x02, &x))
				return -1;
			t->error = der_uint(&x);
			t->has_error = 1;
			break;
		case 0xa5:
			if (der_get(&f, 0x04, &t->nonce))
				return -1;
			t->has_nonce = 1;
			break;
		}
	}
	return 0;
}

static int send_tsreq(conn *c, uint32_t version, const buf *token, const buf *auth,
		      const buf *pubkey, const uint8_t *nonce, uint32_t error)
{
	buf b;
	b_init(&b, 1024);
	size_t s = der_begin(&b, 0x30);
	size_t v = der_begin(&b, 0xa0);
	der_int(&b, version);
	der_end(&b, v);
	if (token) {
		size_t a1 = der_begin(&b, 0xa1);
		size_t q1 = der_begin(&b, 0x30);
		size_t q2 = der_begin(&b, 0x30);
		der_ctx_octets(&b, 0, token->p, token->len);
		der_end(&b, q2);
		der_end(&b, q1);
		der_end(&b, a1);
	}
	if (auth)
		der_ctx_octets(&b, 2, auth->p, auth->len);
	if (pubkey)
		der_ctx_octets(&b, 3, pubkey->p, pubkey->len);
	if (error) {
		size_t e = der_begin(&b, 0xa4);
		der_int(&b, error);
		der_end(&b, e);
	}
	if (nonce)
		der_ctx_octets(&b, 5, nonce, 32);
	der_end(&b, s);
	hexdump("-> tsrequest", b.p, b.len);
	int r = c_write(c, b.p, b.len);
	b_free(&b);
	return r;
}

/* ---- NTLM ------------------------------------------------------------- */

#define NTLM_UNICODE 0x00000001
#define NTLM_REQUEST_TARGET 0x00000004
#define NTLM_SIGN 0x00000010
#define NTLM_SEAL 0x00000020
#define NTLM_NTLM 0x00000200
#define NTLM_ALWAYS_SIGN 0x00008000
#define NTLM_TARGET_TYPE_SERVER 0x00020000
#define NTLM_ESS 0x00080000
#define NTLM_TARGET_INFO 0x00800000
#define NTLM_VERSION 0x02000000
#define NTLM_128 0x20000000
#define NTLM_KEY_EXCH 0x40000000
#define NTLM_56 0x80000000

#define AV_EOL 0
#define AV_NB_COMPUTER 1
#define AV_NB_DOMAIN 2
#define AV_DNS_COMPUTER 3
#define AV_DNS_DOMAIN 4
#define AV_FLAGS 6
#define AV_TIMESTAMP 7

static const uint8_t ntlm_version[8] = {10, 0, 0x63, 0x45, 0, 0, 0, 15};
static const uint8_t oid_ntlm[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};
static const uint8_t oid_spnego[] = {0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};

typedef struct {
	int server;
	uint32_t flags;
	uint8_t exported[16];
	uint8_t sign_out[16], sign_in[16], seal_out_key[16], seal_in_key[16];
	rc4 seal_out, seal_in;
	uint32_t seq_out, seq_in;
	buf neg, chal, auth; /* raw messages, for the MIC */
	uint8_t server_chal[8];
	int spnego;
	buf mechtypes; /* DER MechTypeList as sent by the client */
} ntlm;

static void ntlm_free(ntlm *n)
{
	b_free(&n->neg);
	b_free(&n->chal);
	b_free(&n->auth);
	b_free(&n->mechtypes);
	memset(n, 0, sizeof *n);
}

static void derive_keys(ntlm *n)
{
	static const char c2s_sign[] = "session key to client-to-server signing key magic constant";
	static const char s2c_sign[] = "session key to server-to-client signing key magic constant";
	static const char c2s_seal[] = "session key to client-to-server sealing key magic constant";
	static const char s2c_seal[] = "session key to server-to-client sealing key magic constant";
	uint8_t cs[16], ss[16], ck[16], sk[16];
	md5_2(n->exported, 16, c2s_sign, sizeof c2s_sign, cs);
	md5_2(n->exported, 16, s2c_sign, sizeof s2c_sign, ss);
	md5_2(n->exported, 16, c2s_seal, sizeof c2s_seal, ck);
	md5_2(n->exported, 16, s2c_seal, sizeof s2c_seal, sk);
	memcpy(n->sign_out, n->server ? ss : cs, 16);
	memcpy(n->sign_in, n->server ? cs : ss, 16);
	memcpy(n->seal_out_key, n->server ? sk : ck, 16);
	memcpy(n->seal_in_key, n->server ? ck : sk, 16);
	rc4_init(&n->seal_out, n->seal_out_key, 16);
	rc4_init(&n->seal_in, n->seal_in_key, 16);
	n->seq_out = n->seq_in = 0;
}

static void reset_out(ntlm *n)
{
	rc4_init(&n->seal_out, n->seal_out_key, 16);
}

static void reset_in(ntlm *n)
{
	rc4_init(&n->seal_in, n->seal_in_key, 16);
}

/* 16-byte signature over msg with the outgoing keys (MakeSignature). */
static void ntlm_sign(ntlm *n, const uint8_t *msg, size_t len, uint8_t sig[16])
{
	uint8_t seq[4] = {n->seq_out, n->seq_out >> 8, n->seq_out >> 16, n->seq_out >> 24};
	uint8_t mac[16];
	hmac_md5(n->sign_out, seq, 4, msg, len, NULL, 0, mac);
	sig[0] = 1; sig[1] = sig[2] = sig[3] = 0;
	rc4_xor(&n->seal_out, mac, sig + 4, 8);
	memcpy(sig + 12, seq, 4);
	n->seq_out++;
}

static int ntlm_verify(ntlm *n, const uint8_t *msg, size_t len, const uint8_t sig[16])
{
	uint8_t seq[4] = {n->seq_in, n->seq_in >> 8, n->seq_in >> 16, n->seq_in >> 24};
	uint8_t mac[16], cks[8];
	hmac_md5(n->sign_in, seq, 4, msg, len, NULL, 0, mac);
	rc4_xor(&n->seal_in, mac, cks, 8);
	n->seq_in++;
	return memcmp(cks, sig + 4, 8) || memcmp(seq, sig + 12, 4) ? -1 : 0;
}

/* EncryptMessage: out = signature(16) || RC4(msg). */
static void ntlm_seal(ntlm *n, const uint8_t *msg, size_t len, buf *out)
{
	uint8_t seq[4] = {n->seq_out, n->seq_out >> 8, n->seq_out >> 16, n->seq_out >> 24};
	uint8_t mac[16];
	hmac_md5(n->sign_out, seq, 4, msg, len, NULL, 0, mac);
	b_reset(out);
	b_reserve(out, 16 + len);
	out->p[0] = 1; out->p[1] = out->p[2] = out->p[3] = 0;
	rc4_xor(&n->seal_out, msg, out->p + 16, len);
	rc4_xor(&n->seal_out, mac, out->p + 4, 8);
	memcpy(out->p + 12, seq, 4);
	out->len = 16 + len;
	n->seq_out++;
}

static int ntlm_unseal(ntlm *n, const buf *in, buf *out)
{
	if (in->len < 16)
		return -1;
	size_t len = in->len - 16;
	b_reset(out);
	b_reserve(out, len + 1);
	rc4_xor(&n->seal_in, in->p + 16, out->p, len);
	out->len = len;
	uint8_t seq[4] = {n->seq_in, n->seq_in >> 8, n->seq_in >> 16, n->seq_in >> 24};
	uint8_t mac[16], cks[8];
	hmac_md5(n->sign_in, seq, 4, out->p, len, NULL, 0, mac);
	rc4_xor(&n->seal_in, mac, cks, 8);
	n->seq_in++;
	if (memcmp(cks, in->p + 4, 8) || memcmp(seq, in->p + 12, 4)) {
		msg("NTLM: bad message signature");
		return -1;
	}
	return 0;
}

static void ntowfv2(const uint8_t nthash[16], const char *user, const char *domain, uint8_t out[16])
{
	char up[256];
	size_t i;
	for (i = 0; user[i] && i < sizeof up - 1; i++)
		up[i] = toupper((unsigned char)user[i]);
	up[i] = 0;
	buf b;
	b_init(&b, 256);
	w_utf16(&b, up, 0);
	w_utf16(&b, domain, 0);
	hmac_md5(nthash, b.p, b.len, NULL, 0, NULL, 0, out);
	b_free(&b);
}

static uint64_t filetime_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ((uint64_t)ts.tv_sec + 11644473600ULL) * 10000000ULL + ts.tv_nsec / 100;
}

/* Security buffer field (len, maxlen, offset) -> sub-buffer of msg. */
static int ntlm_field(const buf *m, size_t at, buf *out)
{
	if (at + 8 > m->len)
		return -1;
	uint16_t len = m->p[at] | m->p[at + 1] << 8;
	uint32_t off = m->p[at + 4] | m->p[at + 5] << 8 | m->p[at + 6] << 16 | (uint32_t)m->p[at + 7] << 24;
	if ((size_t)off + len > m->len)
		return -1;
	*out = (buf){.p = m->p + off, .len = len};
	return 0;
}

static void w_field(buf *b, size_t len, size_t off)
{
	w_u16(b, len);
	w_u16(b, len);
	w_u32(b, off);
}

static void w_av(buf *b, uint16_t id, const void *p, size_t n)
{
	w_u16(b, id);
	w_u16(b, n);
	w_bytes(b, p, n);
}

static void w_av_str(buf *b, uint16_t id, const char *s)
{
	buf t;
	b_init(&t, 64);
	w_utf16(&t, s, 0);
	w_av(b, id, t.p, t.len);
	b_free(&t);
}

/* ---- SPNEGO ------------------------------------------------------------- */

/* NegTokenInit offering NTLM only, with the NTLM token. */
static void spnego_init(ntlm *n, const buf *tok, buf *out)
{
	b_reset(&n->mechtypes);
	size_t m = der_begin(&n->mechtypes, 0x30);
	w_bytes(&n->mechtypes, oid_ntlm, sizeof oid_ntlm);
	der_end(&n->mechtypes, m);

	b_reset(out);
	size_t app = der_begin(out, 0x60);
	w_bytes(out, oid_spnego, sizeof oid_spnego);
	size_t a0 = der_begin(out, 0xa0);
	size_t s = der_begin(out, 0x30);
	size_t mt = der_begin(out, 0xa0);
	w_bytes(out, n->mechtypes.p, n->mechtypes.len);
	der_end(out, mt);
	der_ctx_octets(out, 2, tok->p, tok->len);
	der_end(out, s);
	der_end(out, a0);
	der_end(out, app);
}

/* NegTokenResp. state < 0 omits negState; mech adds supportedMech NTLM. */
static void spnego_resp(int state, int mech, const buf *tok, const uint8_t *mic, buf *out)
{
	b_reset(out);
	size_t a1 = der_begin(out, 0xa1);
	size_t s = der_begin(out, 0x30);
	if (state >= 0) {
		size_t a0 = der_begin(out, 0xa0);
		w_u8(out, 0x0a);
		w_u8(out, 1);
		w_u8(out, state);
		der_end(out, a0);
	}
	if (mech) {
		size_t c = der_begin(out, 0xa1);
		w_bytes(out, oid_ntlm, sizeof oid_ntlm);
		der_end(out, c);
	}
	if (tok)
		der_ctx_octets(out, 2, tok->p, tok->len);
	if (mic)
		der_ctx_octets(out, 3, mic, 16);
	der_end(out, s);
	der_end(out, a1);
}

typedef struct {
	int state;           /* negState or -1 */
	int ntlm_first;      /* init: NTLM is the first mech type */
	int has_ntlm;        /* init: NTLM offered at all */
	buf tok, mic;
	int has_tok, has_mic;
	buf mechtypes;       /* init: raw MechTypeList */
} spnego_msg;

static int spnego_parse(const buf *in, spnego_msg *m)
{
	memset(m, 0, sizeof *m);
	m->state = -1;
	buf b = *in, outer, seq, f, x;
	b.pos = 0;
	if (der_peek(&b) == 0x60) {
		if (der_get(&b, 0x60, &outer))
			return -1;
		const uint8_t *oid = r_bytes(&outer, sizeof oid_spnego);
		if (!oid || memcmp(oid, oid_spnego, sizeof oid_spnego))
			return -1;
		if (der_get(&outer, 0xa0, &x) || der_get(&x, 0x30, &seq))
			return -1;
		while (r_left(&seq)) {
			int tag = der_peek(&seq);
			if (der_get(&seq, tag, &f))
				return -1;
			if (tag == 0xa0) {
				buf list;
				size_t start = f.pos;
				if (der_get(&f, 0x30, &list))
					return -1;
				m->mechtypes = (buf){.p = f.p + start, .len = f.pos - start};
				for (int i = 0; r_left(&list); i++) {
					buf o;
					size_t os = list.pos;
					if (der_get(&list, 0x06, &o))
						return -1;
					if (list.pos - os == sizeof oid_ntlm &&
					    !memcmp(list.p + os, oid_ntlm, sizeof oid_ntlm)) {
						m->has_ntlm = 1;
						if (i == 0)
							m->ntlm_first = 1;
					}
				}
			} else if (tag == 0xa2) {
				if (der_get(&f, 0x04, &m->tok))
					return -1;
				m->has_tok = 1;
			} else if (tag == 0xa3) {
				/* mechListMIC in init: ignore */
			}
		}
		return 0;
	}
	if (der_get(&b, 0xa1, &outer) || der_get(&outer, 0x30, &seq))
		return -1;
	while (r_left(&seq)) {
		int tag = der_peek(&seq);
		if (der_get(&seq, tag, &f))
			return -1;
		if (tag == 0xa0) {
			if (der_get(&f, 0x0a, &x))
				return -1;
			m->state = der_uint(&x);
		} else if (tag == 0xa2) {
			if (der_get(&f, 0x04, &m->tok))
				return -1;
			m->has_tok = 1;
		} else if (tag == 0xa3) {
			if (der_get(&f, 0x04, &m->mic) || m->mic.len != 16)
				return -1;
			m->has_mic = 1;
		}
	}
	return 0;
}

/* ---- public key binding -------------------------------------------------- */

static int peer_or_own_pubkey(conn *c, int server, buf *out)
{
	X509 *x = server ? SSL_get_certificate(c->ssl) : SSL_get1_peer_certificate(c->ssl);
	if (!x)
		return -1;
	EVP_PKEY *pk = X509_get0_pubkey(x);
	unsigned char *der = NULL;
	int n = pk ? i2d_PublicKey(pk, &der) : -1;
	if (!server)
		X509_free(x);
	if (n <= 0)
		return -1;
	b_reset(out);
	w_bytes(out, der, n);
	OPENSSL_free(der);
	return 0;
}

static void binding_hash(int client_to_server, const uint8_t nonce[32], const buf *pub, uint8_t out[32])
{
	static const char c2s[] = "CredSSP Client-To-Server Binding Hash";
	static const char s2c[] = "CredSSP Server-To-Client Binding Hash";
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	EVP_DigestInit_ex(c, EVP_sha256(), NULL);
	EVP_DigestUpdate(c, client_to_server ? c2s : s2c, sizeof c2s); /* includes NUL */
	EVP_DigestUpdate(c, nonce, 32);
	EVP_DigestUpdate(c, pub->p, pub->len);
	EVP_DigestFinal_ex(c, out, NULL);
	EVP_MD_CTX_free(c);
}

#define CREDSSP_VERSION 6
#define STATUS_LOGON_FAILURE 0xc000006d

/* ---- client ------------------------------------------------------------- */

int credssp_client(conn *c, const char *user, const char *domain, const char *pass)
{
	ntlm n = {0};
	n.flags = NTLM_56 | NTLM_KEY_EXCH | NTLM_128 | NTLM_VERSION | NTLM_ESS | NTLM_ALWAYS_SIGN |
		  NTLM_NTLM | NTLM_SEAL | NTLM_SIGN | NTLM_REQUEST_TARGET | NTLM_UNICODE;
	b_init(&n.neg, 64);
	b_init(&n.chal, 256);
	b_init(&n.auth, 512);
	b_init(&n.mechtypes, 32);
	buf rx, tok, pub, sealed, plain;
	b_init(&rx, 4096);
	b_init(&tok, 1024);
	b_init(&pub, 512);
	b_init(&sealed, 1024);
	b_init(&plain, 1024);
	int rc = -1;
	tsreq t;

	if (peer_or_own_pubkey(c, 0, &pub)) {
		msg("CredSSP: no server public key");
		goto out;
	}

	/* NEGOTIATE */
	w_bytes(&n.neg, "NTLMSSP", 8);
	w_u32(&n.neg, 1);
	w_u32(&n.neg, n.flags);
	w_field(&n.neg, 0, 40);
	w_field(&n.neg, 0, 40);
	w_bytes(&n.neg, ntlm_version, 8);
	/* Raw NTLMSSP like mstsc and FreeRDP 2 when only NTLM is usable;
	 * RDESK_SPNEGO=1 wraps it in SPNEGO instead. */
	n.spnego = getenv("RDESK_SPNEGO") && *getenv("RDESK_SPNEGO") == '1';
	if (n.spnego) {
		spnego_init(&n, &n.neg, &tok);
	} else {
		b_reset(&tok);
		w_bytes(&tok, n.neg.p, n.neg.len);
	}
	if (send_tsreq(c, CREDSSP_VERSION, &tok, NULL, NULL, NULL, 0))
		goto out;

	/* CHALLENGE */
	if (read_der_pdu(c, &rx) || parse_tsreq(&rx, &t))
		goto out;
	if (t.has_error) {
		msg("CredSSP: server error 0x%08x", t.error);
		goto out;
	}
	uint32_t version = t.version < CREDSSP_VERSION ? t.version : CREDSSP_VERSION;
	spnego_msg sm;
	if (t.has_token && t.token.len >= 8 && !memcmp(t.token.p, "NTLMSSP", 8)) {
		w_bytes(&n.chal, t.token.p, t.token.len);
	} else {
		if (!t.has_token || spnego_parse(&t.token, &sm) || !sm.has_tok) {
			msg("CredSSP: no NTLM challenge");
			goto out;
		}
		if (sm.state == 2) {
			msg("CredSSP: server rejected NTLM");
			goto out;
		}
		w_bytes(&n.chal, sm.tok.p, sm.tok.len);
	}
	if (n.chal.len < 48 || memcmp(n.chal.p, "NTLMSSP", 8) || n.chal.p[8] != 2) {
		msg("CredSSP: bad NTLM challenge");
		goto out;
	}
	buf ch = n.chal, tinfo;
	ch.pos = 20;
	uint32_t sflags = r_u32(&ch);
	memcpy(n.server_chal, n.chal.p + 24, 8);
	if (ntlm_field(&n.chal, 40, &tinfo)) {
		msg("CredSSP: bad target info");
		goto out;
	}
	n.flags &= sflags | NTLM_VERSION;

	/* temp blob: copy AV pairs, add MsvAvFlags (MIC present) */
	uint64_t ts = 0;
	buf av;
	b_init(&av, tinfo.len + 32);
	{
		buf ti = tinfo;
		while (r_left(&ti) >= 4) {
			uint16_t id = r_u16(&ti), len = r_u16(&ti);
			const uint8_t *v = r_bytes(&ti, len);
			if (!v || id == AV_EOL)
				break;
			if (id == AV_FLAGS)
				continue;
			if (id == AV_TIMESTAMP && len == 8)
				for (int i = 7; i >= 0; i--)
					ts = ts << 8 | v[i];
			w_av(&av, id, v, len);
		}
	}
	uint8_t avflags[4] = {2, 0, 0, 0};
	w_av(&av, AV_FLAGS, avflags, 4);
	w_av(&av, AV_EOL, NULL, 0);
	if (!ts)
		ts = filetime_now();

	uint8_t cchal[8];
	RAND_bytes(cchal, 8);
	buf temp;
	b_init(&temp, av.len + 32);
	w_u8(&temp, 1);
	w_u8(&temp, 1);
	w_zero(&temp, 6);
	w_u32(&temp, ts);
	w_u32(&temp, ts >> 32);
	w_bytes(&temp, cchal, 8);
	w_zero(&temp, 4);
	w_bytes(&temp, av.p, av.len);
	w_zero(&temp, 4);
	b_free(&av);

	uint8_t nth[16], owf[16], proof[16], base[16];
	nt_hash(pass, nth);
	ntowfv2(nth, user, domain, owf);
	hmac_md5(owf, n.server_chal, 8, temp.p, temp.len, NULL, 0, proof);
	hmac_md5(owf, proof, 16, NULL, 0, NULL, 0, base);
	RAND_bytes(n.exported, 16);
	uint8_t enckey[16];
	rc4 r;
	rc4_init(&r, base, 16);
	rc4_xor(&r, n.exported, enckey, 16);

	/* AUTHENTICATE */
	buf d16, u16, w16;
	b_init(&d16, 64);
	b_init(&u16, 64);
	b_init(&w16, 64);
	w_utf16(&d16, domain, 0);
	w_utf16(&u16, user, 0);
	w_utf16(&w16, "RDESK-C", 0);
	size_t off = 88;
	w_bytes(&n.auth, "NTLMSSP", 8);
	w_u32(&n.auth, 3);
	size_t o_dom = off, o_user = o_dom + d16.len, o_ws = o_user + u16.len;
	size_t o_lm = o_ws + w16.len, o_nt = o_lm + 24, o_key = o_nt + 16 + temp.len;
	w_field(&n.auth, 24, o_lm);
	w_field(&n.auth, 16 + temp.len, o_nt);
	w_field(&n.auth, d16.len, o_dom);
	w_field(&n.auth, u16.len, o_user);
	w_field(&n.auth, w16.len, o_ws);
	w_field(&n.auth, 16, o_key);
	w_u32(&n.auth, n.flags);
	w_bytes(&n.auth, ntlm_version, 8);
	w_zero(&n.auth, 16); /* MIC */
	w_bytes(&n.auth, d16.p, d16.len);
	w_bytes(&n.auth, u16.p, u16.len);
	w_bytes(&n.auth, w16.p, w16.len);
	w_zero(&n.auth, 24);
	w_bytes(&n.auth, proof, 16);
	w_bytes(&n.auth, temp.p, temp.len);
	w_bytes(&n.auth, enckey, 16);
	b_free(&d16);
	b_free(&u16);
	b_free(&w16);
	b_free(&temp);
	uint8_t mic[16];
	hmac_md5(n.exported, n.neg.p, n.neg.len, n.chal.p, n.chal.len, n.auth.p, n.auth.len, mic);
	memcpy(n.auth.p + 72, mic, 16);
	derive_keys(&n);

	if (n.spnego) {
		/* SPNEGO mechListMIC, then the cipher state restarts */
		uint8_t mlmic[16];
		ntlm_sign(&n, n.mechtypes.p, n.mechtypes.len, mlmic);
		reset_out(&n);
		n.seq_out = 0;
		spnego_resp(-1, 0, &n.auth, mlmic, &tok);
	} else {
		b_reset(&tok);
		w_bytes(&tok, n.auth.p, n.auth.len);
	}

	uint8_t nonce[32];
	RAND_bytes(nonce, 32);
	if (version >= 5) {
		uint8_t h[32];
		binding_hash(1, nonce, &pub, h);
		ntlm_seal(&n, h, 32, &sealed);
	} else {
		ntlm_seal(&n, pub.p, pub.len, &sealed);
	}
	if (send_tsreq(c, version, &tok, NULL, &sealed, version >= 5 ? nonce : NULL, 0))
		goto out;

	/* server's public key echo */
	if (read_der_pdu(c, &rx) || parse_tsreq(&rx, &t))
		goto out;
	if (t.has_error) {
		msg("CredSSP: server error 0x%08x%s", t.error,
		    t.error == STATUS_LOGON_FAILURE ? " (logon failure: wrong user or password)" : "");
		goto out;
	}
	if (n.spnego && t.has_token && !spnego_parse(&t.token, &sm)) {
		if (sm.state == 2) {
			msg("CredSSP: server rejected authentication");
			goto out;
		}
		if (sm.has_mic) {
			if (ntlm_verify(&n, n.mechtypes.p, n.mechtypes.len, sm.mic.p)) {
				msg("CredSSP: bad server mechListMIC");
				goto out;
			}
			reset_in(&n);
			n.seq_in = 0;
		}
	}
	if (!t.has_pubkey || ntlm_unseal(&n, &t.pubkey, &plain)) {
		msg("CredSSP: no valid public key echo");
		goto out;
	}
	if (version >= 5) {
		uint8_t h[32];
		binding_hash(0, nonce, &pub, h);
		if (plain.len != 32 || memcmp(plain.p, h, 32)) {
			msg("CredSSP: server public key hash mismatch");
			goto out;
		}
	} else {
		pub.p[0]++;
		if (plain.len != pub.len || memcmp(plain.p, pub.p, pub.len)) {
			msg("CredSSP: server public key mismatch");
			goto out;
		}
	}

	/* delegate the password: TSCredentials { 1, TSPasswordCreds } */
	buf pc;
	b_init(&pc, 512);
	size_t s = der_begin(&pc, 0x30);
	b_reset(&plain);
	w_utf16(&plain, domain, 0);
	der_ctx_octets(&pc, 0, plain.p, plain.len);
	b_reset(&plain);
	w_utf16(&plain, user, 0);
	der_ctx_octets(&pc, 1, plain.p, plain.len);
	b_reset(&plain);
	w_utf16(&plain, pass, 0);
	der_ctx_octets(&pc, 2, plain.p, plain.len);
	memset(plain.p, 0, plain.len);
	der_end(&pc, s);
	buf cr;
	b_init(&cr, pc.len + 32);
	s = der_begin(&cr, 0x30);
	size_t a0 = der_begin(&cr, 0xa0);
	der_int(&cr, 1);
	der_end(&cr, a0);
	der_ctx_octets(&cr, 1, pc.p, pc.len);
	der_end(&cr, s);
	ntlm_seal(&n, cr.p, cr.len, &sealed);
	memset(pc.p, 0, pc.len);
	memset(cr.p, 0, cr.len);
	b_free(&pc);
	b_free(&cr);
	if (send_tsreq(c, version, NULL, &sealed, NULL, NULL, 0))
		goto out;
	dbg("CredSSP v%u done", version);
	rc = 0;
out:
	b_free(&rx);
	b_free(&tok);
	b_free(&pub);
	b_free(&sealed);
	b_free(&plain);
	ntlm_free(&n);
	return rc;
}

/* ---- server ------------------------------------------------------------- */

static void server_challenge(ntlm *n, buf *out)
{
	char host[256] = "rdesk";
	gethostname(host, sizeof host);
	host[sizeof host - 1] = 0;
	char *dot = strchr(host, '.');
	if (dot)
		*dot = 0;
	char nb[16];
	size_t i;
	for (i = 0; host[i] && i < 15; i++)
		nb[i] = toupper((unsigned char)host[i]);
	nb[i] = 0;

	buf name, av;
	b_init(&name, 64);
	b_init(&av, 256);
	w_utf16(&name, nb, 0);
	w_av_str(&av, AV_NB_DOMAIN, nb);
	w_av_str(&av, AV_NB_COMPUTER, nb);
	w_av_str(&av, AV_DNS_DOMAIN, host);
	w_av_str(&av, AV_DNS_COMPUTER, host);
	uint64_t ts = filetime_now();
	uint8_t tsb[8];
	for (int k = 0; k < 8; k++)
		tsb[k] = ts >> (8 * k);
	w_av(&av, AV_TIMESTAMP, tsb, 8);
	w_av(&av, AV_EOL, NULL, 0);

	RAND_bytes(n->server_chal, 8);
	b_reset(out);
	w_bytes(out, "NTLMSSP", 8);
	w_u32(out, 2);
	w_field(out, name.len, 56);
	w_u32(out, n->flags);
	w_bytes(out, n->server_chal, 8);
	w_zero(out, 8);
	w_field(out, av.len, 56 + name.len);
	w_bytes(out, ntlm_version, 8);
	w_bytes(out, name.p, name.len);
	w_bytes(out, av.p, av.len);
	b_free(&name);
	b_free(&av);
}

static void utf16_field(const buf *m, size_t at, char *out, size_t outsz)
{
	buf f;
	if (ntlm_field(m, at, &f)) {
		out[0] = 0;
		return;
	}
	r_utf16(&f, f.len, out, outsz);
}

/* Check AUTHENTICATE against the NT hash; sets n->exported. */
static int server_check(ntlm *n, const uint8_t nthash[16], nla_creds *who)
{
	buf *a = &n->auth, nt, ek;
	if (a->len < 88 || memcmp(a->p, "NTLMSSP", 8) || a->p[8] != 3)
		return -1;
	if (ntlm_field(a, 20, &nt) || nt.len < 16 + 28)
		return -1;
	utf16_field(a, 28, who->domain, sizeof who->domain);
	utf16_field(a, 36, who->user, sizeof who->user);
	buf af = *a;
	af.pos = 60;
	uint32_t flags = r_u32(&af);
	uint8_t owf[16], proof[16], base[16];
	ntowfv2(nthash, who->user, who->domain, owf);
	hmac_md5(owf, n->server_chal, 8, nt.p + 16, nt.len - 16, NULL, 0, proof);
	if (memcmp(proof, nt.p, 16)) {
		msg("NTLM: wrong password for '%s' (domain '%s')", who->user, who->domain);
		return -1;
	}
	hmac_md5(owf, proof, 16, NULL, 0, NULL, 0, base);
	if (flags & NTLM_KEY_EXCH) {
		if (ntlm_field(a, 52, &ek) || ek.len != 16)
			return -1;
		rc4 r;
		rc4_init(&r, base, 16);
		rc4_xor(&r, ek.p, n->exported, 16);
	} else {
		memcpy(n->exported, base, 16);
	}
	n->flags = flags;

	/* MIC, when the client says it sent one (MsvAvFlags bit 1) */
	buf av = {.p = nt.p + 16 + 28, .len = nt.len - 16 - 28};
	int has_mic = 0;
	while (r_left(&av) >= 4) {
		uint16_t id = r_u16(&av), len = r_u16(&av);
		const uint8_t *v = r_bytes(&av, len);
		if (!v || id == AV_EOL)
			break;
		if (id == AV_FLAGS && len == 4 && (v[0] & 2))
			has_mic = 1;
	}
	if (has_mic) {
		uint8_t got[16], want[16];
		memcpy(got, a->p + 72, 16);
		memset(a->p + 72, 0, 16);
		hmac_md5(n->exported, n->neg.p, n->neg.len, n->chal.p, n->chal.len, a->p, a->len, want);
		memcpy(a->p + 72, got, 16);
		if (memcmp(got, want, 16)) {
			msg("NTLM: bad MIC");
			return -1;
		}
	}
	derive_keys(n);
	return 0;
}

int credssp_server(conn *c, const uint8_t nthash[16], nla_creds *who)
{
	ntlm n = {.server = 1};
	n.flags = NTLM_56 | NTLM_KEY_EXCH | NTLM_128 | NTLM_VERSION | NTLM_TARGET_INFO | NTLM_ESS |
		  NTLM_TARGET_TYPE_SERVER | NTLM_ALWAYS_SIGN | NTLM_NTLM | NTLM_SEAL | NTLM_SIGN |
		  NTLM_REQUEST_TARGET | NTLM_UNICODE;
	b_init(&n.neg, 64);
	b_init(&n.chal, 256);
	b_init(&n.auth, 512);
	b_init(&n.mechtypes, 64);
	buf rx, tok, pub, sealed, plain;
	b_init(&rx, 4096);
	b_init(&tok, 1024);
	b_init(&pub, 512);
	b_init(&sealed, 1024);
	b_init(&plain, 1024);
	int rc = -1;
	uint32_t version = 2;
	tsreq t;
	spnego_msg sm;
	memset(who, 0, sizeof *who);

	if (peer_or_own_pubkey(c, 1, &pub))
		goto out;

	/* NEGOTIATE, possibly after an SPNEGO mech switch */
	for (int round = 0;; round++) {
		if (round > 2 || read_der_pdu(c, &rx) || parse_tsreq(&rx, &t) || !t.has_token) {
			msg("CredSSP: no negotiate token");
			goto out;
		}
		version = t.version < CREDSSP_VERSION ? t.version : CREDSSP_VERSION;
		if (t.token.len >= 8 && !memcmp(t.token.p, "NTLMSSP", 8)) {
			w_bytes(&n.neg, t.token.p, t.token.len);
			break;
		}
		if (spnego_parse(&t.token, &sm)) {
			msg("CredSSP: unknown token 0x%02x", t.token.len ? t.token.p[0] : 0);
			goto out;
		}
		n.spnego = 1;
		if (sm.mechtypes.len) {
			b_reset(&n.mechtypes);
			w_bytes(&n.mechtypes, sm.mechtypes.p, sm.mechtypes.len);
			if (!sm.has_ntlm) {
				msg("CredSSP: client does not offer NTLM");
				spnego_resp(2, 0, NULL, NULL, &tok);
				send_tsreq(c, version, &tok, NULL, NULL, NULL, 0);
				goto out;
			}
		}
		if (sm.has_tok && sm.tok.len >= 8 && !memcmp(sm.tok.p, "NTLMSSP", 8) &&
		    (sm.ntlm_first || !sm.mechtypes.len)) {
			w_bytes(&n.neg, sm.tok.p, sm.tok.len);
			break;
		}
		/* client led with another mech (Kerberos): ask for NTLM */
		dbg("SPNEGO: switching client to NTLM");
		spnego_resp(1, 1, NULL, NULL, &tok);
		if (send_tsreq(c, version, &tok, NULL, NULL, NULL, 0))
			goto out;
	}
	if (n.neg.len < 16 || n.neg.p[8] != 1) {
		msg("CredSSP: bad NTLM negotiate");
		goto out;
	}
	n.flags &= (n.neg.p[12] | n.neg.p[13] << 8 | n.neg.p[14] << 16 | (uint32_t)n.neg.p[15] << 24) |
		   NTLM_TARGET_INFO | NTLM_TARGET_TYPE_SERVER | NTLM_VERSION;

	/* CHALLENGE */
	server_challenge(&n, &n.chal);
	if (n.spnego)
		spnego_resp(1, 1, &n.chal, NULL, &tok);
	else {
		b_reset(&tok);
		w_bytes(&tok, n.chal.p, n.chal.len);
	}
	if (send_tsreq(c, version, &tok, NULL, NULL, NULL, 0))
		goto out;

	/* AUTHENTICATE + pubKeyAuth */
	if (read_der_pdu(c, &rx) || parse_tsreq(&rx, &t) || !t.has_token) {
		msg("CredSSP: no authenticate token");
		goto out;
	}
	if (t.version && t.version < version)
		version = t.version;
	buf mic = {0};
	int has_mic = 0;
	if (t.token.len >= 8 && !memcmp(t.token.p, "NTLMSSP", 8)) {
		w_bytes(&n.auth, t.token.p, t.token.len);
	} else if (!spnego_parse(&t.token, &sm) && sm.has_tok) {
		w_bytes(&n.auth, sm.tok.p, sm.tok.len);
		mic = sm.mic;
		has_mic = sm.has_mic;
	} else {
		msg("CredSSP: bad authenticate token");
		goto out;
	}
	if (server_check(&n, nthash, who)) {
		if (version >= 3)
			send_tsreq(c, version, NULL, NULL, NULL, NULL, STATUS_LOGON_FAILURE);
		goto out;
	}
	uint8_t mymic[16];
	if (n.spnego) {
		if (has_mic) {
			if (ntlm_verify(&n, n.mechtypes.p, n.mechtypes.len, mic.p)) {
				msg("SPNEGO: bad client mechListMIC");
				goto out;
			}
			reset_in(&n);
			n.seq_in = 0;
		}
		ntlm_sign(&n, n.mechtypes.p, n.mechtypes.len, mymic);
		reset_out(&n);
		n.seq_out = 0;
	}
	if (!t.has_pubkey || ntlm_unseal(&n, &t.pubkey, &plain)) {
		msg("CredSSP: bad pubKeyAuth");
		goto out;
	}
	if (version >= 5) {
		uint8_t h[32];
		if (!t.has_nonce || t.nonce.len != 32) {
			msg("CredSSP: v%u without client nonce", version);
			goto out;
		}
		binding_hash(1, t.nonce.p, &pub, h);
		if (plain.len != 32 || memcmp(plain.p, h, 32)) {
			msg("CredSSP: public key hash mismatch (TLS interception?)");
			goto out;
		}
		binding_hash(0, t.nonce.p, &pub, h);
		ntlm_seal(&n, h, 32, &sealed);
	} else {
		if (plain.len != pub.len || memcmp(plain.p, pub.p, pub.len)) {
			msg("CredSSP: public key mismatch (TLS interception?)");
			goto out;
		}
		pub.p[0]++;
		ntlm_seal(&n, pub.p, pub.len, &sealed);
	}
	if (n.spnego)
		spnego_resp(0, 0, NULL, mymic, &tok);
	if (send_tsreq(c, version, n.spnego ? &tok : NULL, NULL, &sealed, NULL, 0))
		goto out;

	/* TSCredentials */
	if (read_der_pdu(c, &rx) || parse_tsreq(&rx, &t) || !t.has_auth ||
	    ntlm_unseal(&n, &t.auth, &plain)) {
		msg("CredSSP: no credentials");
		goto out;
	}
	{
		buf b = plain, seq, f, x, pc, ps;
		b.pos = 0;
		uint32_t type = 0;
		if (der_get(&b, 0x30, &seq) || der_get(&seq, 0xa0, &f) || der_get(&f, 0x02, &x))
			goto bad;
		type = der_uint(&x);
		if (type != 1) {
			msg("CredSSP: credential type %u (smartcard/remote guard) unsupported", type);
			goto out;
		}
		if (der_get(&seq, 0xa1, &f) || der_get(&f, 0x04, &pc) || der_get(&pc, 0x30, &ps))
			goto bad;
		char *dst[3] = {who->domain, who->user, who->pass};
		size_t sz[3] = {sizeof who->domain, sizeof who->user, sizeof who->pass};
		for (int i = 0; i < 3; i++) {
			if (der_get(&ps, 0xa0 | i, &f) || der_get(&f, 0x04, &x))
				goto bad;
			r_utf16(&x, x.len, dst[i], sz[i]);
		}
		memset(plain.p, 0, plain.len);
	}
	dbg("CredSSP v%u done, user '%s' domain '%s'", version, who->user, who->domain);
	rc = 0;
	goto out;
bad:
	msg("CredSSP: bad TSCredentials");
out:
	b_free(&rx);
	b_free(&tok);
	b_free(&pub);
	b_free(&sealed);
	b_free(&plain);
	ntlm_free(&n);
	return rc;
}
