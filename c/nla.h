/* nla.h - CredSSP (NLA) with SPNEGO/NTLMv2, client and server. */
#pragma once
#include "rdp.h"

void md4(const uint8_t *p, size_t n, uint8_t out[16]);
void nt_hash(const char *pass, uint8_t out[16]);
int read_nthash(const char *path, uint8_t out[16]); /* hex file; 0 ok */
int write_nthash(const char *path, const char *pass); /* 1 changed, 0 same, -1 err */

typedef struct {
	char user[256];
	char domain[256];
	char pass[512];
} nla_creds;

/* After TLS, before MCS. Client sends user/domain/pass; returns 0 on success. */
int credssp_client(conn *c, const char *user, const char *domain, const char *pass);

/* Server: authenticates the client against nthash (NTLMv2), returns the
 * credentials the client delegates. On NTLM failure the client is told
 * STATUS_LOGON_FAILURE. */
int credssp_server(conn *c, const uint8_t nthash[16], nla_creds *out);
