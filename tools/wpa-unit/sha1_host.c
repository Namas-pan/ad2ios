/*
 * Plain FIPS 180-1 SHA-1 for the host unit tests (tools/wpa-unit).
 *
 * The kernel code under test gets SHA-1 from libkern, which we cannot link on
 * the host. This is a deliberate second implementation: the tests check the
 * WPA2 derivation and MIC logic against an independent implementation, so a
 * bug in one does not hide a bug in the other.
 */
#include <string.h>
#include "libkern/crypto/sha1.h"

#define ROL(v, b) (((v) << (b)) | ((v) >> (32 - (b))))

static void
sha1_block(uint32_t h[5], const uint8_t *p)
{
	uint32_t w[80], a, b, c, d, e, t;
	unsigned i;

	for (i = 0; i < 16; i++) {
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
		    ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
	}
	for (i = 16; i < 80; i++) {
		w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}
	a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
	for (i = 0; i < 80; i++) {
		uint32_t f, k;

		if (i < 20) {
			f = (b & c) | (~b & d);
			k = 0x5a827999u;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ed9eba1u;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8f1bbcdcu;
		} else {
			f = b ^ c ^ d;
			k = 0xca62c1d6u;
		}
		t = ROL(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = t;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

int
SHA1Init(SHA1_CTX *ctx)
{
	ctx->state[0] = 0x67452301u;
	ctx->state[1] = 0xefcdab89u;
	ctx->state[2] = 0x98badcfeu;
	ctx->state[3] = 0x10325476u;
	ctx->state[4] = 0xc3d2e1f0u;
	ctx->count[0] = ctx->count[1] = 0;
	memset(ctx->buffer, 0, sizeof(ctx->buffer));
	return 0;
}

int
SHA1Update(SHA1_CTX *ctx, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	size_t used = ctx->count[1] & 0x3fu;

	ctx->count[1] += (uint32_t)len;
	if (ctx->count[1] < len) {
		ctx->count[0]++;
	}
	ctx->count[0] += (uint32_t)(len >> 29);
	if (used != 0) {
		size_t room = SHA1_BLOCK_LENGTH - used;

		if (len < room) {
			memcpy(ctx->buffer + used, p, len);
			return 0;
		}
		memcpy(ctx->buffer + used, p, room);
		sha1_block(ctx->state, ctx->buffer);
		p += room;
		len -= room;
	}
	while (len >= SHA1_BLOCK_LENGTH) {
		sha1_block(ctx->state, p);
		p += SHA1_BLOCK_LENGTH;
		len -= SHA1_BLOCK_LENGTH;
	}
	if (len != 0) {
		memcpy(ctx->buffer, p, len);
	}
	return 0;
}

int
SHA1Final(uint8_t digest[SHA1_DIGEST_LENGTH], SHA1_CTX *ctx)
{
	uint8_t pad[72];
	uint64_t bits = ((uint64_t)ctx->count[0] << 32) | ctx->count[1];
	size_t used = ctx->count[1] & 0x3fu, padlen;
	unsigned i;

	bits *= 8;
	padlen = (used < 56) ? (56 - used) : (120 - used);
	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;
	for (i = 0; i < 8; i++) {
		pad[padlen + i] = (uint8_t)(bits >> (56 - 8 * i));
	}
	SHA1Update(ctx, pad, padlen + 8);
	for (i = 0; i < 5; i++) {
		digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
		digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
		digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
		digest[i * 4 + 3] = (uint8_t)ctx->state[i];
	}
	return 0;
}
