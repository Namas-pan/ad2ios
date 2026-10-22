/* Host shim for <libkern/crypto/sha1.h> (tools/wpa-unit only). */
#ifndef _WPAUNIT_LIBKERN_CRYPTO_SHA1_H_
#define _WPAUNIT_LIBKERN_CRYPTO_SHA1_H_

#include <sys/param.h>

#define SHA1_BLOCK_LENGTH   64
#define SHA1_DIGEST_LENGTH  20

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	uint8_t buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;

int SHA1Init(SHA1_CTX *context);
int SHA1Update(SHA1_CTX *context, const void *data, size_t len);
int SHA1Final(uint8_t digest[SHA1_DIGEST_LENGTH], SHA1_CTX *context);

#endif
