/*
 * Host unit tests for the WPA2-PSK 4-way handshake crypto in
 * bsd/dev/topaz_wlan_wpa.c (patch 0132).
 *
 * The test #includes the kernel source itself, so the code being executed is
 * the code that ships in the kernel: no re-implementation, no drift. Only
 * libkern SHA-1 is replaced (tools/wpa-unit/sha1_host.c), and that replacement
 * is itself pinned to the FIPS 180-1 vector below.
 *
 * Output is one NAME=hex line per value; tools/wpa-unit/run.py compares those
 * against vectors from the standards and against an independent Python
 * implementation (hashlib/hmac).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "topaz_wlan_wpa.c"

static void
dump(const char *name, const uint8_t *p, unsigned n)
{
	unsigned i;

	printf("%s=", name);
	for (i = 0; i < n; i++) {
		printf("%02x", p[i]);
	}
	printf("\n");
}

/*
 * Authenticator-side EAPOL-Key encoder, written from the standard with literal
 * offsets (header 4 + body 95, MIC at body+77, key data at body+95). The tests
 * must not borrow the kernel's own layout macros, or a wrong offset would agree
 * with itself and still pass.
 */
#define AP_BODY   95u
#define AP_MIC    77u

static void
ap16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void
ap64(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 7; i >= 0; i--) {
		p[i] = (uint8_t)v;
		v >>= 8;
	}
}

static unsigned
ap_eapol(uint8_t *out, unsigned max, uint16_t key_info, uint64_t replay,
    const uint8_t nonce[32], const uint8_t *kd, unsigned kdlen,
    const uint8_t mic[16])
{
	unsigned body = AP_BODY + kdlen;
	uint8_t *b;

	if (4 + body > max) {
		return 0;
	}
	out[0] = 2;             /* EAPOL version */
	out[1] = 3;             /* EAPOL-Key */
	ap16(out + 2, (uint16_t)body);
	b = out + 4;
	memset(b, 0, body);
	b[0] = 0x02;            /* RSN key descriptor */
	ap16(b + 1, key_info);
	ap16(b + 3, 0);
	ap64(b + 5, replay);
	memcpy(b + 13, nonce, 32);
	memcpy(b + AP_MIC, mic, 16);
	ap16(b + 93, (uint16_t)kdlen);
	if (kdlen != 0) {
		memcpy(b + AP_BODY, kd, kdlen);
	}
	return 4 + body;
}

/*
 * RFC 3394 key wrap, written here so the incoming GTK test does not use the
 * kernel's own (unwrap-only) implementation as both stimulus and oracle.
 */
static unsigned
key_wrap(const uint8_t kek[16], const uint8_t *plain, unsigned plen,
    uint8_t *out)
{
	uint8_t rk[176], blk[16], enc[16];
	uint8_t a[8] = { 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6 };
	unsigned n = plen / 8, i, j, t;

	aes_expand(kek, rk);
	memcpy(out + 8, plain, plen);
	for (j = 0; j < 6; j++) {
		for (i = 1; i <= n; i++) {
			memcpy(blk, a, 8);
			memcpy(blk + 8, out + 8 * i, 8);
			aes_encrypt_block(rk, blk, enc);
			t = n * j + i;
			memcpy(a, enc, 8);
			a[4] ^= (uint8_t)(t >> 24);
			a[5] ^= (uint8_t)(t >> 16);
			a[6] ^= (uint8_t)(t >> 8);
			a[7] ^= (uint8_t)t;
			memcpy(out + 8 * i, enc + 8, 8);
		}
	}
	memcpy(out, a, 8);
	return plen + 8;
}

int
main(void)
{
	uint8_t sha1_abc[20];
	SHA1_CTX sctx;

	/* 0. check the host SHA-1 shim itself before trusting anything below */
	SHA1Init(&sctx);
	SHA1Update(&sctx, "abc", 3);
	SHA1Final(sha1_abc, &sctx);
	dump("sha1_abc", sha1_abc, sizeof(sha1_abc));

	/* 1. AES-128 block (FIPS-197 C.1) + decrypt roundtrip */
	{
		static const uint8_t key[16] = {
			0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
		};
		static const uint8_t pt[16] = {
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
			0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
		};
		uint8_t rk[176], ct[16], back[16];

		aes_expand(key, rk);
		aes_encrypt_block(rk, pt, ct);
		aes_decrypt_block(rk, ct, back);
		dump("aes_ecb", ct, 16);
		dump("aes_rt", back, 16);
	}

	/* 2. HMAC-SHA1 (RFC 2202 case 2) */
	{
		uint8_t out[20];

		hmac_sha1((const uint8_t *)"Jefe", 4,
		    (const uint8_t *)"what do ya want for nothing?", 28, out);
		dump("hmac", out, sizeof(out));
	}

	/* 3. PBKDF2-HMAC-SHA1: IEEE 802.11i passphrase vector + a second case */
	{
		uint8_t pmk[32];

		pbkdf2_sha1((const uint8_t *)"password", 8,
		    (const uint8_t *)"IEEE", 4, 4096, pmk, sizeof(pmk));
		dump("pbkdf2_a", pmk, sizeof(pmk));

		pbkdf2_sha1((const uint8_t *)"ThisIsAPassword", 15,
		    (const uint8_t *)"ThisIsASSID", 11, 4096, pmk, sizeof(pmk));
		dump("pbkdf2_b", pmk, sizeof(pmk));
	}

	/* 4. PRF-512 over a fixed 76-byte context (no nonce/mack sorting here) */
	{
		uint8_t key[32], data[76], out[48];
		unsigned i;

		for (i = 0; i < sizeof(key); i++) {
			key[i] = (uint8_t)i;
		}
		for (i = 0; i < sizeof(data); i++) {
			data[i] = (uint8_t)i;
		}
		prf_sha1(key, sizeof(key), "Pairwise key expansion", data,
		    sizeof(data), out, sizeof(out));
		dump("prf", out, sizeof(out));
	}

	/* 5. PTK derivation: sorted inputs, and the swap-invariance property */
	{
		static const uint8_t aa[6] = {0x02,0x11,0x22,0x33,0x44,0x55};
		static const uint8_t spa[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
		uint8_t pmk[32], anonce[32], snonce[32];
		uint8_t kck[16], kek[16], tk[16];
		uint8_t kck2[16], kek2[16], tk2[16], both[48];
		unsigned i;

		for (i = 0; i < 32; i++) {
			pmk[i] = (uint8_t)(0x40 + i);
			anonce[i] = (uint8_t)(0x80 + i);
			snonce[i] = (uint8_t)(0xc0 + i);
		}
		derive_ptk(pmk, aa, spa, anonce, snonce, kck, kek, tk);
		memcpy(both, kck, 16);
		memcpy(both + 16, kek, 16);
		memcpy(both + 32, tk, 16);
		dump("ptk", both, sizeof(both));

		/* deliberately wrong order: the 802.11i PRF sorts MACs and nonces */
		derive_ptk(pmk, spa, aa, snonce, anonce, kck2, kek2, tk2);
		memcpy(both, kck2, 16);
		memcpy(both + 16, kek2, 16);
		memcpy(both + 32, tk2, 16);
		dump("ptk_swap", both, sizeof(both));
	}

	/* 6. Key MIC: HMAC-SHA1 truncated to 16 octets over a fixed frame */
	{
		uint8_t kck[16], frame[32], mic[16];
		unsigned i;

		for (i = 0; i < 16; i++) {
			kck[i] = (uint8_t)i;
		}
		for (i = 0; i < 32; i++) {
			frame[i] = (uint8_t)(0x30 + i);
		}
		eapol_mic(kck, frame, sizeof(frame), mic);
		dump("mic", mic, sizeof(mic));
	}

	/* 7. RFC 3394 key unwrap of a 128-bit KEK (+ one corrupted block) */	{
		static const uint8_t kek[16] = {
			0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
		};
		static const uint8_t wrapped[24] = {
			0x1f,0xa6,0x8b,0x0a,0x81,0x12,0xb4,0x47,
			0xae,0xf3,0x4b,0xd8,0xfb,0x5a,0x7b,0x82,
			0x9d,0x3e,0x86,0x23,0x71,0xd2,0xcf,0xe5
		};
		uint8_t bad[24], plain[64];
		unsigned plen = 0;

		if (aes_key_unwrap(kek, wrapped, sizeof(wrapped), plain, &plen) == 0) {
			dump("unwrap", plain, plen);
		} else {
			printf("unwrap=fail\n");
		}
		memcpy(bad, wrapped, sizeof(bad));
		bad[3] ^= 0x01; /* must not authenticate */
		plen = 0;
		printf("unwrap_bad=%s\n",
		    aes_key_unwrap(kek, bad, sizeof(bad), plain, &plen) == 0 ?
		    "accepted" : "rejected");
	}

	/* 8. Full 4-way handshake against a synthetic authenticator */
	{
		static const uint8_t ssid[9] = "TopazTest";
		static const uint8_t spa[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
		static const uint8_t aa[6] = {0x02,0x11,0x22,0x33,0x44,0x55};
		uint8_t anonce[32], zmic[16], msg[256], out[512], mic[16];
		uint8_t tmp[256];
		struct topaz_wlan_wpa_keys keys;
		const uint8_t *b;
		unsigned i, n;
		int r, mic_ok;

		for (i = 0; i < sizeof(anonce); i++) {
			anonce[i] = (uint8_t)(0xa0 + i);
		}
		memset(zmic, 0, sizeof(zmic));
		topaz_wlan_wpa_start(ssid, sizeof(ssid) - 1, "0123456789", spa, aa,
		    NULL, 0);

		/* msg1 (pairwise|ack, no MIC) -> msg2 */
		n = (unsigned)ap_eapol(msg, sizeof(msg),
		    (uint16_t)(2 | KI_PAIRWISE | KI_ACK), 1, anonce, NULL, 0, zmic);
		r = topaz_wlan_wpa_on_eapol(msg, n, out, sizeof(out), &keys);
		b = out + 4;
		printf("eapol_msg2=%s\n",
		    (r == 4 + EAPOL_KEY_BODY + 22 &&
		    out[0] == EAPOL_VER && out[1] == EAPOL_TYPE_KEY &&
		    be16(out + 2) == EAPOL_KEY_BODY + 22 &&
		    be16(b + 1) == (2 | KI_PAIRWISE | KI_MIC) &&
		    get_be64(b + 5) == 1 &&
		    memcmp(b + 13, w_snonce, 32) == 0 &&
		    be16(b + 93) == 22 && b[95] == 48 && b[96] == 20) ? "ok" : "bad");

		/* msg2's MIC must verify under the derived KCK */
		memcpy(tmp, out, (size_t)r);
		bzero(tmp + (4 + AP_MIC), 16);
		eapol_mic(w_kck, tmp, (unsigned)r, mic);
		mic_ok = memcmp(mic, out + (4 + AP_MIC), 16) == 0;
		printf("eapol_msg2_mic=%s\n", mic_ok ? "ok" : "bad");

		/* msg3 with a valid MIC -> msg4 + TK install */
		n = (unsigned)ap_eapol(msg, sizeof(msg),
		    (uint16_t)(2 | KI_PAIRWISE | KI_MIC | KI_ACK | KI_SECURE), 2,
		    anonce, NULL, 0, zmic);
		eapol_mic(w_kck, msg, n, mic);
		memcpy(msg + (4 + AP_MIC), mic, 16);
		r = topaz_wlan_wpa_on_eapol(msg, n, out, sizeof(out), &keys);
		printf("eapol_msg4=%s\n",
		    (r == 4 + EAPOL_KEY_BODY && keys.done &&
		    memcmp(keys.tk, w_tk, 16) == 0 &&
		    be16(out + 4 + 1) ==
		    (2 | KI_PAIRWISE | KI_MIC | KI_SECURE)) ? "ok" : "bad");

		/* an all-zero MIC must be refused */
		memcpy(tmp, msg, n);
		bzero(tmp + (4 + AP_MIC), 16);
		r = topaz_wlan_wpa_on_eapol(tmp, n, out, sizeof(out), &keys);
		printf("eapol_badmic=%s\n", r < 0 ? "rejected" : "accepted");

		/* a replayed msg3 (older counter) with a valid MIC must be refused */
		ap_eapol(msg, sizeof(msg),
		    (uint16_t)(2 | KI_PAIRWISE | KI_MIC | KI_ACK | KI_SECURE), 0,
		    anonce, NULL, 0, zmic);
		eapol_mic(w_kck, msg, n, mic);
		memcpy(msg + (4 + AP_MIC), mic, 16);
		r = topaz_wlan_wpa_on_eapol(msg, n, out, sizeof(out), &keys);
		printf("eapol_replay=%s\n", r < 0 ? "rejected" : "accepted");
	}

	/* 9. msg3 carrying an encrypted GTK: RFC 3394 unwrap + KDE parse */
	{
		uint8_t anonce[32], gtk[16], kd[24], kd_enc[64], zmic[16];
		uint8_t msg3[256], out[512], mic[16];
		uint16_t info = (uint16_t)(2 | KI_PAIRWISE | KI_MIC | KI_ACK |
		    KI_INSTALL | KI_SECURE | KI_ENCRYPTED);
		struct topaz_wlan_wpa_keys keys;
		unsigned enclen, i, n3;
		int r;

		for (i = 0; i < sizeof(anonce); i++) {
			anonce[i] = (uint8_t)(0xa0 + i);
		}
		for (i = 0; i < sizeof(gtk); i++) {
			gtk[i] = (uint8_t)(0x30 + i);
		}
		/* KDE: 0xdd | len 22 | 00 0f ac 01 | key id | reserved | GTK */
		kd[0] = 0xdd;
		kd[1] = 22;
		kd[2] = 0x00;
		kd[3] = 0x0f;
		kd[4] = 0xac;
		kd[5] = 0x01;
		kd[6] = 0x01;   /* key id 1, TX bit clear */
		kd[7] = 0x00;
		memcpy(kd + 8, gtk, sizeof(gtk));
		enclen = key_wrap(w_kek, kd, sizeof(kd), kd_enc);

		memset(zmic, 0, sizeof(zmic));
		n3 = ap_eapol(msg3, sizeof(msg3), info, 2, anonce, kd_enc, enclen,
		    zmic);
		eapol_mic(w_kck, msg3, n3, mic);
		memcpy(msg3 + (4 + AP_MIC), mic, 16);
		r = topaz_wlan_wpa_on_eapol(msg3, n3, out, sizeof(out), &keys);
		printf("gtk_msg4=%s\n", r == 4 + EAPOL_KEY_BODY ? "ok" : "bad");
		printf("gtk_parsed=%s\n",
		    (keys.have_gtk && keys.gtk_len == sizeof(gtk) &&
		    keys.gtk_id == 1 &&
		    memcmp(keys.gtk, gtk, sizeof(gtk)) == 0) ? "ok" : "bad");

		/* a corrupted wrapped blob, with a valid MIC, must be refused */
		kd_enc[1] ^= 0x40;
		n3 = ap_eapol(msg3, sizeof(msg3), info, 3, anonce, kd_enc, enclen,
		    zmic);
		eapol_mic(w_kck, msg3, n3, mic);
		memcpy(msg3 + (4 + AP_MIC), mic, 16);
		r = topaz_wlan_wpa_on_eapol(msg3, n3, out, sizeof(out), &keys);
		printf("gtk_badwrap=%s\n", r < 0 ? "rejected" : "accepted");
	}

	return 0;
}
