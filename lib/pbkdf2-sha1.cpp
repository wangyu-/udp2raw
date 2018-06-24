/*
   this file is from https://github.com/kholia/PKCS5_PBKDF2

*
 *  FIPS-180-1 compliant SHA-1 implementation
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  The SHA-1 standard was published by NIST in 1993.
 *
 *  http://www.itl.nist.gov/fipspubs/fip180-1.htm
 *
 *  Copyright 2012 Mathias Olsson mathias@kompetensum.com
 *
 *  This file is dual licensed as either GPL version 2 or Apache License 2.0 at your choice
 *  http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *  http://www.apache.org/licenses/
 *
 *  Note that PolarSSL uses GPL with a FOSS License Exception */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(TEST) ||defined(DEBUG)
#undef TEST 
#undef DEBUG
#warning "undefined TEST/DEBUG"
#endif

typedef struct {
	unsigned long total[2];	/*!< number of bytes processed  */
	unsigned long state[5];	/*!< intermediate digest state  */
	unsigned char buffer[64];	/*!< data block being processed */

	unsigned char ipad[64];	/*!< HMAC: inner padding        */
	unsigned char opad[64];	/*!< HMAC: outer padding        */
} sha1_context;

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 * SHA-1 context setup
 */
void sha1_starts(sha1_context * ctx)
{
	ctx->total[0] = 0;
	ctx->total[1] = 0;

	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
}

static void sha1_process(sha1_context * ctx, const unsigned char data[64])
{
	unsigned long temp, W[16], A, B, C, D, E;

	GET_ULONG_BE(W[0], data, 0);
	GET_ULONG_BE(W[1], data, 4);
	GET_ULONG_BE(W[2], data, 8);
	GET_ULONG_BE(W[3], data, 12);
	GET_ULONG_BE(W[4], data, 16);
	GET_ULONG_BE(W[5], data, 20);
	GET_ULONG_BE(W[6], data, 24);
	GET_ULONG_BE(W[7], data, 28);
	GET_ULONG_BE(W[8], data, 32);
	GET_ULONG_BE(W[9], data, 36);
	GET_ULONG_BE(W[10], data, 40);
	GET_ULONG_BE(W[11], data, 44);
	GET_ULONG_BE(W[12], data, 48);
	GET_ULONG_BE(W[13], data, 52);
	GET_ULONG_BE(W[14], data, 56);
	GET_ULONG_BE(W[15], data, 60);

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W[0]);
	P(E, A, B, C, D, W[1]);
	P(D, E, A, B, C, W[2]);
	P(C, D, E, A, B, W[3]);
	P(B, C, D, E, A, W[4]);
	P(A, B, C, D, E, W[5]);
	P(E, A, B, C, D, W[6]);
	P(D, E, A, B, C, W[7]);
	P(C, D, E, A, B, W[8]);
	P(B, C, D, E, A, W[9]);
	P(A, B, C, D, E, W[10]);
	P(E, A, B, C, D, W[11]);
	P(D, E, A, B, C, W[12]);
	P(C, D, E, A, B, W[13]);
	P(B, C, D, E, A, W[14]);
	P(A, B, C, D, E, W[15]);
	P(E, A, B, C, D, R(16));
	P(D, E, A, B, C, R(17));
	P(C, D, E, A, B, R(18));
	P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R(20));
	P(E, A, B, C, D, R(21));
	P(D, E, A, B, C, R(22));
	P(C, D, E, A, B, R(23));
	P(B, C, D, E, A, R(24));
	P(A, B, C, D, E, R(25));
	P(E, A, B, C, D, R(26));
	P(D, E, A, B, C, R(27));
	P(C, D, E, A, B, R(28));
	P(B, C, D, E, A, R(29));
	P(A, B, C, D, E, R(30));
	P(E, A, B, C, D, R(31));
	P(D, E, A, B, C, R(32));
	P(C, D, E, A, B, R(33));
	P(B, C, D, E, A, R(34));
	P(A, B, C, D, E, R(35));
	P(E, A, B, C, D, R(36));
	P(D, E, A, B, C, R(37));
	P(C, D, E, A, B, R(38));
	P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R(40));
	P(E, A, B, C, D, R(41));
	P(D, E, A, B, C, R(42));
	P(C, D, E, A, B, R(43));
	P(B, C, D, E, A, R(44));
	P(A, B, C, D, E, R(45));
	P(E, A, B, C, D, R(46));
	P(D, E, A, B, C, R(47));
	P(C, D, E, A, B, R(48));
	P(B, C, D, E, A, R(49));
	P(A, B, C, D, E, R(50));
	P(E, A, B, C, D, R(51));
	P(D, E, A, B, C, R(52));
	P(C, D, E, A, B, R(53));
	P(B, C, D, E, A, R(54));
	P(A, B, C, D, E, R(55));
	P(E, A, B, C, D, R(56));
	P(D, E, A, B, C, R(57));
	P(C, D, E, A, B, R(58));
	P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, R(60));
	P(E, A, B, C, D, R(61));
	P(D, E, A, B, C, R(62));
	P(C, D, E, A, B, R(63));
	P(B, C, D, E, A, R(64));
	P(A, B, C, D, E, R(65));
	P(E, A, B, C, D, R(66));
	P(D, E, A, B, C, R(67));
	P(C, D, E, A, B, R(68));
	P(B, C, D, E, A, R(69));
	P(A, B, C, D, E, R(70));
	P(E, A, B, C, D, R(71));
	P(D, E, A, B, C, R(72));
	P(C, D, E, A, B, R(73));
	P(B, C, D, E, A, R(74));
	P(A, B, C, D, E, R(75));
	P(E, A, B, C, D, R(76));
	P(D, E, A, B, C, R(77));
	P(C, D, E, A, B, R(78));
	P(B, C, D, E, A, R(79));

#undef K
#undef F

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
}

/*
 * SHA-1 process buffer
 */
void sha1_update(sha1_context * ctx, const unsigned char *input, int ilen)
{
	int fill;
	unsigned long left;

	if (ilen <= 0)
		return;

	left = ctx->total[0] & 0x3F;
	fill = 64 - left;

	ctx->total[0] += (unsigned long) ilen;
	ctx->total[0] &= 0xFFFFFFFF;

	if (ctx->total[0] < (unsigned long) ilen)
		ctx->total[1]++;

	if (left && ilen >= fill) {
		memcpy((void *) (ctx->buffer + left), (void *) input, fill);
		sha1_process(ctx, ctx->buffer);
		input += fill;
		ilen -= fill;
		left = 0;
	}

	while (ilen >= 64) {
		sha1_process(ctx, input);
		input += 64;
		ilen -= 64;
	}

	if (ilen > 0) {
		memcpy((void *) (ctx->buffer + left), (void *) input, ilen);
	}
}

static const unsigned char sha1_padding[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SHA-1 final digest
 */
void sha1_finish(sha1_context * ctx, unsigned char output[20])
{
	unsigned long last, padn;
	unsigned long high, low;
	unsigned char msglen[8];

	high = (ctx->total[0] >> 29)
	    | (ctx->total[1] << 3);
	low = (ctx->total[0] << 3);

	PUT_ULONG_BE(high, msglen, 0);
	PUT_ULONG_BE(low, msglen, 4);

	last = ctx->total[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	sha1_update(ctx, (unsigned char *) sha1_padding, padn);
	sha1_update(ctx, msglen, 8);

	PUT_ULONG_BE(ctx->state[0], output, 0);
	PUT_ULONG_BE(ctx->state[1], output, 4);
	PUT_ULONG_BE(ctx->state[2], output, 8);
	PUT_ULONG_BE(ctx->state[3], output, 12);
	PUT_ULONG_BE(ctx->state[4], output, 16);
}

/*
 * output = SHA-1( input buffer )
 */
void sha1(const unsigned char *input, int ilen, unsigned char output[20])
{
	sha1_context ctx;

	sha1_starts(&ctx);
	sha1_update(&ctx, input, ilen);
	sha1_finish(&ctx, output);

}


/*
 * SHA-1 HMAC context setup
 */
void sha1_hmac_starts(sha1_context * ctx, const unsigned char *key, int keylen)
{
	int i;
	unsigned char sum[20];

	if (keylen > 64) {
		sha1(key, keylen, sum);
		keylen = 20;
		key = sum;
	}

	memset(ctx->ipad, 0x36, 64);
	memset(ctx->opad, 0x5C, 64);

	for (i = 0; i < keylen; i++) {
		ctx->ipad[i] = (unsigned char) (ctx->ipad[i] ^ key[i]);
		ctx->opad[i] = (unsigned char) (ctx->opad[i] ^ key[i]);
	}

	sha1_starts(ctx);
	sha1_update(ctx, ctx->ipad, 64);

}

/*
 * SHA-1 HMAC process buffer
 */
void sha1_hmac_update(sha1_context * ctx, const unsigned char *input, int ilen)
{
	sha1_update(ctx, input, ilen);
}

/*
 * SHA-1 HMAC final digest
 */
void sha1_hmac_finish(sha1_context * ctx, unsigned char output[20])
{
	unsigned char tmpbuf[20];

	sha1_finish(ctx, tmpbuf);
	sha1_starts(ctx);
	sha1_update(ctx, ctx->opad, 64);
	sha1_update(ctx, tmpbuf, 20);
	sha1_finish(ctx, output);

}

/*
 * SHA1 HMAC context reset
 */
void sha1_hmac_reset(sha1_context * ctx)
{
	sha1_starts(ctx);
	sha1_update(ctx, ctx->ipad, 64);
}

/*
 * output = HMAC-SHA-1( hmac key, input buffer )
 */
void sha1_hmac(const unsigned char *key, int keylen,
    const unsigned char *input, int ilen, unsigned char output[20])
{
	sha1_context ctx;

	sha1_hmac_starts(&ctx, key, keylen);
	sha1_hmac_update(&ctx, input, ilen);
	sha1_hmac_finish(&ctx, output);

}







#ifndef min
#define min( a, b ) ( ((a) < (b)) ? (a) : (b) )
#endif

void PKCS5_PBKDF2_HMAC_SHA1(const unsigned char *password, size_t plen,
    const unsigned char *salt, size_t slen,
    const unsigned long iteration_count, const unsigned long key_length,
    unsigned char *output)
{
	sha1_context ctx;
	sha1_starts(&ctx);

	// Size of the generated digest
	unsigned char md_size = 20;
	unsigned char md1[20];
	unsigned char work[20];

	unsigned long counter = 1;
	unsigned long generated_key_length = 0;
	while (generated_key_length < key_length) {
		// U1 ends up in md1 and work
		unsigned char c[4];
		c[0] = (counter >> 24) & 0xff;
		c[1] = (counter >> 16) & 0xff;
		c[2] = (counter >> 8) & 0xff;
		c[3] = (counter >> 0) & 0xff;

		sha1_hmac_starts(&ctx, password, plen);
		sha1_hmac_update(&ctx, salt, slen);
		sha1_hmac_update(&ctx, c, 4);
		sha1_hmac_finish(&ctx, md1);
		memcpy(work, md1, md_size);

		unsigned long ic = 1;
		for (ic = 1; ic < iteration_count; ic++) {
			// U2 ends up in md1
			sha1_hmac_starts(&ctx, password, plen);
			sha1_hmac_update(&ctx, md1, md_size);
			sha1_hmac_finish(&ctx, md1);
			// U1 xor U2
			unsigned long i = 0;
			for (i = 0; i < md_size; i++) {
				work[i] ^= md1[i];
			}
			// and so on until iteration_count
		}

		// Copy the generated bytes to the key
		unsigned long bytes_to_write =
		    min((key_length - generated_key_length), md_size);
		memcpy(output + generated_key_length, work, bytes_to_write);
		generated_key_length += bytes_to_write;
		++counter;
	}
}


#if defined(TEST)
/*
 * FIPS-180-1 test vectors
 */
static unsigned char sha1_test_buf[3][57] = {
	{"abc"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
	{""}
};

static const int sha1_test_buflen[3] = {
	3, 56, 1000
};

static const unsigned char sha1_test_sum[3][20] = {
	{0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
	    0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D},
	{0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
	    0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1},
	{0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
	    0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F}
};

/*
 * RFC 2202 test vectors
 */
static unsigned char sha1_hmac_test_key[7][26] = {
	{"\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
		    "\x0B\x0B\x0B\x0B"},
	{"Jefe"},
	{"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
		    "\xAA\xAA\xAA\xAA"},
	{"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
		    "\x11\x12\x13\x14\x15\x16\x17\x18\x19"},
	{"\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
		    "\x0C\x0C\x0C\x0C"},
	{""},			/* 0xAA 80 times */
	{""}
};

static const int sha1_hmac_test_keylen[7] = {
	20, 4, 20, 25, 20, 80, 80
};

static unsigned char sha1_hmac_test_buf[7][74] = {
	{"Hi There"},
	{"what do ya want for nothing?"},
	{"\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
		    "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
		    "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
		    "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
		    "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"},
	{"\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
		    "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
		    "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
		    "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
		    "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"},
	{"Test With Truncation"},
	{"Test Using Larger Than Block-Size Key - Hash Key First"},
	{"Test Using Larger Than Block-Size Key and Larger"
		    " Than One Block-Size Data"}
};

static const int sha1_hmac_test_buflen[7] = {
	8, 28, 50, 50, 20, 54, 73
};

static const unsigned char sha1_hmac_test_sum[7][20] = {
	{0xB6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xE2, 0x8B,
	    0xC0, 0xB6, 0xFB, 0x37, 0x8C, 0x8E, 0xF1, 0x46, 0xBE, 0x00},
	{0xEF, 0xFC, 0xDF, 0x6A, 0xE5, 0xEB, 0x2F, 0xA2, 0xD2, 0x74,
	    0x16, 0xD5, 0xF1, 0x84, 0xDF, 0x9C, 0x25, 0x9A, 0x7C, 0x79},
	{0x12, 0x5D, 0x73, 0x42, 0xB9, 0xAC, 0x11, 0xCD, 0x91, 0xA3,
	    0x9A, 0xF4, 0x8A, 0xA1, 0x7B, 0x4F, 0x63, 0xF1, 0x75, 0xD3},
	{0x4C, 0x90, 0x07, 0xF4, 0x02, 0x62, 0x50, 0xC6, 0xBC, 0x84,
	    0x14, 0xF9, 0xBF, 0x50, 0xC8, 0x6C, 0x2D, 0x72, 0x35, 0xDA},
	{0x4C, 0x1A, 0x03, 0x42, 0x4B, 0x55, 0xE0, 0x7F, 0xE7, 0xF2,
	    0x7B, 0xE1},
	{0xAA, 0x4A, 0xE5, 0xE1, 0x52, 0x72, 0xD0, 0x0E, 0x95, 0x70,
	    0x56, 0x37, 0xCE, 0x8A, 0x3B, 0x55, 0xED, 0x40, 0x21, 0x12},
	{0xE8, 0xE9, 0x9D, 0x0F, 0x45, 0x23, 0x7D, 0x78, 0x6D, 0x6B,
	    0xBA, 0xA7, 0x96, 0x5C, 0x78, 0x08, 0xBB, 0xFF, 0x1A, 0x91}
};

typedef struct {
	char *t;
	char *p;
	int plen;
	char *s;
	int slen;
	int c;
	int dkLen;
	char dk[1024];		// Remember to set this to max dkLen
} testvector;

int do_test(testvector * tv)
{
	printf("Started %s\n", tv->t);
	fflush(stdout);
	char *key = malloc(tv->dkLen);
	if (key == 0) {
		return -1;
	}

	PKCS5_PBKDF2_HMAC(tv->p, tv->plen, tv->s, tv->slen, tv->c,
	    tv->dkLen, key);

	if (memcmp(tv->dk, key, tv->dkLen) != 0) {
		// Failed
		return -1;
	}

	return 0;
}

#ifdef DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

/*
 * Checkup routine
 */
int main(int argc,char * argv[])
{
	int verbose = 1;
	int i, j, buflen;
	unsigned char buf[1024];
	unsigned char sha1sum[20];

	sha1_context ctx;

	/*
	 * SHA-1
	 */
	for (i = 0; i < 3; i++) {
		if (verbose != 0)
			printf("  SHA-1 test #%d: ", i + 1);

		sha1_starts(&ctx);

		if (i == 2) {
			memset(buf, 'a', buflen = 1000);

			for (j = 0; j < 1000; j++)
				sha1_update(&ctx, buf, buflen);
		} else
			sha1_update(&ctx, sha1_test_buf[i],
			    sha1_test_buflen[i]);

		sha1_finish(&ctx, sha1sum);

		if (memcmp(sha1sum, sha1_test_sum[i], 20) != 0) {
			if (verbose != 0)
				printf("failed\n");

			return (1);
		}

		if (verbose != 0)
			printf("passed\n");
	}

	if (verbose != 0)
		printf("\n");

	for (i = 0; i < 7; i++) {
		if (verbose != 0)
			printf("  HMAC-SHA-1 test #%d: ", i + 1);

		if (i == 5 || i == 6) {
			memset(buf, '\xAA', buflen = 80);
			sha1_hmac_starts(&ctx, buf, buflen);
		} else
			sha1_hmac_starts(&ctx, sha1_hmac_test_key[i],
			    sha1_hmac_test_keylen[i]);

		sha1_hmac_update(&ctx, sha1_hmac_test_buf[i],
		    sha1_hmac_test_buflen[i]);

		sha1_hmac_finish(&ctx, sha1sum);

		buflen = (i == 4) ? 12 : 20;

		if (memcmp(sha1sum, sha1_hmac_test_sum[i], buflen) != 0) {
			if (verbose != 0)
				printf("failed\n");

			return (1);
		}

		if (verbose != 0)
			printf("passed\n");
	}

	if (verbose != 0)
		printf("\n");

	// Test vectors from RFC 6070

	testvector *tv = 0;
	int res = 0;

/*
    Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 1
       dkLen = 20

     Output:
       DK = 0c 60 c8 0f 96 1f 0e 71
            f3 a9 b5 24 af 60 12 06
            2f e0 37 a6             (20 octets)

*/
	testvector t1 = {
		"Test 1",
		"password", 8, "salt", 4, 1, 20,
		.dk = {0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
			    0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
		    0x2f, 0xe0, 0x37, 0xa6}
	};

	tv = &t1;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

/*
       Input:
             P = "password" (8 octets)
             S = "salt" (4 octets)
             c = 2
             dkLen = 20

           Output:
             DK = ea 6c 01 4d c7 2d 6f 8c
                  cd 1e d9 2a ce 1d 41 f0
                  d8 de 89 57             (20 octets)

*/

	testvector t2 = {
		"Test 2",
		"password", 8, "salt", 4, 2, 20,
		{0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
			    0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
		    0xd8, 0xde, 0x89, 0x57}
	};

	tv = &t2;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

/*
             Input:
                  P = "password" (8 octets)
                  S = "salt" (4 octets)
                  c = 4096
                  dkLen = 20

                Output:
                  DK = 4b 00 79 01 b7 65 48 9a
                       be ad 49 d9 26 f7 21 d0
                       65 a4 29 c1             (20 octets)


*/
	testvector t3 = {
		"Test 3",
		"password", 8, "salt", 4, 4096, 20,
		{0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
			    0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
		    0x65, 0xa4, 0x29, 0xc1}
	};

	tv = &t3;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

/*
                  Input:
                     P = "password" (8 octets)
                     S = "salt" (4 octets)
                     c = 16777216
                     dkLen = 20

                   Output:
                     DK = ee fe 3d 61 cd 4d a4 e4
                          e9 94 5b 3d 6b a2 15 8c
                          26 34 e9 84             (20 octets)

*/
	testvector t4 = {
		"Test 4",
		"password", 8, "salt", 4, 16777216, 20,
		{0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
			    0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
		    0x26, 0x34, 0xe9, 0x84}
	};

	tv = &t4;
	// res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

/*
                     Input:
                        P = "passwordPASSWORDpassword" (24 octets)
                        S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
                        c = 4096
                        dkLen = 25

                      Output:
                        DK = 3d 2e ec 4f e4 1c 84 9b
                             80 c8 d8 36 62 c0 e4 4a
                             8b 29 1a 96 4c f2 f0 70
                             38                      (25 octets)

*/
	testvector t5 = {
		"Test 5",
		"passwordPASSWORDpassword", 24,
		    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, 25,
		{0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
			    0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
			    0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
		    0x38}
	};

	tv = &t5;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

/*
                        Input:
                           P = "pass\0word" (9 octets)
                           S = "sa\0lt" (5 octets)
                           c = 4096
                           dkLen = 16

                         Output:
                           DK = 56 fa 6a a7 55 48 09 9d
                                cc 37 d7 f0 34 25 e0 c3 (16 octets)
*/
	testvector t6 = {
		"Test 6",
		"pass\0word", 9, "sa\0lt", 5, 4096, 16,
		{0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
			    0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3,
		    }
	};

	tv = &t6;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

	printf("All tests successful\n");
	return 0;
}

#endif
/*
int main()
{
}*/
