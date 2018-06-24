#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void PKCS5_PBKDF2_HMAC_SHA256(unsigned char *password, size_t plen,
    unsigned char *salt, size_t slen,
    const unsigned long iteration_count, const unsigned long key_length,
    unsigned char *output);

//void sha2( const unsigned char *input, size_t ilen,unsigned char output[32], int is224 );

int hkdf_sha256_extract(
                          const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len,
                          unsigned char *prk );

int hkdf_sha256_expand( const unsigned char *prk,
                         size_t prk_len, const unsigned char *info,
                         size_t info_len, unsigned char *okm, size_t okm_len );

int hkdf_sha256( const unsigned char *salt,
                  size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                  const unsigned char *info, size_t info_len,
                  unsigned char *okm, size_t okm_len );


