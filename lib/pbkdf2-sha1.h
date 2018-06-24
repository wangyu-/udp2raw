#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sha1(const unsigned char *input, int ilen, unsigned char output[20]);

void sha1_hmac(const unsigned char *key, int keylen, const unsigned char *input, int ilen, unsigned char output[20]);

void PKCS5_PBKDF2_HMAC_SHA1(const unsigned char *password, size_t plen,
    const unsigned char *salt, size_t slen,
    const unsigned long iteration_count, const unsigned long key_length,
    unsigned char *output);
