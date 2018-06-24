#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void PKCS5_PBKDF2_HMAC_SHA256(unsigned char *password, size_t plen,
    unsigned char *salt, size_t slen,
    const unsigned long iteration_count, const unsigned long key_length,
    unsigned char *output);

void sha2( const unsigned char *input, size_t ilen,
           unsigned char output[32], int is224 );
