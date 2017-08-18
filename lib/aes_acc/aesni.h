/*
 * This file is adapted from PolarSSL 1.3.19 (GPL)
 */

/**
 * \file aesni.h
 *
 * \brief AES-NI for hardware AES acceleration on some Intel processors
 *
 *  Copyright (C) 2013, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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
 */

#ifndef _AESNI_H_
#define _AESNI_H_

#ifndef AES_ENCRYPT
#define AES_ENCRYPT     1
#endif

#ifndef AES_DECRYPT
#define AES_DECRYPT     0
#endif

#if defined(__GNUC__) &&  \
    ( defined(__amd64__) || defined(__x86_64__) ) && \
    !defined(NO_AESACC)
#define HAVE_AMD64
#endif

#if defined(HAVE_AMD64)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          AES-NI features detection routine
 *
 * \return         1 if CPU has support for AES-NI, 0 otherwise
 */
int aesni_supported( void );

/**
 * \brief          AES-NI AES-ECB block en(de)cryption
 *
 * \param nr       number of rounds
 * \param rk       AES round keys
 * \param mode     AES_ENCRYPT or AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 on success (cannot fail)
 */
int aesni_crypt_ecb( int nr,
                     unsigned char *rk,
                     int mode,
                     const unsigned char input[16],
                     unsigned char output[16] );

/**
 * \brief           Compute decryption round keys from encryption round keys
 *
 * \param invkey    Round keys for the equivalent inverse cipher
 * \param fwdkey    Original round keys (for encryption)
 * \param nr        Number of rounds (that is, number of round keys minus one)
 */
void aesni_inverse_key( unsigned char *invkey,
                        const unsigned char *fwdkey, int nr );

/**
 * \brief           Perform 128-bit key expansion (for encryption)
 *
 * \param rk        Destination buffer where the round keys are written
 * \param key       Encryption key
 */
void aesni_setkey_enc_128( unsigned char *rk,
                           const unsigned char *key );

/**
 * \brief           Perform 192-bit key expansion (for encryption)
 *
 * \param rk        Destination buffer where the round keys are written
 * \param key       Encryption key
 */
void aesni_setkey_enc_192( unsigned char *rk,
                           const unsigned char *key );

/**
 * \brief           Perform 256-bit key expansion (for encryption)
 *
 * \param rk        Destination buffer where the round keys are written
 * \param key       Encryption key
 */
void aesni_setkey_enc_256( unsigned char *rk,
                           const unsigned char *key );

#ifdef __cplusplus
}
#endif 

#endif /* HAVE_AMD64 */

#endif /* _AESNI_H_ */
