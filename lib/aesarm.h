/*
 * This file is adapted from https://github.com/CriticalBlue/mbedtls
 */

/**
 * \file aes_armv8a_ce.h
 *
 * \brief AES support functions using the ARMv8-A Cryptography Extension for
 * hardware acceleration on some ARM processors.
 *
 *  Copyright (C) 2016, CriticalBlue Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef _AESARM_H_
#define _AESARM_H_

#ifndef AES_ENCRYPT
#define AES_ENCRYPT     1
#endif

#ifndef AES_DECRYPT
#define AES_DECRYPT     0
#endif

#if defined(__GNUC__) && \
    __ARM_ARCH >= 8 && \
    __ARM_ARCH_PROFILE == 'A' && \
    defined(__aarch64__) &&  \
    defined(__ARM_FEATURE_CRYPTO) && \
    defined(__linux__) && \
    !defined(NO_AESACC)
#define HAVE_ARM64
#endif

#if defined(HAVE_ARM64)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          ARMv8-A features detection routine
 *
 * \return         1 if the CPU has support for the feature, 0 otherwise
 */
int aesarm_supported( void );

/**
 * \brief          AES ARMv8-A Cryptography Extension AES-ECB block en(de)cryption
 *
 * \param nr       number of rounds
 * \param rk       AES round keys
 * \param mode     AESARM_ENCRYPT or AESARM_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 */
void aesarm_crypt_ecb( int nr,
                       unsigned char *rk,
                       int mode,
                       const unsigned char input[16],
                       unsigned char output[16] );

#ifdef __cplusplus
}
#endif 

#endif /* HAVE_ARM64 */

#endif /* _AESARM_H_ */
