/*
 * This file is adapted from https://github.com/CriticalBlue/mbedtls
 */

/*
 *  ARMv8-A Cryptography Extension AES support functions
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

#include "aesarm.h"

#if defined(HAVE_ARM64)

#include <sys/auxv.h>
#include <asm/hwcap.h>
#include <arm_neon.h>

/*
 * ARMv8a Crypto Extension support detection routine
 */
int aesarm_supported( void )
{
    static int done = 0;
    static unsigned int c = 0;

    if ( ! done )
    {
        c = getauxval(AT_HWCAP);
        done = 1;
    }

    return ( c & HWCAP_AES ) != 0;
}

/*
 * ARMv8a AES-ECB block en(de)cryption
 */
void aesarm_crypt_ecb( int nr,
                       unsigned char *rk,
                       int mode,
                       const unsigned char input[16],
                       unsigned char output[16] )
{
    int i;
    uint8x16_t state_vec, roundkey_vec;
    uint8_t *RK = (uint8_t *) rk;

    // Load input and round key into into their vectors
    state_vec = vld1q_u8( input );

    if ( mode == AES_ENCRYPT )
    {
        // Initial AddRoundKey is in the loop due to AES instruction always doing AddRoundKey first
        for( i = 0; i < nr - 1; i++ )
        {
            // Load Round Key
            roundkey_vec = vld1q_u8( RK );
            // Forward (AESE) round (AddRoundKey, SubBytes and ShiftRows)
            state_vec = vaeseq_u8( state_vec, roundkey_vec );
            // Mix Columns (AESMC)
            state_vec = vaesmcq_u8( state_vec );
            // Move pointer ready to load next round key
            RK += 16;
        }

        // Final Forward (AESE) round (AddRoundKey, SubBytes and ShiftRows). No Mix columns
        roundkey_vec = vld1q_u8( RK ); /* RK already moved in loop */
        state_vec = vaeseq_u8( state_vec, roundkey_vec );
    }
    else
    {
        // Initial AddRoundKey is in the loop due to AES instruction always doing AddRoundKey first
        for( i = 0; i < nr - 1; i++ )
        {
            // Load Round Key
            roundkey_vec = vld1q_u8( RK );
            // Reverse (AESD) round (AddRoundKey, SubBytes and ShiftRows)
            state_vec = vaesdq_u8( state_vec, roundkey_vec );
            // Inverse Mix Columns (AESIMC)
            state_vec = vaesimcq_u8( state_vec );
            // Move pointer ready to load next round key
            RK += 16;
        }

        // Final Reverse (AESD) round (AddRoundKey, SubBytes and ShiftRows). No Mix columns
        roundkey_vec = vld1q_u8( RK ); /* RK already moved in loop */
        state_vec = vaesdq_u8( state_vec, roundkey_vec );
    }

    // Manually apply final Add RoundKey step (EOR)
    RK += 16;
    roundkey_vec = vld1q_u8( RK );
    state_vec = veorq_u8( state_vec, roundkey_vec );

    // Write results back to output array
    vst1q_u8( output, state_vec );
}

#endif /* HAVE_ARM64 */
