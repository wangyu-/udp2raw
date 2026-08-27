#include "aesarm_backend.h"

#include "aesarm.h"
#include "aesarm_table.h"
#include "lib/aes-keysize.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

namespace {

const size_t kRoundKeyWordCount = 68;

#define GET_UINT32_LE(n, b, i)                 \
    do {                                       \
        (n) = ((uint32_t)(b)[(i)]) |           \
              ((uint32_t)(b)[(i) + 1] << 8) |  \
              ((uint32_t)(b)[(i) + 2] << 16) | \
              ((uint32_t)(b)[(i) + 3] << 24);  \
    } while (0)

void setkey_enc(uint32_t* round_keys, const uint8_t* key) {
    uint32_t* rk = round_keys;
    unsigned int i;

    for (i = 0; i < (UDP2RAW_AES_KEY_BITS >> 5); ++i) {
        GET_UINT32_LE(rk[i], key, i << 2);
    }

    switch (UDP2RAW_AES_ROUNDS) {
        case 10:
            for (i = 0; i < 10; ++i, rk += 4) {
                rk[4] = rk[0] ^ RCON[i] ^
                        ((uint32_t)FSb[(rk[3] >> 8) & 0xff]) ^
                        ((uint32_t)FSb[(rk[3] >> 16) & 0xff] << 8) ^
                        ((uint32_t)FSb[(rk[3] >> 24) & 0xff] << 16) ^
                        ((uint32_t)FSb[rk[3] & 0xff] << 24);
                rk[5] = rk[1] ^ rk[4];
                rk[6] = rk[2] ^ rk[5];
                rk[7] = rk[3] ^ rk[6];
            }
            break;

        case 12:
            for (i = 0; i < 8; ++i, rk += 6) {
                rk[6] = rk[0] ^ RCON[i] ^
                        ((uint32_t)FSb[(rk[5] >> 8) & 0xff]) ^
                        ((uint32_t)FSb[(rk[5] >> 16) & 0xff] << 8) ^
                        ((uint32_t)FSb[(rk[5] >> 24) & 0xff] << 16) ^
                        ((uint32_t)FSb[rk[5] & 0xff] << 24);
                rk[7] = rk[1] ^ rk[6];
                rk[8] = rk[2] ^ rk[7];
                rk[9] = rk[3] ^ rk[8];
                rk[10] = rk[4] ^ rk[9];
                rk[11] = rk[5] ^ rk[10];
            }
            break;

        case 14:
            for (i = 0; i < 7; ++i, rk += 8) {
                rk[8] = rk[0] ^ RCON[i] ^
                        ((uint32_t)FSb[(rk[7] >> 8) & 0xff]) ^
                        ((uint32_t)FSb[(rk[7] >> 16) & 0xff] << 8) ^
                        ((uint32_t)FSb[(rk[7] >> 24) & 0xff] << 16) ^
                        ((uint32_t)FSb[rk[7] & 0xff] << 24);
                rk[9] = rk[1] ^ rk[8];
                rk[10] = rk[2] ^ rk[9];
                rk[11] = rk[3] ^ rk[10];
                rk[12] = rk[4] ^
                         ((uint32_t)FSb[rk[11] & 0xff]) ^
                         ((uint32_t)FSb[(rk[11] >> 8) & 0xff] << 8) ^
                         ((uint32_t)FSb[(rk[11] >> 16) & 0xff] << 16) ^
                         ((uint32_t)FSb[(rk[11] >> 24) & 0xff] << 24);
                rk[13] = rk[5] ^ rk[12];
                rk[14] = rk[6] ^ rk[13];
                rk[15] = rk[7] ^ rk[14];
            }
            break;
    }
}

void setkey_dec(uint32_t* round_keys, const uint8_t* key) {
    alignas(16) uint32_t forward_keys[kRoundKeyWordCount];
    setkey_enc(forward_keys, key);

    uint32_t* rk = round_keys;
    uint32_t* sk = forward_keys + UDP2RAW_AES_ROUNDS * 4;

    *rk++ = *sk++;
    *rk++ = *sk++;
    *rk++ = *sk++;
    *rk++ = *sk++;

    int i = UDP2RAW_AES_ROUNDS - 1;
    for (sk -= 8; i > 0; --i, sk -= 8) {
        for (int j = 0; j < 4; ++j, ++sk) {
            *rk++ = RT0[FSb[*sk & 0xff]] ^
                    RT1[FSb[(*sk >> 8) & 0xff]] ^
                    RT2[FSb[(*sk >> 16) & 0xff]] ^
                    RT3[FSb[(*sk >> 24) & 0xff]];
        }
    }

    *rk++ = *sk++;
    *rk++ = *sk++;
    *rk++ = *sk++;
    *rk++ = *sk++;
}

void encrypt_block(uint32_t* round_keys, const uint8_t input[16],
                   uint8_t output[16]) {
    aesarm_crypt_ecb(UDP2RAW_AES_ROUNDS,
                     reinterpret_cast<unsigned char*>(round_keys),
                     AES_ENCRYPT, input, output);
}

void decrypt_block(uint32_t* round_keys, const uint8_t input[16],
                   uint8_t output[16]) {
    aesarm_crypt_ecb(UDP2RAW_AES_ROUNDS,
                     reinterpret_cast<unsigned char*>(round_keys),
                     AES_DECRYPT, input, output);
}

void encrypt_cbc(uint32_t* round_keys, uint32_t length, uint8_t iv[16],
                 const uint8_t* input, uint8_t* output) {
    while (length > 0) {
        for (int i = 0; i < 16; ++i) {
            output[i] = static_cast<uint8_t>(input[i] ^ iv[i]);
        }
        encrypt_block(round_keys, output, output);
        memcpy(iv, output, 16);
        input += 16;
        output += 16;
        length -= 16;
    }
}

void decrypt_cbc(uint32_t* round_keys, uint32_t length, uint8_t iv[16],
                 const uint8_t* input, uint8_t* output) {
    uint8_t ciphertext[16];
    while (length > 0) {
        memcpy(ciphertext, input, sizeof(ciphertext));
        decrypt_block(round_keys, input, output);
        for (int i = 0; i < 16; ++i) {
            output[i] = static_cast<uint8_t>(output[i] ^ iv[i]);
        }
        memcpy(iv, ciphertext, sizeof(ciphertext));
        input += 16;
        output += 16;
        length -= 16;
    }
}

void crypt_cfb(uint32_t* round_keys, bool encrypt, uint32_t length,
               uint8_t iv[16], const uint8_t* input, uint8_t* output) {
    size_t offset = 0;
    while (length-- > 0) {
        if (offset == 0) {
            encrypt_block(round_keys, iv, iv);
        }
        const uint8_t input_byte = *input++;
        const uint8_t output_byte = static_cast<uint8_t>(input_byte ^ iv[offset]);
        *output++ = output_byte;
        iv[offset] = encrypt ? output_byte : input_byte;
        offset = (offset + 1) & 0x0f;
    }
}

}  // namespace

namespace aesarm_backend {

void ecb_encrypt(const uint8_t* input, const uint8_t* key, uint8_t* output) {
    alignas(16) static uint32_t round_keys[kRoundKeyWordCount];
    if (key != NULL) {
        setkey_enc(round_keys, key);
    }
    encrypt_block(round_keys, input, output);
}

void ecb_decrypt(const uint8_t* input, const uint8_t* key, uint8_t* output) {
    alignas(16) static uint32_t round_keys[kRoundKeyWordCount];
    if (key != NULL) {
        setkey_dec(round_keys, key);
    }
    decrypt_block(round_keys, input, output);
}

void cbc_encrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv) {
    alignas(16) static uint32_t round_keys[kRoundKeyWordCount];
    uint8_t iv_copy[16];
    assert(iv != NULL);
    assert((length & 0x0f) == 0);
    if ((length & 0x0f) != 0) {
        return;
    }
    if (key != NULL) {
        setkey_enc(round_keys, key);
    }
    memcpy(iv_copy, iv, sizeof(iv_copy));
    encrypt_cbc(round_keys, length, iv_copy, input, output);
}

void cbc_decrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv) {
    alignas(16) static uint32_t round_keys[kRoundKeyWordCount];
    uint8_t iv_copy[16];
    assert(iv != NULL);
    assert((length & 0x0f) == 0);
    if ((length & 0x0f) != 0) {
        return;
    }
    if (key != NULL) {
        setkey_dec(round_keys, key);
    }
    memcpy(iv_copy, iv, sizeof(iv_copy));
    decrypt_cbc(round_keys, length, iv_copy, input, output);
}

void cfb_encrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv) {
    alignas(16) static uint32_t round_keys[kRoundKeyWordCount];
    uint8_t iv_copy[16];
    assert(iv != NULL);
    if (key != NULL) {
        setkey_enc(round_keys, key);
    }
    memcpy(iv_copy, iv, sizeof(iv_copy));
    crypt_cfb(round_keys, true, length, iv_copy, input, output);
}

void cfb_decrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv) {
    alignas(16) static uint32_t round_keys[kRoundKeyWordCount];
    uint8_t iv_copy[16];
    assert(iv != NULL);
    if (key != NULL) {
        setkey_enc(round_keys, key);  // CFB decryption uses encryption keys.
    }
    memcpy(iv_copy, iv, sizeof(iv_copy));
    crypt_cfb(round_keys, false, length, iv_copy, input, output);
}

}  // namespace aesarm_backend
