#include "backend.h"

#include "aes.h"
#include "lib/aes-keysize.h"

#include <assert.h>
#include <string.h>

namespace aes_faster_c {

void ecb_encrypt(const uint8_t* input, const uint8_t* key, uint8_t* output) {
    static aes_context ctx;
    if (key != NULL) {
        aes_init(&ctx);
        const int ret = aes_setkey_enc(&ctx, key, UDP2RAW_AES_KEY_BITS);
        assert(ret == 0);
    }
    const int ret = aes_crypt_ecb(&ctx, AES_ENCRYPT, input, output);
    assert(ret == 0);
}

void ecb_decrypt(const uint8_t* input, const uint8_t* key, uint8_t* output) {
    static aes_context ctx;
    if (key != NULL) {
        aes_init(&ctx);
        const int ret = aes_setkey_dec(&ctx, key, UDP2RAW_AES_KEY_BITS);
        assert(ret == 0);
    }
    const int ret = aes_crypt_ecb(&ctx, AES_DECRYPT, input, output);
    assert(ret == 0);
}

void cbc_encrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv) {
    static aes_context ctx;
    unsigned char iv_copy[16];
    assert(iv != NULL);
    if (key != NULL) {
        aes_init(&ctx);
        const int ret = aes_setkey_enc(&ctx, key, UDP2RAW_AES_KEY_BITS);
        assert(ret == 0);
    }
    memcpy(iv_copy, iv, sizeof(iv_copy));
    const int ret = aes_crypt_cbc(&ctx, AES_ENCRYPT, length, iv_copy, input, output);
    assert(ret == 0);
}

void cbc_decrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv) {
    static aes_context ctx;
    unsigned char iv_copy[16];
    assert(iv != NULL);
    if (key != NULL) {
        aes_init(&ctx);
        const int ret = aes_setkey_dec(&ctx, key, UDP2RAW_AES_KEY_BITS);
        assert(ret == 0);
    }
    memcpy(iv_copy, iv, sizeof(iv_copy));
    const int ret = aes_crypt_cbc(&ctx, AES_DECRYPT, length, iv_copy, input, output);
    assert(ret == 0);
}

void cfb_encrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv) {
    static aes_context ctx;
    unsigned char iv_copy[16];
    assert(iv != NULL);
    if (key != NULL) {
        aes_init(&ctx);
        const int ret = aes_setkey_enc(&ctx, key, UDP2RAW_AES_KEY_BITS);
        assert(ret == 0);
    }
    memcpy(iv_copy, iv, sizeof(iv_copy));
    size_t offset = 0;
    const int ret = aes_crypt_cfb128(&ctx, AES_ENCRYPT, length, &offset,
                                     iv_copy, input, output);
    assert(ret == 0);
}

void cfb_decrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv) {
    static aes_context ctx;
    unsigned char iv_copy[16];
    assert(iv != NULL);
    if (key != NULL) {
        aes_init(&ctx);
        const int ret = aes_setkey_enc(&ctx, key, UDP2RAW_AES_KEY_BITS);
        assert(ret == 0);  // CFB decryption uses the encryption schedule.
    }
    memcpy(iv_copy, iv, sizeof(iv_copy));
    size_t offset = 0;
    const int ret = aes_crypt_cfb128(&ctx, AES_DECRYPT, length, &offset,
                                     iv_copy, input, output);
    assert(ret == 0);
}

}  // namespace aes_faster_c
