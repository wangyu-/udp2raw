#include "lib/aes-common.h"

#include "aesarm.h"
#include "aesarm_backend.h"
#include "lib/aes_faster_c/backend.h"

namespace {

typedef void (*ecb_function)(const uint8_t*, const uint8_t*, uint8_t*);
typedef void (*stream_function)(uint8_t*, uint8_t*, uint32_t,
                                const uint8_t*, const uint8_t*);

struct AesBackend {
    ecb_function ecb_encrypt;
    ecb_function ecb_decrypt;
    stream_function cbc_encrypt;
    stream_function cbc_decrypt;
    stream_function cfb_encrypt;
    stream_function cfb_decrypt;
    const char* name;
    bool hardware;
};

const AesBackend kPortableBackend = {
    aes_faster_c::ecb_encrypt,
    aes_faster_c::ecb_decrypt,
    aes_faster_c::cbc_encrypt,
    aes_faster_c::cbc_decrypt,
    aes_faster_c::cfb_encrypt,
    aes_faster_c::cfb_decrypt,
    "portable-c",
    false,
};

const AesBackend kArmv8CryptoBackend = {
    aesarm_backend::ecb_encrypt,
    aesarm_backend::ecb_decrypt,
    aesarm_backend::cbc_encrypt,
    aesarm_backend::cbc_decrypt,
    aesarm_backend::cfb_encrypt,
    aesarm_backend::cfb_decrypt,
    "armv8-crypto",
    true,
};

const AesBackend* detect_backend() {
    return aesarm_supported() ? &kArmv8CryptoBackend : &kPortableBackend;
}

const AesBackend& selected_backend() {
    static const AesBackend* const backend = detect_backend();
    return *backend;
}

}  // namespace

int AES_support_hwaccel(void) {
    return selected_backend().hardware ? 1 : 0;
}

const char* AES_backend_name(void) {
    return selected_backend().name;
}

void AES_ECB_encrypt_buffer(const uint8_t* input, const uint8_t* key,
                            uint8_t* output) {
    selected_backend().ecb_encrypt(input, key, output);
}

void AES_ECB_decrypt_buffer(const uint8_t* input, const uint8_t* key,
                            uint8_t* output) {
    selected_backend().ecb_decrypt(input, key, output);
}

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length,
                            const uint8_t* key, const uint8_t* iv) {
    selected_backend().cbc_encrypt(output, input, length, key, iv);
}

void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length,
                            const uint8_t* key, const uint8_t* iv) {
    selected_backend().cbc_decrypt(output, input, length, key, iv);
}

void AES_CFB_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length,
                            const uint8_t* key, const uint8_t* iv) {
    selected_backend().cfb_encrypt(output, input, length, key, iv);
}

void AES_CFB_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length,
                            const uint8_t* key, const uint8_t* iv) {
    selected_backend().cfb_decrypt(output, input, length, key, iv);
}
