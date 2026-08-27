#include "lib/aes-common.h"
#include "backend.h"

int AES_support_hwaccel(void) {
    return 0;
}

const char* AES_backend_name(void) {
    return "portable-c";
}

void AES_ECB_encrypt_buffer(const uint8_t* input, const uint8_t* key,
                            uint8_t* output) {
    aes_faster_c::ecb_encrypt(input, key, output);
}

void AES_ECB_decrypt_buffer(const uint8_t* input, const uint8_t* key,
                            uint8_t* output) {
    aes_faster_c::ecb_decrypt(input, key, output);
}

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length,
                            const uint8_t* key, const uint8_t* iv) {
    aes_faster_c::cbc_encrypt(output, input, length, key, iv);
}

void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length,
                            const uint8_t* key, const uint8_t* iv) {
    aes_faster_c::cbc_decrypt(output, input, length, key, iv);
}

void AES_CFB_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length,
                            const uint8_t* key, const uint8_t* iv) {
    aes_faster_c::cfb_encrypt(output, input, length, key, iv);
}

void AES_CFB_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length,
                            const uint8_t* key, const uint8_t* iv) {
    aes_faster_c::cfb_decrypt(output, input, length, key, iv);
}
