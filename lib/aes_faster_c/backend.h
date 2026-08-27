#ifndef UDP2RAW_AES_FASTER_C_BACKEND_H_
#define UDP2RAW_AES_FASTER_C_BACKEND_H_

#include <stdint.h>

namespace aes_faster_c {

void ecb_encrypt(const uint8_t* input, const uint8_t* key, uint8_t* output);
void ecb_decrypt(const uint8_t* input, const uint8_t* key, uint8_t* output);
void cbc_encrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv);
void cbc_decrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv);
void cfb_encrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv);
void cfb_decrypt(uint8_t* output, uint8_t* input, uint32_t length,
                 const uint8_t* key, const uint8_t* iv);

}  // namespace aes_faster_c

#endif
