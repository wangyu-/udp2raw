#ifndef UDP2RAW_AESARM_BACKEND_H_
#define UDP2RAW_AESARM_BACKEND_H_

#include <stdint.h>

namespace aesarm_backend {

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

}  // namespace aesarm_backend

#endif
