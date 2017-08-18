#ifndef _AESACC_H_
#define _AESACC_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int AESACC_supported(void);
void AESACC_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length);
void AESACC_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length);
void AESACC_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AESACC_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);

#ifdef __cplusplus
}
#endif

#endif /* _AESACC_H_ */
