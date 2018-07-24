/*
 *  this file comes from https://github.com/kokke/tiny-AES128-C
 */

#pragma once

#include <stdint.h>


//not used
//void AES_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length);
//void AES_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length);

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);


void AES_CFB_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AES_CFB_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
