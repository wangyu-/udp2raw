#ifndef _ENCRYPTION_H_
#define _ENCRYPTION_H_
#include <aes.h>
#include <md5.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
int my_encrypt(uint8_t *data,uint8_t *output,int &len,uint8_t * key);
int my_decrypt(uint8_t *data,uint8_t *output,int &len,uint8_t * key);
#endif
