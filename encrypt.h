#ifndef _ENCRYPTION_H_
#define _ENCRYPTION_H_
#include <aes.h>
#include <md5.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
int my_encrypt(const char *data,char *output,int &len,char * key);
int my_decrypt(const char *data,char *output,int &len,char * key);

int my_encrypt_pesudo_header(uint8_t *data,uint8_t *output,int &len,uint8_t * key,uint8_t *header,int hlen);
int my_decrypt_pesudo_header(uint8_t *data,uint8_t *output,int &len,uint8_t * key,uint8_t *header,int hlen);


unsigned short csum(const unsigned short *ptr,int nbytes) ;


const int auth_none=0;
const int auth_md5=1;

const int cipher_none=0;
const int cipher_aes128cbc=1;

#endif
