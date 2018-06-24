#include "aes.h"
#include <stdio.h>
#include <stdlib.h>

#if defined(AES256) && (AES256 == 1)
#define AES_KEYSIZE 256
#elif defined(AES192) && (AES192 == 1)
#define AES_KEYSIZE 192
#else
#define AES_KEYSIZE 128
#endif


void AES_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length)
{
	printf("AES_ECB_encrypt not implemented\n");
	exit(-1);
}
void AES_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length)
{
	printf("AES_ECB_encrypt not implemented\n");
	exit(-1);
}

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
	static aes_context ctx;
	static int done=0;
	if(done==0)
	{
		aes_init( &ctx);
		done=1;
	}

	char tmp_iv[16];
	if(key!=0) aes_setkey_enc(&ctx,key,AES_KEYSIZE);
	memcpy(tmp_iv,iv,16);
	aes_crypt_cbc( &ctx, AES_ENCRYPT, length, (unsigned char* )tmp_iv, (const unsigned char*)input,(unsigned char*) output );
	return ;
}
void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
	static aes_context ctx;
	static int done=0;
	if(done==0)
	{
		aes_init( &ctx);
		done=1;
	}

	char tmp_iv[16];
	if(key!=0) aes_setkey_dec(&ctx,key,AES_KEYSIZE);
	memcpy(tmp_iv,iv,16);
	aes_crypt_cbc( &ctx,AES_DECRYPT, length, (unsigned char*)tmp_iv, (const unsigned char*)input, (unsigned char*) output );
	return;
}
