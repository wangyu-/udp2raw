#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#if defined(AES256) && (AES256 == 1)
#define AES_KEYSIZE 256
#elif defined(AES192) && (AES192 == 1)
#define AES_KEYSIZE 192
#else
#define AES_KEYSIZE 128
#endif


void AES_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length)
{
	static aes_context ctx;
	if(key!=0)
	{
		aes_init( &ctx);
		aes_setkey_enc(&ctx,key,AES_KEYSIZE);
	}
	int ret=aes_crypt_ecb( &ctx, AES_ENCRYPT, (const unsigned char*)input,(unsigned char*) output );
	assert(ret==0);
	return ;
}
void AES_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length)
{
	static aes_context ctx;
	if(key!=0)
	{
		aes_init( &ctx);
		aes_setkey_dec(&ctx,key,AES_KEYSIZE);
	}
	int ret=aes_crypt_ecb( &ctx, AES_DECRYPT, (const unsigned char*)input,(unsigned char*) output );
	assert(ret==0);
    return ;
}

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
	static aes_context ctx;

	char tmp_iv[16];
	if(key!=0)
	{
		aes_init( &ctx);
		aes_setkey_enc(&ctx,key,AES_KEYSIZE);
	}
	memcpy(tmp_iv,iv,16);
	int ret=aes_crypt_cbc( &ctx, AES_ENCRYPT, length, (unsigned char* )tmp_iv, (const unsigned char*)input,(unsigned char*) output );
	assert(ret==0);
	return ;
}
void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
	static aes_context ctx;

	char tmp_iv[16];
	if(key!=0)
	{
		aes_init( &ctx);
		aes_setkey_dec(&ctx,key,AES_KEYSIZE);
	}
	memcpy(tmp_iv,iv,16);
	int ret=aes_crypt_cbc( &ctx,AES_DECRYPT, length, (unsigned char*)tmp_iv, (const unsigned char*)input, (unsigned char*) output );
	assert(ret==0);
}

void AES_CFB_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
	static aes_context ctx;

	char tmp_iv[16];
	if(key!=0)
	{
		aes_init( &ctx);
		aes_setkey_enc(&ctx,key,AES_KEYSIZE);
	}
	memcpy(tmp_iv,iv,16);
	size_t offset=0;
	int ret=aes_crypt_cfb128( &ctx, AES_ENCRYPT, length,&offset, (unsigned char* )tmp_iv, (const unsigned char*)input,(unsigned char*) output );
	assert(ret==0);
	return ;
}
void AES_CFB_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
	static aes_context ctx;

	char tmp_iv[16];
	if(key!=0)
	{
		aes_init( &ctx);
		aes_setkey_enc(&ctx,key,AES_KEYSIZE);// its aes_setkey_enc again, no typo
	}
	memcpy(tmp_iv,iv,16);
	size_t offset=0;
	int ret=aes_crypt_cfb128( &ctx,AES_DECRYPT, length,&offset, (unsigned char*)tmp_iv, (const unsigned char*)input, (unsigned char*) output );
	assert(ret==0);
	return;
}


