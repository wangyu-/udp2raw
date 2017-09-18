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


static aes_context ctx_de;
static aes_context ctx_en;
inline void init_de()
{
	static int done=0;
	if(done==0)
	{
		aes_init( &ctx_de );
		done=1;
	}
}
inline void init_en()
{
	static int done=0;
	if(done==0)
	{
		aes_init( &ctx_en);
		done=1;
	}
}
void AES_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length)
{
	init_en();
	printf("AES_ECB_encrypt not implemented\n");
	exit(-1);
}
void AES_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length)
{
	init_de();
	printf("AES_ECB_encrypt not implemented\n");
	exit(-1);
}

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
	char tmp_iv[16];
	init_en();
	if(key!=0) aes_setkey_enc(&ctx_en,key,AES_KEYSIZE);

	memcpy(tmp_iv,iv,16);
	aes_crypt_cbc( &ctx_en, AES_ENCRYPT, length, (unsigned char* )tmp_iv, (const unsigned char*)input,(unsigned char*) output );
	return ;
}
void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
	char tmp_iv[16];
	init_de();
	if(key!=0) aes_setkey_dec(&ctx_de,key,AES_KEYSIZE);
	memcpy(tmp_iv,iv,16);
	aes_crypt_cbc( &ctx_de, AES_DECRYPT, length, (unsigned char*)tmp_iv, (const unsigned char*)input, (unsigned char*) output );
	return;
}
