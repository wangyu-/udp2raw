/*
 * This file is adapted from PolarSSL 1.3.19 (GPL)
 */

#include "aes0.h"
#include "aesni.h"
#include "aesarm.h"
#include "aesacc.h"

#include <string.h>

#if defined(AES256) && (AES256 == 1)
#define AES_KEYSIZE 256
#ifdef HAVE_AMD64
  #define aes_setkey_enc aesni_setkey_enc_256
#endif
#elif defined(AES192) && (AES192 == 1)
#define AES_KEYSIZE 192
#ifdef HAVE_AMD64
  #define aes_setkey_enc aesni_setkey_enc_192
#endif
#else
#define AES_KEYSIZE 128
#ifdef HAVE_AMD64
  #define aes_setkey_enc aesni_setkey_enc_128
#endif
#endif

#define AES_NR ((AES_KEYSIZE >> 5) + 6)
#define AES_RKSIZE      272

#ifdef HAVE_AMD64
#define HAVE_HARDAES 1
#define aes_supported aesni_supported
#define aes_crypt_ecb aesni_crypt_ecb
#define aes_inverse_key(a,b) aesni_inverse_key(a,b,AES_NR)
#endif /* HAVE_AMD64 */

#ifdef HAVE_ARM64
#define HAVE_HARDAES 1
#define aes_supported aesarm_supported
#define aes_crypt_ecb aesarm_crypt_ecb

#include "aesarm_table.h"

#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

static void aes_setkey_enc(uint8_t *rk, const uint8_t *key)
{
    unsigned int i;
    uint32_t *RK;

    RK = (uint32_t *) rk;

    for( i = 0; i < ( AES_KEYSIZE >> 5 ); i++ )
    {
        GET_UINT32_LE( RK[i], key, i << 2 );
    }

    switch( AES_NR )
    {
        case 10:

            for( i = 0; i < 10; i++, RK += 4 )
            {
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[3] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[3]       ) & 0xFF ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:

            for( i = 0; i < 8; i++, RK += 6 )
            {
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[5] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[5]       ) & 0xFF ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for( i = 0; i < 7; i++, RK += 8 )
            {
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[7] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[7]       ) & 0xFF ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                ( (uint32_t) FSb[ ( RK[11]       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[11] >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 24 ) & 0xFF ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;
    }
}

static void aes_inverse_key(uint8_t *invkey, const uint8_t *fwdkey)
{
  int i, j;
  uint32_t *RK;
  uint32_t *SK;

  RK = (uint32_t *) invkey;
  SK = ((uint32_t *) fwdkey) + AES_NR * 4;

  *RK++ = *SK++;
  *RK++ = *SK++;
  *RK++ = *SK++;
  *RK++ = *SK++;

  for( i = AES_NR - 1, SK -= 8; i > 0; i--, SK -= 8 )
  {
      for( j = 0; j < 4; j++, SK++ )
      {
          *RK++ = RT0[ FSb[ ( *SK       ) & 0xFF ] ] ^
                  RT1[ FSb[ ( *SK >>  8 ) & 0xFF ] ] ^
                  RT2[ FSb[ ( *SK >> 16 ) & 0xFF ] ] ^
                  RT3[ FSb[ ( *SK >> 24 ) & 0xFF ] ];
      }
  }

  *RK++ = *SK++;
  *RK++ = *SK++;
  *RK++ = *SK++;
  *RK++ = *SK++;
}

#endif /* HAVE_ARM64 */

#ifdef HAVE_ASM

#define AES_MAXNR 14

typedef struct {
  uint32_t rd_key[4 * (AES_MAXNR + 1)];
  int rounds;
} AES_KEY;

#ifdef __cplusplus
extern "C" {
#endif

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);

#ifdef __cplusplus
}
#endif

static int aes_supported(void)
{
  return 2;
}

static void aes_crypt_ecb( int nr,
                           unsigned char *rk,
                           int mode,
                           const unsigned char input[16],
                           unsigned char output[16] )
{
  AES_KEY *ctx;
  ctx = (AES_KEY *) rk;
  ctx->rounds = nr;
  if (mode == AES_DECRYPT) {
    AES_decrypt(input, output, ctx);
  } else {
    AES_encrypt(input, output, ctx);
  }
}

static void aes_setkey_enc(uint8_t *rk, const uint8_t *key)
{
  AES_KEY *ctx;
  ctx = (AES_KEY *) rk;
  ctx->rounds = AES_NR;
  AES_set_encrypt_key(key, AES_KEYSIZE, ctx);
}

static void aes_setkey_dec(uint8_t *rk, const uint8_t *key)
{
  AES_KEY *ctx;
  ctx = (AES_KEY *) rk;
  ctx->rounds = AES_NR;
  AES_set_decrypt_key(key, AES_KEYSIZE, ctx);
}

#endif

#ifdef HAVE_HARDAES

static void aes_setkey_dec(uint8_t *rk, const uint8_t *key)
{
  uint8_t rk_tmp[AES_RKSIZE];
  aes_setkey_enc(rk_tmp, key);
  aes_inverse_key(rk, rk_tmp);
}

#endif

#if defined(HAVE_HARDAES) || defined(HAVE_ASM)

#define HAVE_ACC 1

/*
 * AESNI-CBC buffer encryption/decryption
 */
static void aes_crypt_cbc( int mode,
                           uint8_t* rk,
                           uint32_t length,
                           uint8_t iv[16],
                           const uint8_t *input,
                           uint8_t *output )
{
    int i;
    uint8_t temp[16];

    if( mode == AES_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
            aes_crypt_ecb( AES_NR, rk, mode, input, output );

            for( i = 0; i < 16; i++ )
                output[i] = (uint8_t)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
                output[i] = (uint8_t)( input[i] ^ iv[i] );

            aes_crypt_ecb( AES_NR, rk, mode, output, output );
            memcpy( iv, output, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
}

#endif /* HAVE_HARDAES or HAVE_ASM */

int AESACC_supported(void)
{
#if defined(HAVE_ACC)
  return aes_supported();
#else
  return 0;
#endif
}

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
#if defined(HAVE_ACC)
  uint8_t iv_tmp[16];
  uint8_t rk[AES_RKSIZE];

  if (aes_supported())
  {
    if (key == NULL || iv == NULL)
    {
      return;
    }
    memcpy(iv_tmp, iv, 16);
    aes_setkey_enc(rk, key);
    aes_crypt_cbc(AES_ENCRYPT, rk, \
                  length, iv_tmp, input, output);
    return;
  }
#endif

  AES_CBC_encrypt_buffer0(output, input, length, key, iv);
}

void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
#if defined(HAVE_ACC)
  uint8_t iv_tmp[16];
  uint8_t rk[AES_RKSIZE];

  if (aes_supported())
  {
    if (key == NULL || iv == NULL)
    {
      return;
    }
    memcpy(iv_tmp, iv, 16);
    aes_setkey_dec(rk, key);
    aes_crypt_cbc(AES_DECRYPT, rk, \
                  length, iv_tmp, input, output);
    return;
  }
#endif

  AES_CBC_decrypt_buffer0(output, input, length, key, iv);
}

void AES_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t* output, const uint32_t length)
{
#if defined(HAVE_ACC)
  uint8_t rk[AES_RKSIZE];

  if (aes_supported())
  {
    if (key == NULL)
    {
      return;
    }
    aes_setkey_enc(rk, key);
    aes_crypt_ecb(AES_NR, rk, AES_ENCRYPT, input, output);
    return;
  }
#endif

  AES_ECB_encrypt0(input, key, output, length);
}

void AES_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length)
{
#if defined(HAVE_ACC)
  uint8_t rk[AES_RKSIZE];

  if (aes_supported())
  {
    if (key == NULL)
    {
      return;
    }
    aes_setkey_dec(rk, key);
    aes_crypt_ecb(AES_NR, rk, AES_DECRYPT, input, output);
    return;
  }
#endif

  AES_ECB_decrypt0(input, key, output, length);
}
