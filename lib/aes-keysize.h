#ifndef UDP2RAW_AES_KEYSIZE_H_
#define UDP2RAW_AES_KEYSIZE_H_

#if defined(AES256) && (AES256 == 1) && \
    defined(AES192) && (AES192 == 1)
#error "AES192 and AES256 cannot be enabled at the same time"
#endif

#if defined(AES256) && (AES256 == 1)
#define UDP2RAW_AES_KEY_BITS 256
#define UDP2RAW_AES_KEY_BYTES 32
#define UDP2RAW_AES_ROUNDS 14
#elif defined(AES192) && (AES192 == 1)
#define UDP2RAW_AES_KEY_BITS 192
#define UDP2RAW_AES_KEY_BYTES 24
#define UDP2RAW_AES_ROUNDS 12
#else
#define UDP2RAW_AES_KEY_BITS 128
#define UDP2RAW_AES_KEY_BYTES 16
#define UDP2RAW_AES_ROUNDS 10
#endif

#endif
