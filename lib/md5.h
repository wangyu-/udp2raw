#ifndef UDP2RAW_MD5_H_
#define UDP2RAW_MD5_H_
#include <stdint.h>
#include <stddef.h>

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);

#endif
