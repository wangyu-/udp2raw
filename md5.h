#ifndef _MD5_H_
#define _MD5_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);

#endif
