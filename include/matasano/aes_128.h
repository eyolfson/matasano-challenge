#ifndef MATASANO_AES_128_H
#define MATASANO_AES_128_H

#include "matasano/utils.h"

int aes_128_cbc_decrypt(struct malloced_bytes *mb,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size);

#endif