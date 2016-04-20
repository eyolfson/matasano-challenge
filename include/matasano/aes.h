#ifndef MATASANO_AES_H
#define MATASANO_AES_H

#include "matasano/utils.h"

#include <stdbool.h>

#define AES_BLOCK_SIZE 16

int aes_detect_ecb(bool *is_ecb, const uint8_t *input, size_t input_size);

int aes_128_cbc_decrypt(struct malloced_bytes *mb,
                        const uint8_t *initialization_vector,
                        size_t initialization_vector_size,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size);

int aes_128_cbc_encrypt(struct malloced_bytes *mb,
                        const uint8_t *initialization_vector,
                        size_t initialization_vector_size,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size);

int aes_128_ctr(struct malloced_bytes *mb,
                uint32_t nonce,
                const uint8_t *key_data, size_t key_size,
                const uint8_t *input_data, size_t input_size);

int aes_128_ecb_decrypt(struct malloced_bytes *mb,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size);

int aes_128_ecb_encrypt(struct malloced_bytes *mb,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size);

#endif
