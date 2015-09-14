#include "matasano/aes_128.h"

#include <openssl/aes.h>
#include <openssl/err.h>

#define AES_128_BLOCK_SIZE 16

int aes_128_cbc_decrypt(struct malloced_bytes *mb,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size)
{
    if (mb == NULL || key_size != 16 || input_size % AES_128_BLOCK_SIZE != 0) {
        return 1;
    }

    size_t size = input_size;
    uint8_t *data = malloc(size);
    if (data == NULL) {
        return 1;
    }

    AES_KEY aes_key;
    AES_set_decrypt_key(key, key_size * 8, &aes_key);

    uint8_t previous_ciphertext[AES_128_BLOCK_SIZE];
    for (size_t i = 0; i < AES_128_BLOCK_SIZE; ++i) {
        previous_ciphertext[i] = 0;
    }
    uint8_t block[AES_128_BLOCK_SIZE];

    for (size_t i = 0; i < size; i += AES_128_BLOCK_SIZE) {
        AES_decrypt(input + i, block, &aes_key);
        for (size_t j = 0; j < AES_128_BLOCK_SIZE; ++j) {
            data[i + j] = block[j] ^ previous_ciphertext[j];
            previous_ciphertext[j] = input[i + j];
        }
    }

    mb->data = data;
    mb->size = size;
    return 0;
}
