#include "matasano/aes.h"

#include <openssl/aes.h>

#include <stdlib.h>

int aes_128_cbc_decrypt(struct malloced_bytes *mb,
                        const uint8_t *initialization_vector,
                        size_t initialization_vector_size,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size)
{
    if (mb == NULL
        || initialization_vector == NULL
        || key == NULL
        || input == NULL) {
        return 1;
    }
    if (initialization_vector_size != AES_BLOCK_SIZE
        || key_size != 16
        || input_size % AES_BLOCK_SIZE != 0) {
        return 1;
    }

    size_t size = input_size;
    uint8_t *data = malloc(size);
    if (data == NULL) {
        return 1;
    }

    uint8_t previous_ciphertext[AES_BLOCK_SIZE];
    for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        previous_ciphertext[i] = initialization_vector[i];
    }

    uint8_t block[AES_BLOCK_SIZE];
    AES_KEY aes_key;
    AES_set_decrypt_key(key, key_size * 8, &aes_key);
    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_decrypt(input + i, block, &aes_key);
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            data[i + j] = block[j] ^ previous_ciphertext[j];
            previous_ciphertext[j] = input[i + j];
        }
    }

    mb->data = data;
    mb->size = size;
    return 0;
}

int aes_128_cbc_encrypt(struct malloced_bytes *mb,
                        const uint8_t *initialization_vector,
                        size_t initialization_vector_size,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size)
{
    if (mb == NULL
        || initialization_vector == NULL
        || key == NULL
        || input == NULL) {
        return 1;
    }
    if (initialization_vector_size != AES_BLOCK_SIZE
        || key_size != 16
        || input_size % AES_BLOCK_SIZE != 0) {
        return 1;
    }

    size_t size = input_size;
    uint8_t *data = malloc(size);
    if (data == NULL) {
        return 1;
    }

    uint8_t previous_ciphertext[AES_BLOCK_SIZE];
    for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        previous_ciphertext[i] = initialization_vector[i];
    }

    uint8_t block[AES_BLOCK_SIZE];
    AES_KEY aes_key;
    AES_set_encrypt_key(key, key_size * 8, &aes_key);
    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            block[j] = input[i + j] ^ previous_ciphertext[j];
        }
        AES_encrypt(block, data + i, &aes_key);
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            previous_ciphertext[j] = data[i + j];
        }
    }

    mb->data = data;
    mb->size = size;
    return 0;
}

int aes_128_ecb_decrypt(struct malloced_bytes *mb,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size)
{
    if (mb == NULL
        || key == NULL
        || input == NULL) {
        return 1;
    }
    if (key_size != 16
        || input_size % AES_BLOCK_SIZE != 0) {
        return 1;
    }

    size_t size = input_size;
    uint8_t *data = malloc(size);
    if (data == NULL) {
        return 1;
    }

    AES_KEY aes_key;
    AES_set_decrypt_key(key, key_size * 8, &aes_key);
    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_decrypt(input + i, data + i, &aes_key);
    }

    mb->data = data;
    mb->size = size;
    return 0;
}

int aes_128_ecb_encrypt(struct malloced_bytes *mb,
                        const uint8_t *key, size_t key_size,
                        const uint8_t *input, size_t input_size)
{
    if (mb == NULL
        || key == NULL
        || input == NULL) {
        return 1;
    }
    if (key_size != 16
        || input_size % AES_BLOCK_SIZE != 0) {
        return 1;
    }

    size_t size = input_size;
    uint8_t *data = malloc(size);
    if (data == NULL) {
        return 1;
    }

    AES_KEY aes_key;
    AES_set_encrypt_key(key, key_size * 8, &aes_key);
    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_encrypt(input + i, data + i, &aes_key);
    }

    mb->data = data;
    mb->size = size;
    return 0;
}
