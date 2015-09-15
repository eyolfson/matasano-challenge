#include "matasano/aes.h"
#include "matasano/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE_GUESSES 40

int append_bytes(struct malloced_bytes *mb,
                 const uint8_t *first, size_t first_size,
                 const uint8_t *second, size_t second_size)
{
    if (mb == NULL) {
        return 1;
    }
    if (first == NULL && first_size != 0) {
        return 1;
    }
    if (second == NULL && second_size != 0) {
        return 1;
    }

    size_t size = first_size + second_size;
    if (size == 0) {
        return 1;
    }
    uint8_t padding_bytes = 16 - (size % 16);
    size += padding_bytes;
    uint8_t *data = malloc(size);
    if (data == NULL) {
        return 1;
    }
    memcpy(data, first, first_size);
    memcpy(data + first_size, second, second_size);
    memset(data + second_size, padding_bytes, padding_bytes);

    mb->data = data;
    mb->size = size;
    return 0;
}

int main()
{
    int ret = 0;

    /* Generate a random AES key */
    struct malloced_bytes key_bytes;
    ret = random_bytes(&key_bytes, 16);
    if (ret != 0) {
        return ret;
    }

    /* The unknown string */
    struct static_bytes unknown_base64;
    str_literal(&unknown_base64,
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                "YnkK");

    struct malloced_bytes unknown_bytes;
    ret = base64_to_bytes(&unknown_bytes,
                          unknown_base64.data, unknown_base64.size);
    if (ret != 0) {
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    /* Find the block size */
    size_t block_size = 0;
    {
        size_t last_block_size;
        struct malloced_bytes plaintext_bytes;
        ret = append_bytes(&plaintext_bytes,
                           NULL, 0,
                           unknown_bytes.data, unknown_bytes.size);
        if (ret != 0) {
            fini_malloced_bytes(&unknown_bytes);
            fini_malloced_bytes(&key_bytes);
            return ret;
        }

        struct malloced_bytes encrypted_bytes;
        ret = aes_128_ecb_encrypt(&encrypted_bytes,
                                  key_bytes.data, key_bytes.size,
                                  plaintext_bytes.data, plaintext_bytes.size);
        if (ret != 0) {
            fini_malloced_bytes(&plaintext_bytes);
            fini_malloced_bytes(&unknown_bytes);
            fini_malloced_bytes(&key_bytes);
            return ret;
        }
        last_block_size = encrypted_bytes.size;
        uint8_t bytes[BLOCK_SIZE_GUESSES];
        for (size_t i = 0; i < BLOCK_SIZE_GUESSES; ++i) {
            bytes[i] = 'A';

            struct malloced_bytes plaintext_bytes;
            ret = append_bytes(&plaintext_bytes,
                            bytes, i + 1,
                            unknown_bytes.data, unknown_bytes.size);
            if (ret != 0) {
                fini_malloced_bytes(&unknown_bytes);
                fini_malloced_bytes(&key_bytes);
                return ret;
            }

            struct malloced_bytes encrypted_bytes;
            ret = aes_128_ecb_encrypt(&encrypted_bytes,
                                    key_bytes.data, key_bytes.size,
                                    plaintext_bytes.data, plaintext_bytes.size);
            if (ret != 0) {
                fini_malloced_bytes(&plaintext_bytes);
                fini_malloced_bytes(&unknown_bytes);
                fini_malloced_bytes(&key_bytes);
                return ret;
            }

            if (last_block_size != encrypted_bytes.size) {
                block_size = encrypted_bytes.size - last_block_size;
            }

            fini_malloced_bytes(&encrypted_bytes);
            fini_malloced_bytes(&plaintext_bytes);

            if (block_size != 0) {
                break;
            }
        }
        if (block_size == 0) {
            fini_malloced_bytes(&unknown_bytes);
            fini_malloced_bytes(&key_bytes);
            return 1;
        }
    }
    printf("Found block size: %lu\n", block_size);

    /* Detect ECB mode */
    {
        uint8_t *bytes = calloc(block_size * 2, 1);
        struct malloced_bytes plaintext_bytes;
        ret = append_bytes(&plaintext_bytes,
                           bytes, block_size * 2,
                           unknown_bytes.data, unknown_bytes.size);
        if (ret != 0) {
            fini_malloced_bytes(&unknown_bytes);
            fini_malloced_bytes(&key_bytes);
            return ret;
        }

        struct malloced_bytes encrypted_bytes;
        ret = aes_128_ecb_encrypt(&encrypted_bytes,
                                key_bytes.data, key_bytes.size,
                                plaintext_bytes.data, plaintext_bytes.size);
        if (ret != 0) {
            fini_malloced_bytes(&plaintext_bytes);
            fini_malloced_bytes(&unknown_bytes);
            fini_malloced_bytes(&key_bytes);
            return ret;
        }

        bool is_ecb;
        ret = aes_detect_ecb(&is_ecb, encrypted_bytes.data, encrypted_bytes.size);
        if (ret != 0) {
            fini_malloced_bytes(&encrypted_bytes);
            fini_malloced_bytes(&plaintext_bytes);
            fini_malloced_bytes(&unknown_bytes);
            fini_malloced_bytes(&key_bytes);
            return ret;
        }

        fini_malloced_bytes(&encrypted_bytes);
        fini_malloced_bytes(&plaintext_bytes);

        if (is_ecb) {
            printf("Encryption function uses ECB\n");
        }
        else {
            fini_malloced_bytes(&unknown_bytes);
            fini_malloced_bytes(&key_bytes);
            return 1;
        }
    }

    fini_malloced_bytes(&unknown_bytes);
    fini_malloced_bytes(&key_bytes);
    return ret;
}
