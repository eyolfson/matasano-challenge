#include "matasano/aes.h"
#include "matasano/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE_GUESSES 40

static int append_bytes(struct malloced_bytes *mb,
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
    memset(data + first_size + second_size, padding_bytes, padding_bytes);

    mb->data = data;
    mb->size = size;
    return 0;
}

static const uint8_t *key_data;
static size_t key_size;
static const uint8_t *unknown_data;
static size_t unknown_size;

static int encryption_orcale(struct malloced_bytes *mb,
                             const uint8_t *prefix_data, size_t prefix_size)
{
    int ret = 0;

    struct malloced_bytes plaintext_bytes;
    ret = append_bytes(&plaintext_bytes,
                       prefix_data, prefix_size,
                       unknown_data, unknown_size);
    if (ret != 0) {
        return ret;
    }

    struct malloced_bytes encrypted_bytes;
    ret = aes_128_ecb_encrypt(&encrypted_bytes,
                              key_data, key_size,
                              plaintext_bytes.data, plaintext_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&plaintext_bytes);
        return ret;
    }

    fini_malloced_bytes(&plaintext_bytes);
    mb->data = encrypted_bytes.data;
    mb->size = encrypted_bytes.size;
    return ret;
}

static int find_sizes(size_t *encrypted_size, size_t *block_size)
{
    int ret = 0;
    struct malloced_bytes encrypted_bytes;
    ret = encryption_orcale(&encrypted_bytes,
                            NULL, 0);
    if (ret != 0) {
        return ret;
    }

    *encrypted_size = encrypted_bytes.size;
    size_t last_size = encrypted_bytes.size;

    fini_malloced_bytes(&encrypted_bytes);

    uint8_t bytes[BLOCK_SIZE_GUESSES];
    for (size_t i = 0; i < BLOCK_SIZE_GUESSES; ++i) {
        ret = encryption_orcale(&encrypted_bytes,
                                bytes, i + 1);
        if (ret != 0) {
            return ret;
        }

        size_t size = encrypted_bytes.size;
        fini_malloced_bytes(&encrypted_bytes);

        if (size != last_size) {
            *block_size = size - last_size;
            return ret;
        }
    }

    return 1;
}

static int detect_ecb(size_t block_size)
{
    int ret = 0;

    uint8_t *bytes = calloc(block_size * 2, 1);
    if (bytes == NULL) {
        return 1;
    }

    struct malloced_bytes encrypted_bytes;
    ret = encryption_orcale(&encrypted_bytes,
                            bytes, block_size * 2);
    if (ret != 0) {
        free(bytes);
        return ret;
    }


    bool is_ecb;
    ret = aes_detect_ecb(&is_ecb, encrypted_bytes.data, encrypted_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&encrypted_bytes);
        free(bytes);
        return ret;
    }

    fini_malloced_bytes(&encrypted_bytes);
    free(bytes);
    if (is_ecb) {
        return 0;
    }
    else {
        return 1;
    }
}

static int ecb_decryption(struct malloced_bytes *mb,
                          size_t encrypted_size, size_t block_size)
{
    if (encrypted_size % block_size != 0) {
        return 1;
    }

    int ret = 0;

    uint8_t *decrypted = malloc(encrypted_size);
    if (decrypted == NULL) {
        return 1;
    }

    uint8_t *temp_block = malloc(block_size);
    if (temp_block == NULL) {
        free(decrypted);
        return 1;
    }

    uint8_t *lookup_blocks = malloc(block_size * 256);
    if (lookup_blocks == NULL) {
        free(temp_block);
        free(decrypted);
        return 1;
    }

    for (size_t i = 0; i < (block_size - 1); ++i) {
        temp_block[i] = 'A';
    }

    size_t decrypted_size = 0;
    for (size_t base = 0; base < encrypted_size; base += block_size) {
        for (size_t offset = 0; offset < block_size; ++offset) {
            /* Build the lookup blocks */
            for (size_t i = 0; i < 256; ++i) {
                temp_block[block_size - 1] = i;
                struct malloced_bytes encrypted_bytes;
                ret = encryption_orcale(&encrypted_bytes,
                                        temp_block, block_size);
                if (ret != 0) {
                    free(lookup_blocks);
                    free(temp_block);
                    free(decrypted);
                    return ret;
                }

                memcpy(lookup_blocks + (block_size * i), encrypted_bytes.data,
                       block_size);

                fini_malloced_bytes(&encrypted_bytes);
            }

            /* Append the known (in the case of the first block) or just
               number (in the case of the rest) of bytes to the unknown
               string */
            struct malloced_bytes encrypted_bytes;
            ret = encryption_orcale(&encrypted_bytes,
                                    temp_block, block_size - (offset + 1));
            if (ret != 0) {
                free(lookup_blocks);
                free(temp_block);
                free(decrypted);
                return ret;
            }

            /* Search for the byte */
            uint8_t found;
            for (size_t i = 0; i < 256; ++i) {
                if (memcmp(lookup_blocks + (block_size * i),
                           encrypted_bytes.data + base,
                           block_size) == 0) {
                    found = i;
                    /* If the value is 1, this is the first padding byte */
                    if (found == 1) {
                        break;
                    }
                    decrypted[decrypted_size++] = found;
                }
            }

            fini_malloced_bytes(&encrypted_bytes);

            /* If the value is 1, this is the first padding byte, we're done */
            if (found == 1) {
                break;
            }

            /* Shift all the values in the temp block to the left by 1 */
            for (size_t i = 0; i < (block_size - 1); ++i) {
                temp_block[i] = temp_block[i+1];
            }
            temp_block[block_size - 2] = found;
        }
    }

    free(lookup_blocks);
    free(temp_block);

    mb->data = decrypted;
    mb->size = decrypted_size;
    return ret;
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

    /* Required for the oracle */
    key_data = key_bytes.data;
    key_size = key_bytes.size;
    unknown_data = unknown_bytes.data;
    unknown_size = unknown_bytes.size;

    size_t encrypted_size;
    size_t block_size;
    ret = find_sizes(&encrypted_size, &block_size);
    if (ret != 0) {
        fini_malloced_bytes(&unknown_bytes);
        fini_malloced_bytes(&key_bytes);
        return ret;
    }
    printf("Found block size: %lu\n", block_size);

    ret = detect_ecb(block_size);
    if (ret != 0) {
        fini_malloced_bytes(&unknown_bytes);
        fini_malloced_bytes(&key_bytes);
        return ret;
    }
    printf("Detected ECB\n");

    struct malloced_bytes decrypted_bytes;
    ret = ecb_decryption(&decrypted_bytes, 144, 16);
    if (ret != 0) {
        fini_malloced_bytes(&unknown_bytes);
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    printf("Decrypted\n=========\n");
    for (size_t i = 0; i < decrypted_bytes.size; ++i) {
        printf("%c", decrypted_bytes.data[i]);
    }

    fini_malloced_bytes(&decrypted_bytes);
    fini_malloced_bytes(&unknown_bytes);
    fini_malloced_bytes(&key_bytes);

    return 0;
}
