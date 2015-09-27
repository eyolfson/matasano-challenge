#include "matasano/aes.h"
#include "matasano/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The main idea here is to add padding such that you know you're inserting the
 * attack vector into the beginning of the third block. To do this, make sure
 * the encrypted data does not have an ECB signature then add bytes until you
 * detect that it does, this is the number of bytes to properly pad the third
 * block.
 */

static const uint8_t *key_data;
static size_t key_size;
static const uint8_t *prefix_data;
static size_t prefix_size;
static const uint8_t *unknown_data;
static size_t unknown_size;

static int encryption_orcale(struct malloced_bytes *mb,
                             const uint8_t *user_data, size_t user_size)
{
    int ret = 0;

    struct malloced_bytes plaintext_bytes;
    ret = append_bytes_3(&plaintext_bytes,
                         prefix_data, prefix_size,
                         user_data, user_size,
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

static int find_ecb_padding(size_t *padding_size)
{
    int ret = 0;

    uint8_t bytes[48];
    for (size_t i = 0; i < 48; ++i) {
        bytes[i] = 'A';
    }

    {
        struct malloced_bytes encrypted_bytes;
        ret = encryption_orcale(&encrypted_bytes, NULL, 0);
        if (ret != 0) {
            return ret;
        }
        bool is_ecb;
        ret = aes_detect_ecb(&is_ecb,
                             encrypted_bytes.data, encrypted_bytes.size);
        fini_malloced_bytes(&encrypted_bytes);
        if (ret != 0) {
            return ret;
        }
        if (is_ecb) {
            return 1;
        }
    }

    for (size_t i = 32; i <= 48; ++i) {
        struct malloced_bytes encrypted_bytes;
        ret = encryption_orcale(&encrypted_bytes,
                                bytes, i);
        if (ret != 0) {
            return ret;
        }
        bool is_ecb;
        ret = aes_detect_ecb(&is_ecb, encrypted_bytes.data, encrypted_bytes.size);
        fini_malloced_bytes(&encrypted_bytes);
        if (ret != 0) {
            return ret;
        }
        if (is_ecb) {
            *padding_size = i;
            return 0;
        }
    }

    return 1;
}

#define BLOCK_OFFSET 48

static int ecb_decryption(struct malloced_bytes *mb,
                          size_t padding_size,
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

    size_t temp_size = padding_size + block_size;
    uint8_t *temp_block = malloc(temp_size);
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

    for (size_t i = 0; i < (temp_size - 1); ++i) {
        temp_block[i] = 'A';
    }

    size_t decrypted_size = 0;
    for (size_t base = 0; base < encrypted_size; base += block_size) {
        for (size_t offset = 0; offset < block_size; ++offset) {
            /* Build the lookup blocks */
            for (size_t i = 0; i < 256; ++i) {
                temp_block[temp_size - 1] = i;
                struct malloced_bytes encrypted_bytes;
                ret = encryption_orcale(&encrypted_bytes,
                                        temp_block, temp_size);
                if (ret != 0) {
                    free(lookup_blocks);
                    free(temp_block);
                    free(decrypted);
                    return ret;
                }

                memcpy(lookup_blocks + (block_size * i), encrypted_bytes.data + BLOCK_OFFSET,
                       block_size);

                fini_malloced_bytes(&encrypted_bytes);
            }

            /* Append the known (in the case of the first block) or just
               number (in the case of the rest) of bytes to the unknown
               string */
            struct malloced_bytes encrypted_bytes;
            ret = encryption_orcale(&encrypted_bytes,
                                    temp_block, temp_size - (offset + 1));
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
                           encrypted_bytes.data + base + BLOCK_OFFSET,
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
            for (size_t i = 0; i < (temp_size - 1); ++i) {
                temp_block[i] = temp_block[i+1];
            }
            temp_block[temp_size - 2] = found;
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

    srand(time(NULL));

    struct malloced_bytes prefix_bytes;
    ret = random_bytes(&prefix_bytes, (rand() % 6) + 5);
    if (ret != 0) {
        fini_malloced_bytes(&key_bytes);
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
        fini_malloced_bytes(&prefix_bytes);
        return ret;
    }

    /* Required for the oracle */
    key_data = key_bytes.data;
    key_size = key_bytes.size;
    prefix_data = prefix_bytes.data;
    prefix_size = prefix_bytes.size;
    unknown_data = unknown_bytes.data;
    unknown_size = unknown_bytes.size;

    size_t padding_size;
    ret = find_ecb_padding(&padding_size);
    if (ret != 0) {
        fini_malloced_bytes(&unknown_bytes);
        fini_malloced_bytes(&key_bytes);
        fini_malloced_bytes(&prefix_bytes);
        return ret;
    }
    printf("Found padding size: %lu\n", padding_size);

    struct malloced_bytes decrypted_bytes;
    ret = ecb_decryption(&decrypted_bytes, padding_size, 144, 16);
    if (ret != 0) {
        fini_malloced_bytes(&unknown_bytes);
        fini_malloced_bytes(&key_bytes);
        fini_malloced_bytes(&prefix_bytes);
        return ret;
    }

    printf("Decrypted\n=========\n");
    for (size_t i = 0; i < decrypted_bytes.size; ++i) {
        printf("%c", decrypted_bytes.data[i]);
    }

    fini_malloced_bytes(&decrypted_bytes);
    fini_malloced_bytes(&unknown_bytes);
    fini_malloced_bytes(&key_bytes);
    fini_malloced_bytes(&prefix_bytes);

    return 0;
}
