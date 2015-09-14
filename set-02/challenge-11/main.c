#include "matasano/aes_128.h"
#include "matasano/utils.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int detect_ecb_mode(bool *is_ecb_mode, const uint8_t *input, size_t input_size)
{
    if (is_ecb_mode == NULL || input == NULL || input_size == 0) {
        return 1;
    }
    if (input_size % 16 != 0) {
        return 1;
    }

    size_t blocks = input_size / 16;
    uint8_t *buffer = malloc(input_size);
    if (buffer == NULL) {
        return 1;
    }

    size_t valid_blocks = 0;
    for (size_t block = 0; block < blocks; ++block) {
        bool match = false;
        for (size_t valid_block = 0; valid_block < valid_blocks; ++valid_block) {
            match = true;
            for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
                if (buffer[(valid_block * AES_BLOCK_SIZE) + i] != input[(block * AES_BLOCK_SIZE) + i]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                break;
            }
        }
        if (match == false) {
            for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
                buffer[(valid_blocks * AES_BLOCK_SIZE) + i] = input[(block * AES_BLOCK_SIZE) + i];
            }
            ++valid_blocks;
        }
    }

    free(buffer);

    if (valid_blocks < blocks) {
        *is_ecb_mode = true;
    }
    else {
        *is_ecb_mode = false;
    }
    return 0;
}

int encryption_oracle(struct malloced_bytes *mb,
                      const uint8_t *input, size_t input_size)
{
    if (mb == NULL || input == NULL || input_size == 0) {
        return 1;
    }

    int ret = 0;

    /* Generate a random AES key */
    struct malloced_bytes key_bytes;
    ret = random_bytes(&key_bytes, 16);
    if (ret != 0) {
        return ret;
    }

    /* Append 5-10 bytes to the front and back */
    uint8_t append_front = (rand() % 6) + 5;
    uint8_t append_back = (rand() % 6) + 5;
    size_t appended_no_padding_size = append_front + input_size + append_back;
    uint8_t padding_bytes = 16 - (appended_no_padding_size % 16);
    size_t appended_size = appended_no_padding_size + padding_bytes;
    uint8_t *appended_data = malloc(appended_size);
    if (appended_data == NULL) {
        ret = fini_malloced_bytes(&key_bytes);
        if (ret != 0) {
            return ret;
        }
        return 1;
    }

    for (size_t i = 0; i < append_front; ++i) {
        appended_data[i] = rand() % 256;
    }
    memcpy(appended_data + append_front, input, input_size);
    for (size_t i = input_size; i < (input_size + append_back); ++i) {
        appended_data[i] = rand() % 256;
    }
    for (size_t i = appended_no_padding_size; i < appended_size; ++i) {
        appended_data[i] = padding_bytes;
    }

    /* Randomly encrypt under CBC or ECB */
    if (rand() % 2 == 0) {
        struct malloced_bytes iv_bytes;
        ret = random_bytes(&iv_bytes, 16);
        if (ret != 0) {
            free(appended_data);
            fini_malloced_bytes(&key_bytes);
            return ret;
        }

        ret = aes_128_cbc_encrypt(mb,
                                  iv_bytes.data, iv_bytes.size,
                                  key_bytes.data, key_bytes.size,
                                  appended_data, appended_size);

        fini_malloced_bytes(&iv_bytes);
    }
    else {
        ret = aes_128_ecb_encrypt(mb,
                                  key_bytes.data, key_bytes.size,
                                  appended_data, appended_size);
    }

    free(appended_data);
    fini_malloced_bytes(&key_bytes);
    return ret;
}

int main()
{
    int ret = 0;

    srand(time(NULL));

    struct static_bytes input_bytes;
    str_literal(&input_bytes, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    struct malloced_bytes encrypted_bytes;
    ret = encryption_oracle(&encrypted_bytes,
                            input_bytes.data, input_bytes.size);
    if (ret != 0) {
        return ret;
    }

    bool is_ecb_mode;
    ret = detect_ecb_mode(&is_ecb_mode, encrypted_bytes.data, encrypted_bytes.size);
    if (ret != 0) {
        return ret;
    }

    if (is_ecb_mode) {
        printf("Detected data encrypted with ECB\n");
    }
    else {
        printf("Did not detect data encrypted with ECB\n");
    }

    return ret;
}
