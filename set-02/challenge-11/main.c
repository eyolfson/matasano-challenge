#include "matasano/aes.h"
#include "matasano/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

    bool is_ecb;
    ret = aes_detect_ecb(&is_ecb, encrypted_bytes.data, encrypted_bytes.size);
    if (ret != 0) {
        return ret;
    }

    if (is_ecb) {
        printf("Detected data encrypted with ECB\n");
    }
    else {
        printf("Did not detect data encrypted with ECB\n");
    }

    return ret;
}
