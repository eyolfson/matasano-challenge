#include "matasano/aes.h"
#include "matasano/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t *key_data;
static size_t key_size;

static int append_bytes(struct malloced_bytes *mb,
                        const uint8_t *first, size_t first_size,
                        const uint8_t *second, size_t second_size,
                        const uint8_t *third, size_t third_size)
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
    if (third == NULL && third_size != 0) {
        return 1;
    }

    size_t size = first_size + second_size + third_size;
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
    memcpy(data + first_size + second_size, third, third_size);
    memset(data + first_size + second_size + third_size,
           padding_bytes, padding_bytes);

    mb->data = data;
    mb->size = size;
    return 0;
}

static int profile_for(struct malloced_bytes *mb,
                       const uint8_t *email_data, size_t email_size)
{
    if (mb == NULL) {
        return 1;
    }

    int ret = 0;

    for (size_t i = 0; i < email_size; ++i) {
        if (email_data[i] < ' ') {
            return 1;
        }
        else if (email_data[i] >= 127) {
            return 1;
        }
        else if (email_data[i] == '&' || email_data[i] == '=') {
            return 1;
        }
    }

    struct static_bytes prefix_bytes;
    ret = str_literal(&prefix_bytes, "email=");
    if (ret != 0) {
        return ret;
    }
    struct static_bytes postfix_bytes;
    ret = str_literal(&postfix_bytes, "&uid=10&role=user");
    if (ret != 0) {
        return ret;
    }

    struct malloced_bytes plaintext_bytes;
    ret = append_bytes(&plaintext_bytes,
                       prefix_bytes.data, prefix_bytes.size,
                       email_data, email_size,
                       postfix_bytes.data, postfix_bytes.size);
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

int main()
{
    int ret = 0;

    /* Generate a random AES key */
    struct malloced_bytes key_bytes;
    ret = random_bytes(&key_bytes, 16);
    if (ret != 0) {
        return ret;
    }

    /* Required for the 'profile_for' function */
    key_data = key_bytes.data;
    key_size = key_bytes.size;

    struct static_bytes test_bytes;
    ret = str_literal(&test_bytes, "foo@bar.com");
    if (ret != 0) {
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    struct malloced_bytes encrypted_bytes;
    ret = profile_for(&encrypted_bytes, test_bytes.data, test_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    fini_malloced_bytes(&key_bytes);
    fini_malloced_bytes(&encrypted_bytes);
    return 0;
}
