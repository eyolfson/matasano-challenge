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

/*
This "attack" boils down to first encrypting this:

email=AAAAAAAAAAAAA&uid=10&role=user
----------------                ----
                ----------------

We take the first 2 blocks here and use them for the first 2 blocks of our
encrypted data

email=AAAAAAAAAAadmin&uid=10&role=user
----------------                ------
                ----------------

We take the second block here and use it for the third block of our encrypted
data. This results in the string:

email=AAAAAAAAAAAAA&uid=10&role=admin&uid=10&rol
----------------                ----------------
                ----------------

However, this relies on the parser output not being validated. There is a
duplicate key (uid) and a key without a value (rol).
*/

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

    struct static_bytes good_bytes;
    str_literal(&good_bytes, "bob@gmail.com");

    struct malloced_bytes encrypted_bytes;
    ret = profile_for(&encrypted_bytes, good_bytes.data, good_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    uint8_t constructed_bytes[3 * AES_BLOCK_SIZE];
    for (size_t i = 0; i < 32; ++i) {
        constructed_bytes[i] = encrypted_bytes.data[i];
    }
    fini_malloced_bytes(&encrypted_bytes);

    struct static_bytes bad_bytes;
    str_literal(&bad_bytes, "AAAAAAAAAAadmin");

    ret = profile_for(&encrypted_bytes, bad_bytes.data, bad_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    for (size_t i = 0; i < 16; ++i) {
        constructed_bytes[i + 32] = encrypted_bytes.data[i + 16];
    }
    fini_malloced_bytes(&encrypted_bytes);

    struct malloced_bytes decrypted_bytes;
    ret = aes_128_ecb_decrypt(&decrypted_bytes,
                              key_bytes.data, key_bytes.size,
                              constructed_bytes, 3 * AES_BLOCK_SIZE);
    if (ret != 0) {
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    printf("Decrypted\n=========\n");
    for (size_t i = 0; i < decrypted_bytes.size; ++i) {
        printf("%c", decrypted_bytes.data[i]);
    }
    printf("\n");

    fini_malloced_bytes(&key_bytes);
    return 0;
}
