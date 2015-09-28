#include "matasano/aes.h"
#include "matasano/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t *key_data;
static size_t key_size;

int first_function(struct malloced_bytes *mb,
                   const uint8_t *data,
                   size_t size)
{

    struct static_bytes prepend_bytes;
    str_literal(&prepend_bytes, "comment1=cooking%20MCs;userdata=");

    struct static_bytes prefix_bytes;
    str_literal(&prefix_bytes, ";comment2=%20like%20a%20pound%20of%20bacon");

    size_t valid_size = 0;
    for (size_t i = 0; i < size; ++i) {
        if ((data[i] != ';') && (data[i] != '=')) {
            ++valid_size;
        }
    }

    uint8_t *valid_data = malloc(valid_size);
    if (valid_data == NULL) {
        return 1;
    }

    {
        size_t current_size = 0;
        for (size_t i = 0; i < size; ++i) {
            if ((data[i] != ';') && (data[i] != '=')) {
                valid_data[current_size] = data[i];
                ++current_size;
            }
        }
    }

    size_t padding_size = AES_BLOCK_SIZE -
        (prepend_bytes.size + valid_size + prefix_bytes.size) % AES_BLOCK_SIZE;

    size_t encrypted_size = prepend_bytes.size + valid_size
        + prefix_bytes.size + padding_size;
    uint8_t *plaintext_data = malloc(encrypted_size);
    if (plaintext_data == NULL) {
        free(valid_data);
        return 1;
    }

    memcpy(plaintext_data, prepend_bytes.data, prepend_bytes.size);
    memcpy(plaintext_data + prepend_bytes.size, valid_data, valid_size);
    memcpy(plaintext_data + prepend_bytes.size + valid_size, prefix_bytes.data,
           prefix_bytes.size);
    memset(plaintext_data + prepend_bytes.size + valid_size + prefix_bytes.size,
           padding_size, padding_size);

    int ret = 0;
    struct malloced_bytes encrypted_bytes;
    uint8_t iv[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ret = aes_128_cbc_encrypt(&encrypted_bytes, iv, 16,
                              key_data, key_size,
                              plaintext_data, encrypted_size);
    free(plaintext_data);
    free(valid_data);
    if (ret != 0) {
        return 1;
    }

    mb->data = encrypted_bytes.data;
    mb->size = encrypted_bytes.size;
    return 0;
}

int second_function(const uint8_t *data, size_t size)
{
    int ret = 0;

    struct malloced_bytes decrypted_bytes;
    uint8_t iv[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ret = aes_128_cbc_decrypt(&decrypted_bytes, iv, 16,
                              key_data, key_size,
                              data, size);
    if (ret != 0) {
        return 1;
    }

    printf("Decrypted\n=========\n");
    for (size_t i = 0; i < decrypted_bytes.size; ++i) {
        if (decrypted_bytes.data[i] >15) {
            printf("%c", decrypted_bytes.data[i]);
        }
    }
    printf("\n");

    fini_malloced_bytes(&decrypted_bytes);
    return ret;
}

/*
 * comment1=cooking%20MCs;userdata=?;comment2=%20like%20a%20pound%20of%20bacon
 * ----------------                ----------------                -----------=====
 *                 ----------------                ----------------
 * This attack consists of picking characters that are valid and one bit off the
 * desired character. We want the ; and = characters. = is 0x3D (0011 1101), so
 * let's use ? and flip the 1 indexed bit. ; is 0x3B (0011 1011), so let's use
 * ? again and flip the 2 indexed bit.
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

    key_data = key_bytes.data;
    key_size = key_bytes.size;

    struct malloced_bytes encrypted_bytes;
    struct static_bytes attack_bytes;
    str_literal(&attack_bytes, "atk?admin?true");
    ret = first_function(&encrypted_bytes,
                         attack_bytes.data, attack_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    ret = second_function(encrypted_bytes.data, encrypted_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&encrypted_bytes);
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    uint8_t *bytes = encrypted_bytes.data;
    bytes[19] = bytes[19] ^ 0x04;
    bytes[25] = bytes[25] ^ 0x02;
    ret = second_function(encrypted_bytes.data, encrypted_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&encrypted_bytes);
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    fini_malloced_bytes(&encrypted_bytes);
    fini_malloced_bytes(&key_bytes);
    return ret;
}
