#include "matasano/aes.h"
#include "matasano/pkcs7.h"
#include "matasano/utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const uint8_t *key_data;
static size_t key_size;

struct response {
    struct malloced_bytes ciphertext;
    uint8_t initialization_vector[AES_BLOCK_SIZE];
};

int first_function(struct response *r, const uint8_t *data, size_t size)
{
    int ret = 0;

    struct malloced_bytes unknown_bytes;
    ret = base64_to_bytes(&unknown_bytes, data, size);
    if (ret != 0) {
        return ret;
    }

    size_t padding_size = AES_BLOCK_SIZE
                          - (unknown_bytes.size) % AES_BLOCK_SIZE;
    size_t plaintext_size = unknown_bytes.size + padding_size;
    uint8_t *plaintext_data = realloc((void *) unknown_bytes.data, plaintext_size);
    if (plaintext_data == NULL) {
        fini_malloced_bytes(&unknown_bytes);
        return 1;
    }

    memset(plaintext_data + unknown_bytes.size, padding_size, padding_size);
    memset(r->initialization_vector, 0, AES_BLOCK_SIZE);

    struct malloced_bytes encrypted_bytes;
    ret = aes_128_cbc_encrypt(&encrypted_bytes,
                              r->initialization_vector, AES_BLOCK_SIZE,
                              key_data, key_size,
                              plaintext_data, plaintext_size);
    if (ret != 0) {
        free(plaintext_data);
        return ret;
    }

    r->ciphertext = encrypted_bytes;
    free(plaintext_data);
    return ret;
}

int second_function(bool *is_valid,
                    const uint8_t *iv_data,
                    const uint8_t *ciphertext_data,
                    size_t ciphertext_size)
{
    int ret = 0;

    struct malloced_bytes decrypted_bytes;
    ret = aes_128_cbc_decrypt(&decrypted_bytes,
                              iv_data, AES_BLOCK_SIZE,
                              key_data, key_size,
                              ciphertext_data, ciphertext_size);
    if (ret != 0) {
        return 1;
    }

    *is_valid = is_valid_pkcs7(decrypted_bytes.data
                               + (decrypted_bytes.size - AES_BLOCK_SIZE),
                               AES_BLOCK_SIZE);

    fini_malloced_bytes(&decrypted_bytes);
    return ret;
}

int attack(struct response *r)
{
    int ret = 0;

    size_t size = r->ciphertext.size;
    uint8_t *tmp = malloc(size + AES_BLOCK_SIZE);
    if (tmp == NULL) {
        return 1;
    }
    uint8_t *data = malloc(size);
    if (data == NULL) {
        free(tmp);
        return 1;
    }

    memcpy(tmp, r->initialization_vector, AES_BLOCK_SIZE);
    memcpy(tmp + AES_BLOCK_SIZE, r->ciphertext.data, size);

    uint8_t found_padding;
    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        /* Look for the padding if it's the last block.
         *
         * To find the padding, if it's valid, start at the beginning of the
         * block and change the bytes until the padding is corrupted. The
         * position of the corruption reveals the padding size.
         */
        found_padding = 0;
        if (i == size - AES_BLOCK_SIZE) {
            bool is_valid;
            ret = second_function(&is_valid, tmp, tmp + AES_BLOCK_SIZE,
                                  i + AES_BLOCK_SIZE);
            if (ret != 0) {
                free(tmp);
                free(data);
                return ret;
            }
            if (is_valid) {
                for (size_t j = 0; j < 15; ++j) {
                    uint8_t t = tmp[i + j];
                    tmp[i + j] ^= tmp[i + j];
                    ret = second_function(&is_valid, tmp, tmp + AES_BLOCK_SIZE,
                                          i + AES_BLOCK_SIZE);
                    if (ret != 0) {
                        free(tmp);
                        free(data);
                        return ret;
                    }
                    tmp[i + j] = t;
                    if (is_valid) {
                        found_padding = AES_BLOCK_SIZE - (j + 1);
                    }
                }
            }
        }

        for (size_t j = (15 - found_padding);; --j) {
            /* Control the bytes since we know the correct padding size */
            for (size_t k = 15; k > j; --k) {
                if (i == 0) {
                    tmp[i + k] = data[i + k]
                        ^ (AES_BLOCK_SIZE - j)
                        ^ r->initialization_vector[k];
                }
                else {
                    tmp[i + k] = data[i + k]
                        ^ (AES_BLOCK_SIZE - j)
                        ^ r->ciphertext.data[i - AES_BLOCK_SIZE + k];
                }
            }

            /* Control the byte in the next block */
            for (uint8_t k = 0;; ++k) {
                tmp[i + j] = k;

                bool is_valid;
                ret = second_function(&is_valid, tmp, tmp + AES_BLOCK_SIZE,
                                      i + AES_BLOCK_SIZE);
                if (ret != 0) {
                    free(tmp);
                    free(data);
                    return ret;
                }

                if (is_valid) {
                    if (i == 0) {
                        data[i + j] = k
                            ^ (AES_BLOCK_SIZE - j)
                            ^ r->initialization_vector[j];
                    }
                    else {
                        data[i + j] = k
                            ^ (AES_BLOCK_SIZE - j)
                            ^ r->ciphertext.data[i - AES_BLOCK_SIZE + j];
                    }
                    break;
                }
                if (k == 255) {
                    free(tmp);
                    free(data);
                    return 1;
                }
            }
            if (j == 0) {
                break;
            }
        }
    }
    free(tmp);

    size -= found_padding;
    printf("Found\n=====\n");
    for (size_t i = 0; i < size; ++i) {
        printf("%c", data[i]);
    }
    printf("\n");
    free(data);
    return ret;
}

int main()
{
    int ret = 0;

    struct static_bytes string[10];
    str_literal(&string[0],
                "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=");
    str_literal(&string[1],
                "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3Mg"
                "YXJlIHB1bXBpbic=");
    str_literal(&string[2],
                "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZh"
                "a2luZw==");
    str_literal(&string[3],
                "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==");
    str_literal(&string[4],
                "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmlt"
                "Ymxl");
    str_literal(&string[5],
                "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==");
    str_literal(&string[6],
                "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==");
    str_literal(&string[7],
                "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=");
    str_literal(&string[8],
                "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=");
    str_literal(&string[9],
                "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93");

    /* Generate a random AES key */
    struct malloced_bytes key_bytes;
    ret = random_bytes(&key_bytes, 16);
    if (ret != 0) {
        return ret;
    }

    key_data = key_bytes.data;
    key_size = key_bytes.size;

    struct response response;
    srand(time(NULL));
    uint8_t i = rand() % 10;
    ret = first_function(&response, string[i].data, string[i].size);
    if (ret != 0) {
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    ret = attack(&response);
    if (ret != 0) {
        fini_malloced_bytes(&response.ciphertext);
        fini_malloced_bytes(&key_bytes);
        return ret;
    }

    fini_malloced_bytes(&response.ciphertext);
    fini_malloced_bytes(&key_bytes);
    return ret;
}
