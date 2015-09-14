#include "matasano/aes_128.h"
#include "matasano/utils.h"

#include <stdio.h>

int main()
{
    int ret;

    struct mmaped_bytes file_bytes;
    ret = file_content(&file_bytes, "10.txt");
    if (ret != 0) {
        return ret;
    }

    struct malloced_bytes data_bytes;
    ret = base64_to_bytes(&data_bytes, file_bytes.data, file_bytes.size);
    if (ret != 0) {
        fini_mmaped_bytes(&file_bytes);
        return ret;
    }

    struct static_bytes key_bytes;
    str_literal(&key_bytes, "YELLOW SUBMARINE");

    uint8_t iv_bytes[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    struct malloced_bytes decrypted_bytes;
    ret = aes_128_cbc_decrypt(&decrypted_bytes,
                              iv_bytes, 16,
                              key_bytes.data, key_bytes.size,
                              data_bytes.data, data_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&data_bytes);
        fini_mmaped_bytes(&file_bytes);
        return ret;
    }

    uint8_t last_byte = decrypted_bytes.data[decrypted_bytes.size - 1];
    size_t size;
    if (last_byte < 16) {
        size = decrypted_bytes.size - last_byte;
    }
    else {
        size = decrypted_bytes.size;
    }

    for (size_t i = 0; i < size; ++i) {
        printf("%c", decrypted_bytes.data[i]);
    }

    fini_malloced_bytes(&decrypted_bytes);
    fini_malloced_bytes(&data_bytes);
    fini_mmaped_bytes(&file_bytes);
    return ret;
}
