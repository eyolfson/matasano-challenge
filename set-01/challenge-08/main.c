#include "matasano/aes.h"
#include "matasano/utils.h"

#include <stdio.h>

#define INPUT_SIZE 160

int main()
{
    int ret = 0;

    struct mmaped_bytes file_bytes;
    ret = file_content(&file_bytes, "8.txt");
    if (ret != 0) {
        return ret;
    }

    struct malloced_bytes data_bytes;
    ret = hex_to_bytes(&data_bytes, file_bytes.data, file_bytes.size);
    if (ret != 0) {
        fini_mmaped_bytes(&file_bytes);
        return ret;
    }

    if (data_bytes.size % INPUT_SIZE != 0) {
        fini_malloced_bytes(&data_bytes);
        fini_mmaped_bytes(&file_bytes);
        return 1;
    }
    for (size_t i = 0; i < data_bytes.size; i += INPUT_SIZE) {
        bool is_ecb;
        ret = aes_detect_ecb(&is_ecb, data_bytes.data + i, INPUT_SIZE);
        if (ret != 0) {
            fini_malloced_bytes(&data_bytes);
            fini_mmaped_bytes(&file_bytes);
            return 1;
        }
        if (is_ecb) {

            struct malloced_bytes output_bytes;
            ret = bytes_to_hex(&output_bytes, data_bytes.data + i, INPUT_SIZE);
            if (ret != 0) {
                fini_malloced_bytes(&data_bytes);
                fini_mmaped_bytes(&file_bytes);
                return ret;
            }
            printf("Found ciphertext encrypted with ECB\n===================================\n");
            for (size_t j = 0; j < output_bytes.size; ++j) {
                printf("%c", output_bytes.data[j]);
            }
            printf("\n");
        }
    }


    fini_malloced_bytes(&data_bytes);
    fini_mmaped_bytes(&file_bytes);
    return ret;
}
