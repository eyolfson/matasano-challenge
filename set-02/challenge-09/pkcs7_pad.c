#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#define BLOCK_SIZE 20

int pkcs7_pad(const uint8_t *input, size_t input_size,
               uint8_t *output, size_t output_size)
{
    if (input_size > output_size) {
        return -1;
    }

    for (size_t i = 0; i < input_size; ++i) {
        output[i] = input[i];
    }

    for (size_t i = input_size; i < output_size; ++i) {
        output[i] = output_size - input_size;
    }

    return 0;
}

int main()
{
    uint8_t buffer[BLOCK_SIZE];
    if (pkcs7_pad("YELLOW SUBMARINE", 16, buffer, BLOCK_SIZE) == -1) {
        return 1;
    }
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        if (buffer[i] >= 16) {
        printf("%c", buffer[i]);
        }
        else {
            printf("\\x%02X", buffer[i]);
        }
    }
    printf("\n");

    return 0;
}
