#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 4096

static uint8_t buffer[BUFFER_SIZE];

uint8_t ascii_hex_to_value(uint8_t ascii)
{
    if (ascii >= '0' && ascii <= '9') {
        return ascii - '0';
    }
    else if (ascii >= 'A' && ascii <= 'Z') {
        return ascii - 'A' + 10;
    }
    else if (ascii >= 'a' && ascii <= 'z') {
        return ascii - 'a' + 10;
    }
    else {
        printf("Invalid ascii hex: %d\n", ascii);
        exit(1);
    }
}

void xor_cipher(uint8_t *input)
{
    uint8_t value;
    uint8_t *output = buffer;
    while (*input != 0) {
        value = ascii_hex_to_value(*input);
        ++input;
        if (*input == 0) {
            printf("Invalid string\n");
            exit(1);
        }
        value = (value << 4) + ascii_hex_to_value(*input);
        ++input;

        *output = value ^ 88; /* xor with 88 */
        ++output;
    }
    *output = 0;
}

int main()
{
    buffer[0] = 0;
    xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    printf("xor_cipher: %s\n", buffer);
    return 0;
}
