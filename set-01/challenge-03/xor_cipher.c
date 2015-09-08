#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 4096

static uint8_t buffer[BUFFER_SIZE];

static uint8_t frequency[256];

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
    if (input == 0 || *input == 0) {
        printf("Zero length input\n");
        exit(1);
    }

    for (int i = 0; i < 256; ++i) {
        frequency[i] = 0;
    }
    uint8_t value;
    uint8_t *current = input;
    while (*current != 0) {
        value = ascii_hex_to_value(*current);
        ++current;
        if (*current == 0) {
            printf("Invalid string\n");
            exit(1);
        }
        value = (value << 4) + ascii_hex_to_value(*current);
        ++current;

        ++frequency[value];
    }

    uint8_t max_byte;
    uint8_t max_freq = 0;
    for (uint16_t i = 0; i < 256; ++i) {
        if (frequency[i] > max_freq) {
            max_freq = frequency[i];
            max_byte = i;
        }
    }
    /* Guess that the most frequent byte is the space character (32) */
    uint8_t decode_byte = max_byte ^ 32;

    uint8_t *output = buffer;
    current = input;
    while (*current != 0) {
        value = ascii_hex_to_value(*current);
        ++current;
        if (*current == 0) {
            printf("Invalid string\n");
            exit(1);
        }
        value = (value << 4) + ascii_hex_to_value(*current);
        ++current;

        *output = value ^ decode_byte; /* xor with 88 in this case */
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
