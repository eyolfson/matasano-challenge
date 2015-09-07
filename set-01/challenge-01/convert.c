#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 4096

static char buffer[BUFFER_SIZE];

void write_value_to_base64(uint16_t value, uint8_t* c)
{
    if (value >= 0 && value <= 25) {
        *c = value + 'A';
    }
    else if (value >= 26 && value <= 51) {
        *c = (value - 26) + 'a';
    }
    else if (value >= 52 && value <= 61) {
        *c = (value - 52) + '0';
    }
    else if (value == 62) {
        *c = '+';
    }
    else if (value == 63) {
        *c = '/';
    }
    else {
        printf("Invalid value: %d\n", value);
        exit(1);
    }
}

void convert(const uint8_t *input)
{
    /* const uint8_t *current = input; */
    uint8_t byte = *input;
    uint16_t tmp = 0;
    uint8_t state = 0;
    uint8_t *output = buffer;

    while (byte != 0) {
        uint8_t value = 0;
        if (byte >= '0' && byte <= '9') {
            value = byte - '0';
        }
        else if (byte >= 'A' && byte <= 'Z') {
            value = byte - 'A' + 10;
        }
        else if (byte >= 'a' && byte <= 'z') {
            value = byte - 'a' + 10;
        }
        else {
            printf("Invalid byte: %d\n", byte);
            exit(1);
        }

        switch (state) {
        case 0:
            /* tmp is empty */
            tmp = value;
            state = 1;
            break;
        case 1:
            /* tmp has 4 bits */
            tmp = (tmp << 2) + (value >> 2);

            write_value_to_base64(tmp, output);
            ++output;

            tmp = (value & 0x03);
            state = 2;
            break;
        case 2:
            /* tmp has 2 bits */
            tmp = (tmp << 4) + value;

            write_value_to_base64(tmp, output);
            ++output;

            tmp = 0;
            state = 0;
            break;
        }
        ++input;
        byte = *input;
    }
    if (state != 0) {
        printf("Unhandled state: %d\n", state);
        exit(1);
    }
    *output = 0;
}

int main()
{
    convert("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    /* SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t */
    printf("convert: %s\n", buffer);
    return 0;
}
