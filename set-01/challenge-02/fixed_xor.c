#include <stdint.h>
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

void fixed_xor(uint8_t *s1, uint8_t *s2)
{
    uint8_t value;
    uint8_t *output = buffer;
    while (*s1 != 0) {
        value = ascii_hex_to_value(*s1) ^ ascii_hex_to_value(*s2);
        if (value >= 0 && value <= 9) {
            *output = value + '0';
        }
        else if (value >= 10 && value <= 15) {
            *output = (value - 10) + 'a';
        }
        else {
            printf("Invalid computed value: %d\n", value);
        }
        ++output;

        ++s1;
        ++s2;
    }
    *output = 0;
}

int main()
{
    buffer[0] = 0;
    fixed_xor("1c0111001f010100061a024b53535009181c",
              "686974207468652062756c6c277320657965");
    printf("fixed_xor: %s\n", buffer);
    return 0;
}
