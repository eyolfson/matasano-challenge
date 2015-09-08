#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint8_t convert_value_to_ascii_hex(uint8_t value)
{
    if (value >= 16) {
        return 0;
    }
    else if (value < 10) {
        return value + '0';
    }
    else {
        return (value - 10) + 'a';
    }
}

size_t repeating_key_xor(const char *input,
                       size_t input_size,
                       const char *key,
                       size_t key_size,
                       char *output,
                       size_t output_max_size)
{
    size_t output_used_size = 0;
    size_t key_index = 0;
    for (size_t i = 0; i < input_size; ++i) {
        uint8_t val = input[i];
        val = val ^ key[key_index];

        if (output_max_size < (output_used_size + 2)) {
            return 0;
        }
        uint8_t first_4_bits = val >> 4;
        uint8_t last_4_bits = val & 0x0F;

        uint8_t ascii_hex = convert_value_to_ascii_hex(first_4_bits);
        if (ascii_hex == 0) {
            return 0;
        }
        output[output_used_size] = ascii_hex;
        ascii_hex = convert_value_to_ascii_hex(last_4_bits);
        if (ascii_hex == 0) {
            return 0;
        }
        output[output_used_size + 1] = ascii_hex;
        output_used_size += 2;

        ++key_index;
        if (key_index == key_size) {
            key_index = 0;
        }
    }

    return output_used_size;
}

int main()
{
    const char * input = "Burning 'em, if you ain't quick and nimble\n"
                         "I go crazy when I hear a cymbal";
    size_t input_size = strlen(input);
    const char * key = "ICE";
    size_t key_size = strlen(key);
    size_t output_max_size = 148;
    char output[output_max_size];

    size_t output_used_size = repeating_key_xor(input,
                                                input_size,
                                                key, key_size,
                                                output,
                                                output_max_size);
    if (output_used_size != 0) {
        for (size_t i = 0; i < output_used_size; ++i) {
            printf("%c", output[i]);
        }
        printf("\n");
        return 0;
    }
    else {
        return 1;
    }
}
