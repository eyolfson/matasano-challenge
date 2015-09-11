#include <float.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

uint32_t hamming_distance(uint8_t *i1, uint8_t *i2, size_t size)
{
    /* TODO: POPCNT instruction */
    uint32_t distance = 0;
    for (size_t i = 0; i < size; ++i) {
        for (uint8_t bit = 0; bit < 8; ++bit) {
            uint8_t mask = (1 << bit);
            if (((i1[i] & mask) ^ (i2[i] & mask)) != 0) {
                ++distance;
            }
        }
    }
    return distance;
}

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


/* aaraaaabaaaubuKaqaaauaatebaaa */
/* Terminator X: Bring the noise */

uint8_t xor_cipher(uint8_t *input, size_t input_size, size_t offset, uint8_t step)
{
    if (input == 0 || input_size == 0) {
        printf("Zero length input\n");
        exit(1);
    }
    if (input_size % 2 != 0) {
        printf("Odd length input\n");
        exit(1);
    }

    uint8_t frequency[256];
    for (int i = 0; i < 256; ++i) {
        frequency[i] = 0;
    }

    uint8_t value;
    for (size_t i = offset; i < input_size; i += step) {
        ++frequency[input[i]];
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
    return max_byte ^ 32;
}

size_t repeating_key_xor(const uint8_t *input,
                         size_t input_size,
                         const uint8_t *key,
                         size_t key_size,
                         uint8_t *output,
                         size_t output_max_size)
{
    size_t output_used_size = 0;
    size_t key_index = 0;
    for (size_t i = 0; i < input_size; ++i) {
        /* uint8_t val = input[i]; */
        /* val = val ^ key[key_index]; */

        if (output_max_size < (output_used_size + 1)) {
            return 0;
        }
        /* uint8_t first_4_bits = val >> 4; */
        /* uint8_t last_4_bits = val & 0x0F; */

        /* uint8_t ascii_hex = convert_value_to_ascii_hex(first_4_bits); */
        /* if (ascii_hex == 0) { */
        /*     return 0; */
        /* } */
        /* output[output_used_size] = ascii_hex; */
        /* ascii_hex = convert_value_to_ascii_hex(last_4_bits); */
        /* if (ascii_hex == 0) { */
        /*     return 0; */
        /* } */
        /* output[output_used_size + 1] = ascii_hex; */

        output[output_used_size] = input[i] ^ key[key_index];
        output_used_size += 1;

        ++key_index;
        if (key_index == key_size) {
            key_index = 0;
        }
    }

    return output_used_size;
}

int main()
{
    int ret = 0;

    int fd = open("6.txt", O_RDONLY);
    size_t input_size;
    {
        struct stat stat;
        if (fstat(fd, &stat) == -1) {
            perror("stating input file");
            ret = 2;
            goto close_fd;
        }
        input_size = stat.st_size;
    }
    uint8_t *input = mmap(NULL, input_size,
                          PROT_READ | PROT_WRITE, MAP_PRIVATE,
                          fd, 0);
    if (input == MAP_FAILED) {
        perror("mmap input file");
        ret = 2;
        goto close_fd;
    }

    uint8_t data[4096];
    uint8_t *current = data;
    uint8_t state = 0;
    uint8_t tmp;
    bool seen_equals = false;
    bool requires_equals = false;

    for(size_t i = 0; i < input_size; ++i) {
        uint8_t value = 255;

        if (input[i] >= 'A' && input[i] <= 'Z') {
            value = input[i] - 'A';
        }
        else if (input[i] >= 'a' && input[i] <= 'z') {
            value = input[i] - 'a' + 26;
        }
        else if (input[i] >= '0' && input[i] <= '9') {
            value = input[i] - '0' + 52;
        }
        else if (input[i] == '+') {
            value = 62;
        }
        else if (input[i] == '/') {
            value = 63;
        }

        if (value < 64) {
            if (seen_equals) {
                printf("No more input allowed after '='\n");
                exit(1);
            }
            switch(state) {
            case 0:
                tmp = value << 2;
                /* tmp has bits 7-2 set */
                state = 1;
                break;
            case 1:
                tmp = tmp + (value >> 4);
                *current = tmp;
                ++current;
                tmp = (value & 0x0F) << 4;
                /* tmp has bits 7-4 set */
                state = 2;
                break;
            case 2:
                tmp = tmp + (value >> 2);
                *current = tmp;
                ++current;
                tmp = (value & 0x03) << 6;
                /* tmp has bits 7-6 set */
                state = 3;
                break;
            case 3:
                tmp = tmp + value;
                *current = tmp;
                ++current;
                state = 0;
                break;
            }

        }
        if (input[i] == '=') {
            seen_equals = true;
            switch (state) {
            case 0:
            case 1:
                printf("Encountered unexpected '='\n");
                exit(1);
            case 2:
                requires_equals = true;
                break;
            case 3:
                if (requires_equals) {
                    requires_equals = false;
                }
                break;
            }
        }
    }
    if (requires_equals) {
        printf("Missing equals at end of string");
        exit(1);
    }

    size_t data_size = current - data;

    double lowest_avg = DBL_MAX;
    uint8_t keysize = 0;
    for (uint8_t guessed_keysize = 2; guessed_keysize <= 40; ++guessed_keysize) {

        double d = 0;
        double c = 0;
        for (size_t i = guessed_keysize; i <= (data_size - guessed_keysize);
             i += guessed_keysize) {
            d += hamming_distance(data, data+i, guessed_keysize);
            c += 1;
        }
        double avg = (d/c) / ((double) guessed_keysize);

        if (avg < lowest_avg) {
            lowest_avg = avg;
            keysize = guessed_keysize;
        }
    }

    if (keysize == 0) {
        printf("Could not find keysize\n");
        ret = 1;
        goto unmap_input;
    }

    uint8_t key[4096];
    printf("Key\n===\n");
    for (uint8_t i = 0; i < keysize; ++i) {
        key[i] = xor_cipher(data, data_size, i, keysize);
        printf("%c", key[i]);
    }
    printf("\n");

    uint8_t output[4096];
    size_t output_size = repeating_key_xor(data, data_size, key, keysize,
                                           output, 4096);

    printf("\nData\n====\n");
    for (size_t i; i < output_size; ++i) {
        printf("%c", output[i]);
    }

 unmap_input:
    munmap(input, input_size);
 close_fd:
    close(fd);

    return ret;
}
