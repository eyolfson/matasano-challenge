#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


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

void xor_cipher(uint8_t *input, size_t input_size)
{
    if (input == 0 || input_size == 0) {
        printf("Zero length input\n");
        exit(1);
    }
    if (input_size % 2 != 0) {
        printf("Odd length input\n");
        exit(1);
    }

    for (int i = 0; i < 256; ++i) {
        frequency[i] = 0;
    }

    uint8_t value;
    for (size_t i = 0; i < input_size; i += 2) {
        value = ascii_hex_to_value(input[i]);
        value = (value << 4) + ascii_hex_to_value(input[i + 1]);
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
    for (size_t i = 0; i < input_size; i += 2) {
        value = ascii_hex_to_value(input[i]);
        value = (value << 4) + ascii_hex_to_value(input[i + 1]);
        *output = value ^ decode_byte; /* xor with 88 in this case */
        ++output;
    }
    *output = 0;
}

void check_buffer(size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (buffer[i] <= 8) {
            return;
        }
        else if (buffer[i] >= 11 && buffer[i] <= 31) {
            return;
        }
        else if (buffer[i] >= 127) {
            return;
        }
    }

    for (size_t i = 0; i < size; ++i) {
        printf("%c", buffer[i]);
    }
}

int main()
{
    int ret = 0;

    buffer[0] = 0;

    uint8_t input_buffer[BUFFER_SIZE];
    int fd = open("4cp.txt", O_RDONLY);

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

    uint8_t *current = input;
    size_t current_size = 0;
    for (size_t i = 0; i < input_size; ++i) {
        if (input[i] == '\n') {
            if (current_size != 0) {
                xor_cipher(current, current_size);
                check_buffer(30);
            }
            current = (input + i + 1);
            current_size = 0;
        }
        else {
            ++current_size;
        }
        if (i == (input_size - 1)) {
            if (current_size != 0) {
                xor_cipher(current, current_size);
                check_buffer(30);
            }
        }
    }

 unmap_input:
    munmap(input, input_size);
 close_fd:
    close(fd);

    return ret;
}
