#include "matasano/utils.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

int str_literal(struct static_bytes *sb, const char *s)
{
    if (sb == NULL) {
        return 1;
    }
    sb->data = (const uint8_t *) s;
    sb->size = strlen(s);
    return 0;
}

int file_content(struct mmaped_bytes *mb, const char *path)
{
    if (mb == NULL) {
        return 1;
    }

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        return 1;
    }

    struct stat stat;
    if (fstat(fd, &stat) == -1) {
        close(fd);
        return 1;
    }
    size_t size = stat.st_size;

    uint8_t *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        close(fd);
        return 1;
    }

    mb->data = data;
    mb->size = size;
    return 0;
}

int fini_mmaped_bytes(struct mmaped_bytes *mb) {
    if (mb == NULL || mb->data == NULL) {
        return 1;
    }

    munmap((void *) mb->data, mb->size);

    mb->data = NULL;
    mb->size = 0;
    return 0;
};

int append_bytes_2(struct malloced_bytes *mb,
                   const uint8_t *first, size_t first_size,
                   const uint8_t *second, size_t second_size)
{
    if (mb == NULL) {
        return 1;
    }
    if (first == NULL && first_size != 0) {
        return 1;
    }
    if (second == NULL && second_size != 0) {
        return 1;
    }

    size_t size = first_size + second_size;
    if (size == 0) {
        return 1;
    }
    uint8_t padding_bytes = 16 - (size % 16);
    size += padding_bytes;
    uint8_t *data = malloc(size);
    if (data == NULL) {
        return 1;
    }
    memcpy(data, first, first_size);
    memcpy(data + first_size, second, second_size);
    memset(data + first_size + second_size, padding_bytes, padding_bytes);

    mb->data = data;
    mb->size = size;
    return 0;
}

int append_bytes_3(struct malloced_bytes *mb,
                   const uint8_t *first, size_t first_size,
                   const uint8_t *second, size_t second_size,
                   const uint8_t *third, size_t third_size)
{
    if (mb == NULL) {
        return 1;
    }
    if (first == NULL && first_size != 0) {
        return 1;
    }
    if (second == NULL && second_size != 0) {
        return 1;
    }
    if (third == NULL && third_size != 0) {
        return 1;
    }

    size_t size = first_size + second_size + third_size;
    if (size == 0) {
        return 1;
    }
    uint8_t padding_bytes = 16 - (size % 16);
    size += padding_bytes;
    uint8_t *data = malloc(size);
    if (data == NULL) {
        return 1;
    }
    memcpy(data, first, first_size);
    memcpy(data + first_size, second, second_size);
    memcpy(data + first_size + second_size, third, third_size);
    memset(data + first_size + second_size + third_size,
           padding_bytes, padding_bytes);

    mb->data = data;
    mb->size = size;
    return 0;
}

int base64_to_bytes(struct malloced_bytes *mb,
                    const uint8_t *input, size_t input_size)
{
    if (mb == NULL || input == NULL || input_size == 0) {
        return 1;
    }

    size_t capacity = 4096;
    size_t size = 0;
    uint8_t *data = malloc(capacity);
    if (data == NULL) {
        return 1;
    }

    /* States
     * ------
     * 0 - tmp is empty
     * 1 - tmp has bits 7-2 valid
     * 2 - tmp has bits 7-4 valid [byte output]
     * 3 - tmp has bits 7-6 valid [byte output]
     * 4 - encountered an equal sign
     * 5 - valid end with equal sign
     */
    uint8_t state = 0;
    uint8_t tmp;

    for(size_t i = 0; i < input_size; ++i) {
        /* Ignore whitespace */
        if (input[i] == '\n' || input[i] == '\t' || input[i] == ' ') {
            continue;
        }

        /* Handle the equals case */
        if (input[i] == '=') {
            switch (state) {
            case 0:
            case 1:
                return 1;
            case 2:
                state = 4;
                continue;
            case 3:
                state = 5;
                continue;
            case 4:
                state = 5;
                continue;
            case 5:
                return 1;
            }
        }

        /* If there's some other character after the equals it's invalid */
        if (state == 4 || state == 5) {
            goto base64_to_bytes_error;
        }

        /* Convert the character to a 6 bit value */
        uint8_t value;
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
        else {
            goto base64_to_bytes_error;
        }

        /* Make tmp a valid byte */
        switch(state) {
        case 0:
            break;
        case 1:
            tmp = tmp + (value >> 4);
            break;
        case 2:
            tmp = tmp + (value >> 2);
            break;
        case 3:
            tmp = tmp + value;
            break;
        }

        /* Output a valid byte */
        if (state == 1 || state == 2 || state == 3) {
            if (size >= capacity) {
                capacity += 4096;
                void *ptr = realloc(data, capacity);
                if (ptr == NULL) {
                    goto base64_to_bytes_error;
                }
                data = ptr;
            }
            data[size] = tmp;
            ++size;
        }

        /* Make tmp valid for next iteration */
        switch(state) {
        case 0:
            tmp = value << 2;
            state = 1;
            break;
        case 1:
            tmp = (value & 0x0F) << 4;
            state = 2;
            break;
        case 2:
            tmp = (value & 0x03) << 6;
            state = 3;
            break;
        case 3:
            state = 0;
            break;
        }
    }

    if (state != 0 & state != 5) {
        goto base64_to_bytes_error;
    }

    mb->data = data;
    mb->size = size;
    return 0;

 base64_to_bytes_error:
    free(data);
    return 1;
}

int hex_to_bytes(struct malloced_bytes *mb,
                 const uint8_t *input, size_t input_size)
{
    if (mb == NULL || input == NULL || input_size == 0) {
        return 1;
    }

    size_t capacity = 4096;
    size_t size = 0;
    uint8_t *data = malloc(capacity);
    if (data == NULL) {
        return 1;
    }

    /* States
     * ------
     * 0 - tmp is empty
     * 1 - tmp has bits 7-4 valid [byte output]
     */
    uint8_t state = 0;
    uint8_t tmp;

    for(size_t i = 0; i < input_size; ++i) {
        /* Ignore whitespace */
        if (input[i] == '\n' || input[i] == '\t' || input[i] == ' ') {
            continue;
        }

        /* Convert the character to a 4 bit value */
        uint8_t value;
        if (input[i] >= '0' && input[i] <= '9') {
            value = input[i] - '0';
        }
        else if (input[i] >= 'A' && input[i] <= 'Z') {
            value = input[i] - 'A' + 10;
        }
        else if (input[i] >= 'a' && input[i] <= 'z') {
            value = input[i] - 'a' + 10;
        }
        else {
            goto hex_to_bytes_error;
        }

        /* Make tmp a valid byte */
        switch(state) {
        case 0:
            tmp = value << 4;
            state = 1;
            break;
        case 1:
            tmp = tmp + value;
            /* Output a valid byte */
            if (size >= capacity) {
                capacity += 4096;
                void *ptr = realloc(data, capacity);
                if (ptr == NULL) {
                    goto hex_to_bytes_error;
                }
                data = ptr;
            }
            data[size] = tmp;
            ++size;
            state = 0;
            break;
        }
    }

    if (state != 0) {
        goto hex_to_bytes_error;
    }

    mb->data = data;
    mb->size = size;
    return 0;

 hex_to_bytes_error:
    free(data);
    return 1;
}

static uint8_t byte_to_hex(uint8_t byte)
{
    if (byte >= 16) {
        return 0;
    }
    else if (byte < 10) {
        return byte + '0';
    }
    else {
        return (byte - 10) + 'a';
    }
}

int bytes_to_hex(struct malloced_bytes *mb,
                 const uint8_t *input, size_t input_size)
{
    if (mb == NULL || input == NULL || input_size == 0) {
        return 1;
    }

    size_t capacity = 4096;
    size_t size = 0;
    uint8_t *data = malloc(capacity);
    if (data == NULL) {
        return 1;
    }

    for(size_t i = 0; i < input_size; ++i) {
        if ((size + 2) >= capacity) {
            capacity += 4096;
            void *ptr = realloc(data, capacity);
            if (ptr == NULL) {
                goto bytes_to_hex_error;
            }
            data = ptr;
        }

        uint8_t first_4_bits = input[i] >> 4;
        uint8_t last_4_bits = input[i] & 0x0F;

        uint8_t first_ascii = byte_to_hex(first_4_bits);
        if (first_ascii == 0) {
            goto bytes_to_hex_error;
        }
        data[size] = first_ascii;
        ++size;
        uint8_t second_ascii = byte_to_hex(last_4_bits);
        if (second_ascii == 0) {
            goto bytes_to_hex_error;
        }
        data[size] = second_ascii;
        ++size;
    }

    mb->data = data;
    mb->size = size;
    return 0;

 bytes_to_hex_error:
    free(data);
    return 1;
}

int random_bytes(struct malloced_bytes* mb, size_t size)
{
    if (mb == NULL || size == 0) {
        return 1;
    }

    uint8_t *data = malloc(size);
    if (data == NULL) {
        return 1;
    }

    for (size_t i = 0; i < size; ++i) {
        data[i] = rand() % 256;
    }

    mb->data = data;
    mb->size = size;
    return 0;
}

int fini_malloced_bytes(struct malloced_bytes *mb)
{
    if (mb == NULL || mb->data == NULL) {
        return 1;
    }

    free((void *) mb->data);

    mb->data = NULL;
    mb->size = 0;
    return 0;
}
