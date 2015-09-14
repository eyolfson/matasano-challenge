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

int base64_to_bytes(struct malloced_bytes *mb,
                    const uint8_t *input, size_t input_size)
{
    if (mb == NULL) {
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

    mb->data = data;
    mb->size = size;
    return 0;

 base64_to_bytes_error:
    free(data);
    return 1;
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


/* int dynamic_to_read_only_bytes(struct read_only_bytes *rob, */
/*                                struct dynamic_bytes *db) */
/* { */
/*     if (rob == NULL || db == NULL || db->data == NULL) { */
/*         return 1; */
/*     } */
/*     rob->data = db->data; */
/*     rob->size = db->size; */
/*     return 0; */
/* } */

/* int init_dynamic_bytes(struct dynamic_bytes *db) */
/* { */
/*     if (db == NULL) { */
/*         return 1; */
/*     } */
/*     void *p = malloc(4096); */
/*     if (p == NULL) { */
/*         return 1; */
/*     } */
/*     db->capacity = 4096; */
/*     db->size = 0; */
/*     db->data = (uint8_t *) p; */
/*     return 0; */
/* } */

/* int append_byte(struct dynamic_bytes *db, uint8_t b) */
/* { */
/*     if (db == NULL || db->data == NULL) { */
/*         return 1; */
/*     } */
/*     size_t i = db->size; */
/*     if (db->capacity > i) { */
/*         (db->data)[i] = b; */
/*         ++(db->size); */
/*         return 0; */
/*     } */
/*     else { */
/*         return 1; */
/*     } */
/* } */

/* int fini_dynamic_bytes(struct dynamic_bytes *db) */
/* { */
/*     if (db == NULL || db->data == NULL) { */
/*         return 1; */
/*     } */
/*     free(db->data); */
/*     db->data = NULL; */
/*     db->capacity = 0; */
/*     db->size = 0; */
/*     return 0; */
/* } */
