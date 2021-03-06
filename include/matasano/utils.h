#ifndef MATASANO_UTILS_H
#define MATASANO_UTILS_H

#include <stddef.h>
#include <stdint.h>

struct static_bytes {
    const uint8_t *data;
    size_t size;
};

struct mmaped_bytes {
    const uint8_t *data;
    size_t size;
};

struct malloced_bytes {
    const uint8_t *data;
    size_t size;
};

int str_literal(struct static_bytes *sb, const char *s);

int file_content(struct mmaped_bytes *mb, const char *path);
int fini_mmaped_bytes(struct mmaped_bytes *mb);

int append_bytes_2(struct malloced_bytes *mb,
                   const uint8_t *first, size_t first_size,
                   const uint8_t *second, size_t second_size);
int append_bytes_3(struct malloced_bytes *mb,
                   const uint8_t *first, size_t first_size,
                   const uint8_t *second, size_t second_size,
                   const uint8_t *third, size_t third_size);
int base64_to_bytes(struct malloced_bytes *mb,
                    const uint8_t *input, size_t input_size);
int hex_to_bytes(struct malloced_bytes *mb,
                 const uint8_t *input, size_t input_size);
int bytes_to_hex(struct malloced_bytes *mb,
                 const uint8_t *input, size_t input_size);
int random_bytes(struct malloced_bytes* mb, size_t size);
int fini_malloced_bytes(struct malloced_bytes *mb);

#endif
