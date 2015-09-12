#ifndef MATASANO_FILE_CONTENT_H
#define MATASANO_FILE_CONTENT_H

#include <stddef.h>
#include <stdint.h>

struct file_content {
    uint8_t *data;
    size_t size;
};

int init_file_content(struct file_content *fc, const char *path);
int fini_file_content(struct file_content *fc);

#endif
