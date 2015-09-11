#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct file_mmap {
    uint8_t *data;
    size_t size;
};

bool init_file_mmap(struct file_mmap *file_mmap, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("Cannot open path");
        return false;
    }
    size_t size;
    struct stat stat;
    if (fstat(fd, &stat) == -1) {
        perror("Cannot stat path");
        close(fd);
        return false;
    }
    size = stat.st_size;
    uint8_t *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        perror("Cannot mmap path");
        close(fd);
        return false;
    }
    file_mmap->data = data;
    file_mmap->size = size;
    return true;
}

bool fini_file_mmap(struct file_mmap *file_mmap) {
    if (file_mmap->data == NULL || file_mmap->size == 0) {
        return false;
    }
    munmap(file_mmap->data, file_mmap->size);
    file_mmap->data = NULL;
    file_mmap->size = 0;
    return true;
};

#define BYTES_PER_BLOCK 32
#define BLOCKS_PER_INPUT 10
#define INPUT_SIZE (BYTES_PER_BLOCK * BLOCKS_PER_INPUT)
#define CHUNK_SIZE (INPUT_SIZE + 1)

int main()
{
    struct file_mmap file_mmap;
    if (init_file_mmap(&file_mmap, "8.txt") == false) {
        return 1;
    }

    size_t block_size = CHUNK_SIZE;
    char buffer[BLOCKS_PER_INPUT][BYTES_PER_BLOCK];
    for (size_t i = 0; i < file_mmap.size; i += CHUNK_SIZE) {
        /* Check that the last byte of the chunk is a newline */
        if (file_mmap.data[i + CHUNK_SIZE - 1] != '\n') {
            return 1;
        }

        size_t valid_blocks = 0;
        for (size_t block = 0; block < BLOCKS_PER_INPUT; ++block) {
            bool match = false;
            for (size_t valid_block = 0; valid_block < valid_blocks; ++valid_block) {
                match = true;
                for (size_t byte = 0; byte < BYTES_PER_BLOCK; ++byte) {
                    if (buffer[valid_block][byte] != file_mmap.data[i + (block * BYTES_PER_BLOCK) + byte]) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    break;
                }
            }
            if (match == false) {
                for (size_t byte = 0; byte < BYTES_PER_BLOCK; ++byte) {
                    buffer[valid_blocks][byte] = file_mmap.data[i + (block * BYTES_PER_BLOCK) + byte];
                }
                ++valid_blocks;
            }
        }

        if (valid_blocks < BLOCKS_PER_INPUT) {
            printf("Found ciphertext encrypted with ECB\n===================================\n");
            for (size_t j = 0; j < CHUNK_SIZE; ++j) {
                printf("%c", file_mmap.data[i + j]);
            }
        }
    }

    if (fini_file_mmap(&file_mmap) == false) {
        return 1;
    }

    return 0;
}
