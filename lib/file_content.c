#include "matasano/file_content.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int init_file_content(struct file_content *fc, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        return 1;
    }
    struct stat stat;
    if (fstat(fd, &stat) == -1) {
        close(fd);
        return 2;
    }
    size_t size = stat.st_size;
    uint8_t *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        close(fd);
        return 3;
    }
    fc->data = data;
    fc->size = size;
    return 0;
}

int fini_file_content(struct file_content *fc) {
    if (fc->data == NULL || fc == 0) {
        return 1;
    }
    munmap((void *) fc->data, fc->size);
    fc->data = NULL;
    fc->size = 0;
    return 0;
};
