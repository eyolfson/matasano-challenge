#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/aes.h>
#include <openssl/err.h>

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

size_t base64_ascii_to_binary(const uint8_t *input, size_t input_size,
                              uint8_t *output, size_t output_capacity)
{
    size_t output_size = 0;
    uint8_t state = 0;
    uint8_t tmp;
    bool seen_equals = false;
    bool requires_equals = false;

    for(size_t i = 0; i < input_size; ++i) {
        /* Ignore newlines */
        if (input[i] == '\n') {
            continue;
        }

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
        else if (input[i] == '=') {
            seen_equals = true;
            switch (state) {
            case 0:
            case 1:
                return 0;
            case 2:
                state = 3;
                break;
            case 3:
                state = 0;
                break;
            }
            continue;
        }
        else {
            return 0;
        }

        /* Any values after an equal sign is invalid */
        if (seen_equals) {
            return 0;
        }

        switch(state) {
        case 0:
            tmp = value << 2;
            /* tmp has bits 7-2 set */
            state = 1;
            break;
        case 1:
            tmp = tmp + (value >> 4);
            if (output_size < output_capacity) {
                output[output_size] = tmp;
                ++output_size;
            }
            else {
                return 0;
            }
            tmp = (value & 0x0F) << 4;
            /* tmp has bits 7-4 set */
            state = 2;
            break;
        case 2:
            tmp = tmp + (value >> 2);
            if (output_size < output_capacity) {
                output[output_size] = tmp;
                ++output_size;
            }
            else {
                return 0;
            }
            tmp = (value & 0x03) << 6;
            /* tmp has bits 7-6 set */
            state = 3;
            break;
        case 3:
            tmp = tmp + value;
            if (output_size < output_capacity) {
                output[output_size] = tmp;
                ++output_size;
            }
            else {
                return 0;
            }
            state = 0;
            break;
        }
    }

    return output_size;
}

#define BUFFER_CAPACITY 4096

int main()
{
    struct file_mmap file_mmap;
    if (init_file_mmap(&file_mmap, "10.txt") == false) {
        return 1;
    }

    uint8_t buffer[BUFFER_CAPACITY];
    size_t buffer_size = base64_ascii_to_binary(file_mmap.data, file_mmap.size,
                                                buffer, BUFFER_CAPACITY);
    if (buffer_size == 0) {
        if (fini_file_mmap(&file_mmap) == false) {
            return 3;
        }
        return 2;
    }

    if (buffer_size % 16 != 0) {
        if (fini_file_mmap(&file_mmap) == false) {
            return 5;
        }
        return 4;
    }

    AES_KEY key;
    AES_set_decrypt_key("YELLOW SUBMARINE", 128, &key);

    uint8_t previous_ciphertext[16];
    for (size_t i = 0; i < 16; ++i) {
        previous_ciphertext[i] = 0;
    }
    uint8_t block[16];
    uint8_t decrypt[16];
    for (size_t i = 0; i < buffer_size; i += 16) {
        AES_decrypt(buffer + i, decrypt, &key);
        /* When encrypting, this block was xor'ed against the previous
           ciphertext, undo this operation by applying it again */
        for (size_t j = 0; j < 16; ++j) {
            decrypt[j] = decrypt[j] ^ previous_ciphertext[j];
        }
        /* Save the previous chipertext */
        for (size_t j = 0; j < 16; ++j) {
            previous_ciphertext[j] = (buffer +i)[j];
        }

        /* Handle padding bytes in the last block */
        if (i == (buffer_size - 16)) {
            /* Assume the last byte value is the padding (wrong) */
            uint8_t last_byte = decrypt[15];
            if (last_byte >= 16) {
                /* Any values that are equal or above 16 are not padding */
                last_byte = 0;
            }
            for (size_t j = 0; j < (16-last_byte); ++j) {
                printf("%c", decrypt[j]);
            }
        }
        else {
            for (size_t j = 0; j < 16; ++j) {
                printf("%c", decrypt[j]);
            }
        }
    }

    if (fini_file_mmap(&file_mmap) == false) {
        return 1;
    }

    return 0;
}


/*
When encrypting:

                 plaintext        plaintext
                 I'm back and I'm START
ciphertext
0000000000000000 1234ef1432342323

*/
