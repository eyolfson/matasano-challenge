#include "matasano/pkcs7.h"

#include  <stdio.h>

bool is_valid_pkcs7(const uint8_t *data, size_t size)
{
    uint8_t last_byte = data[size - 1];
    if (last_byte >= size) {
        return true;
    }

    for (ssize_t i = size - 1; i > (size - last_byte - 1); --i) {
        if (data[i] != last_byte) {
            return false;
        }
    }
    return true;
}
