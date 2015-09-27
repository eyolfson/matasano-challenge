#ifndef MATASANO_PKCS7_H
#define MATASANO_PKCS7_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool is_valid_pkcs7(const uint8_t *data, size_t size);

#endif
