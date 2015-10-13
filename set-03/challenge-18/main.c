#include "matasano/aes.h"
#include "matasano/utils.h"

#include <stdio.h>

int main()
{
    int ret = 0;

    /* The unknown string */
    struct static_bytes unknown_base64;
    str_literal(&unknown_base64,
                "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX"
                "0KSvoOLSFQ==");

    struct malloced_bytes unknown_bytes;
    ret = base64_to_bytes(&unknown_bytes,
                          unknown_base64.data, unknown_base64.size);
    if (ret != 0) {
        return ret;
    }

    struct static_bytes key_bytes;
    str_literal(&key_bytes, "YELLOW SUBMARINE");

    struct malloced_bytes decrypted_bytes;
    ret = aes_128_ctr(&decrypted_bytes,
                      0,
                      key_bytes.data, key_bytes.size,
                      unknown_bytes.data, unknown_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&unknown_bytes);
        return ret;
    }
    fini_malloced_bytes(&unknown_bytes);

    printf("Decrypted\n=========\n");
    for (size_t i = 0; i < decrypted_bytes.size; ++i) {
        printf("%c", decrypted_bytes.data[i]);
    }
    printf("\n");

    fini_malloced_bytes(&decrypted_bytes);

    struct static_bytes t;
    str_literal(&t, "Kick it!");

    struct malloced_bytes encrypted_bytes;
    ret = aes_128_ctr(&encrypted_bytes,
                      0,
                      key_bytes.data, key_bytes.size,
                      t.data, t.size);
    ret = aes_128_ctr(&decrypted_bytes,
                      0,
                      key_bytes.data, key_bytes.size,
                      encrypted_bytes.data, encrypted_bytes.size);
    if (ret != 0) {
        fini_malloced_bytes(&encrypted_bytes);
        return ret;
    }
    fini_malloced_bytes(&encrypted_bytes);

    printf("Decrypted\n=========\n");
    for (size_t i = 0; i < decrypted_bytes.size; ++i) {
        printf("%c", decrypted_bytes.data[i]);
    }
    printf("\n");

    fini_malloced_bytes(&decrypted_bytes);
    return 0;
}
