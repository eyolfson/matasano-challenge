#include "matasano/pkcs7.h"
#include "matasano/utils.h"

int main()
{
    struct static_bytes b;

    str_literal(&b, "ICE ICE BABY\x04\x04\x04\x04");
    if (!is_valid_pkcs7(b.data, b.size)) {
        return 1;
    }

    str_literal(&b, "ICE ICE BABY\x05\x05\x05\x05");
    if (is_valid_pkcs7(b.data, b.size)) {
        return 1;
    }

    str_literal(&b, "ICE ICE BABY\x01\x02\x03\x04");
    if (is_valid_pkcs7(b.data, b.size)) {
        return 1;
    }

    return 0;
}
