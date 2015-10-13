#include "matasano/aes.h"
#include "matasano/utils.h"

#include <stdio.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

static const uint8_t *key_data;
static size_t key_size;

int main()
{
    int ret = 0;

    /* Generate a random AES key */
    struct malloced_bytes key_bytes;
    ret = random_bytes(&key_bytes, 16);
    if (ret != 0) {
        return ret;
    }

    key_data = key_bytes.data;
    key_size = key_bytes.size;

    struct static_bytes base64s[40];
    str_literal(&base64s[0], "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==");
    str_literal(&base64s[1], "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=");
    str_literal(&base64s[2], "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==");
    str_literal(&base64s[3], "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=");
    str_literal(&base64s[4],
                "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk");
    str_literal(&base64s[5], "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==");
    str_literal(&base64s[6], "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=");
    str_literal(&base64s[7], "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==");
    str_literal(&base64s[8], "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=");
    str_literal(&base64s[9], "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl");
    str_literal(&base64s[10], "VG8gcGxlYXNlIGEgY29tcGFuaW9u");
    str_literal(&base64s[11], "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==");
    str_literal(&base64s[12], "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=");
    str_literal(&base64s[13], "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==");
    str_literal(&base64s[14], "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=");
    str_literal(&base64s[15], "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=");
    str_literal(&base64s[16], "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==");
    str_literal(&base64s[17], "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==");
    str_literal(&base64s[18], "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==");
    str_literal(&base64s[19], "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==");
    str_literal(&base64s[20], "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==");
    str_literal(&base64s[21], "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==");
    str_literal(&base64s[22], "U2hlIHJvZGUgdG8gaGFycmllcnM/");
    str_literal(&base64s[23], "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=");
    str_literal(&base64s[24], "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=");
    str_literal(&base64s[25], "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=");
    str_literal(&base64s[26], "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=");
    str_literal(&base64s[27],
                "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==");
    str_literal(&base64s[28], "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==");
    str_literal(&base64s[29], "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=");
    str_literal(&base64s[30], "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==");
    str_literal(&base64s[31], "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu");
    str_literal(&base64s[32], "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=");
    str_literal(&base64s[33], "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs");
    str_literal(&base64s[34], "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=");
    str_literal(&base64s[35], "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0");
    str_literal(&base64s[36], "SW4gdGhlIGNhc3VhbCBjb21lZHk7");
    str_literal(&base64s[37],
                "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=");
    str_literal(&base64s[38], "VHJhbnNmb3JtZWQgdXR0ZXJseTo=");
    str_literal(&base64s[39], "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=");

    struct malloced_bytes ciphertexts[ARRAY_SIZE(base64s)];
    for (uint8_t i = 0; i < ARRAY_SIZE(base64s); ++i) {
        struct malloced_bytes plaintext;
        ret = base64_to_bytes(&plaintext, base64s[i].data, base64s[i].size);
        if (ret != 0) {
            fini_malloced_bytes(&key_bytes);
            return ret;
        }
        ret = aes_128_ctr(&ciphertexts[i],
                          0,
                          key_bytes.data, key_bytes.size,
                          plaintext.data, plaintext.size);
        if (ret != 0) {
            for (uint8_t j = 0; j < i; ++j) {
                fini_malloced_bytes(&ciphertexts[j]);
            }
            fini_malloced_bytes(&plaintext);
            fini_malloced_bytes(&key_bytes);
            return ret;
        }
        fini_malloced_bytes(&plaintext);
    }


    for (uint8_t i = 0; i < ARRAY_SIZE(base64s); ++i) {
        /* TODO: Look at ciphertexts[i] */
    }

    for (uint8_t i = 0; i < ARRAY_SIZE(base64s); ++i) {
        fini_malloced_bytes(&ciphertexts[i]);
    }
    fini_malloced_bytes(&key_bytes);
    return ret;
}
