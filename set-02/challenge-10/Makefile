CC := clang

decrypt_aes_128_cbc: decrypt_aes_128_cbc.c
	$(CC) -O2 $^ -o $@ -lcrypto

.PHONY: clean
clean:
	rm -f decrypt_aes_128_cbc
