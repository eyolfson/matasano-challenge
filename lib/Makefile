CC := clang
CFLAGS := -O2 -Wall -fPIC -I../include

libmatasano.so: aes.o pkcs7.o mt19937.o utils.o
	$(CC) -shared $^ -o $@ -lcrypto

.PHONY: clean
clean:
	rm -f *.o
	rm -f libmatasano.so
