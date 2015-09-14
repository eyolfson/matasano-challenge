CC := clang
CFLAGS := -O2 -Wall -fPIC -I../include

libmatasano.so: aes_128.o utils.o
	$(CC) -shared $^ -o $@ -lcrypto

.PHONY: clean
clean:
	rm -f *.o
	rm -f libmatasano.so
