CFLAGS := -fPIC -I../include

libmatasano.so: file_content.o
	$(CC) -shared $^ -o $@

.PHONY: clean
clean:
	rm -f *.o
	rm -f libmatasano.so
