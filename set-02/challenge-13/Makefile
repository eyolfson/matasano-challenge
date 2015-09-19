NAME := ecb-cut-and-paste

CC := clang
CFLAGS := -O2 -Wall -I../../include
LDFLAGS := -L../../lib -lmatasano

.PHONY: all
all: libmatasano $(NAME)

.PHONY: run
run: all
	LD_LIBRARY_PATH=../../lib ./$(NAME)

$(NAME): main.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

.PHONY: libmatasano
libmatasano:
	$(MAKE) -C ../../lib

.PHONY: clean
clean:
	rm -f $(NAME)
