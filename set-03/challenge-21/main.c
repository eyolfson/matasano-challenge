#include "matasano/mt19937.h"

#include <stdint.h>
#include <stdio.h>

int main()
{
	uint8_t ret = 0;

	struct mt19937 mt19937;
	mt19937_init(&mt19937, 4357);
	printf("%u\n", mt19937_next(&mt19937));
	printf("%u\n", mt19937_next(&mt19937));
	printf("%u\n", mt19937_next(&mt19937));
	printf("%u\n", mt19937_next(&mt19937));
	printf("%u\n", mt19937_next(&mt19937));

	return ret;
}
