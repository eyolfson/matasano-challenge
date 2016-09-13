#include "matasano/mt19937.h"

void encrypt(uint16_t seed)
{
	struct mt19937 mt19937;
	mt19937_init(&mt19937, seed);
}

int main()
{
	uint8_t ret = 0;

	return ret;
}
