#include "matasano/mt19937.h"

#include <stdio.h>

uint32_t untemper1(uint32_t y)
{
	uint32_t mask0 = 0x00007FFF;
	uint32_t mask1 = (mask0 << 15);
	uint32_t mask2 = (mask1 << 15);
	y = y ^ ((y << MT19937_T) & MT19937_C & mask1);
	y = y ^ ((y << MT19937_T) & MT19937_C & mask2);
	return y;
}

uint32_t untemper2(uint32_t y)
{
	uint32_t mask0 = 0x0000003F;
	uint32_t mask1 = (mask0 << 7);
	uint32_t mask2 = (mask1 << 7);
	uint32_t mask3 = (mask2 << 7);
	uint32_t mask4 = (mask3 << 7);
	y = y ^ ((y << MT19937_S) & MT19937_B & mask1);
	y = y ^ ((y << MT19937_S) & MT19937_B & mask2);
	y = y ^ ((y << MT19937_S) & MT19937_B & mask3);
	y = y ^ ((y << MT19937_S) & MT19937_B & mask4);
	return y;
}

uint32_t untemper3(uint32_t y)
{
	uint32_t mask0 = 0xFFE00000;
	uint32_t mask1 = (mask0 >> 11);
	uint32_t mask2 = (mask1 >> 11);
	y = y ^ ((y >> MT19937_U) & MT19937_D & mask1);
	y = y ^ ((y >> MT19937_U) & MT19937_D & mask2);
	return y;
}

uint32_t untemper(uint32_t y)
{
	y = y ^ (y >> MT19937_L);
	y = untemper1(y);
	y = untemper2(y);
	y = untemper3(y);
	return y;
}

int main()
{
	uint8_t ret = 0;

	struct mt19937 mt19937;
	mt19937_init(&mt19937, 4357);

	struct mt19937 clone;
	for (int i = 0; i < MT19937_N; ++i) {
		uint32_t n = mt19937_next(&mt19937);
		clone.mt[i] = untemper(n);
	}
	clone.index = MT19937_N;

	printf("Next:  %X\n", mt19937_next(&mt19937));
	printf("Clone: %X\n", mt19937_next(&clone));

	return ret;
}
