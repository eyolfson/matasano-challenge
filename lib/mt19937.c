#include "matasano/mt19937.h"

void mt19937_init(struct mt19937 *mt19937, uint32_t seed)
{
	mt19937->index = MT19937_N;
	mt19937->mt[0] = seed;
	for (uint16_t i = 1; i < MT19937_N; ++i) {
		mt19937->mt[i] = 0;
	}
	for (uint16_t i = 1; i < MT19937_N; ++i) {
		mt19937->mt[i] = MT19937_F
		                 * (mt19937->mt[i - 1]
		                    ^ (mt19937->mt[i -1] >> (MT19937_W - 2)))
		                 + i;
	}
}

static void twist(struct mt19937 *mt19937)
{
	for (uint16_t i = 0; i < MT19937_N; ++i) {
		uint32_t y = (mt19937->mt[i] & 0x80000000)
		             + (mt19937->mt[(i + 1) % MT19937_N] & 0x7FFFFFFF);
		mt19937->mt[i] = mt19937->mt[(i + MT19937_M) % MT19937_N]
		                 ^ y >> 1;
		if (y % 2 != 0) {
			mt19937->mt[i] = mt19937->mt[i] ^ MT19937_A;
		}
	}
	mt19937->index = 0;
}

uint32_t mt19937_next(struct mt19937 *mt19937)
{
	if (mt19937->index == MT19937_N) {
		twist(mt19937);
	}
	uint32_t y = mt19937->mt[mt19937->index];
	y = y ^ ((y >> MT19937_U) & MT19937_D);
	y = y ^ ((y << MT19937_S) & MT19937_B);
	y = y ^ ((y << MT19937_T) & MT19937_C);
	y = y ^ (y >> MT19937_L);
	++mt19937->index;
	return y;
}
