#ifndef MATASANO_MT19937
#define MATASANO_MT19937

#include <stdint.h>

#define MT19937_W 32
#define MT19937_N 624
#define MT19937_M 397
#define MT19937_R 31
#define MT19937_A 0x9908B0DF
#define MT19937_U 11
#define MT19937_D 0xFFFFFFFF
#define MT19937_S 7
#define MT19937_B 0x9D2C5680
#define MT19937_T 15
#define MT19937_C 0xEFC60000
#define MT19937_L 18
#define MT19937_F 1812433253

struct mt19937 {
	uint16_t index;
	uint32_t mt[624];
};

void mt19937_init(struct mt19937 *mt19937, uint32_t seed);
uint32_t mt19937_next(struct mt19937 *mt19937);

#endif
