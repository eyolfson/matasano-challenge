#include "matasano/mt19937.h"

#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define MINIMUM 40
#define INTERVAL 961

uint32_t rng_output()
{
	struct mt19937 mt19937;

	mt19937_init(&mt19937, time(NULL));
	uint32_t wait_time = (mt19937_next(&mt19937) % INTERVAL) + MINIMUM;
	printf("Sleep %u\n", wait_time);
	sleep(wait_time);

	wait_time = (mt19937_next(&mt19937) % INTERVAL) + MINIMUM;
	uint32_t seed = time(NULL);
	printf("Seed %u\n", seed);
	mt19937_init(&mt19937, time(NULL));

	printf("Sleep %u\n", wait_time);
	sleep(wait_time);

	return mt19937_next(&mt19937);
}

int main()
{
	uint8_t ret = 0;

	uint32_t output = rng_output();

	struct mt19937 mt19937;
	int32_t seed_guess = time(NULL) - MINIMUM + 1;
	bool found = false;
	for (int32_t i = 0; i < (INTERVAL + 1); ++i) {
		mt19937_init(&mt19937, seed_guess);
		if (mt19937_next(&mt19937) == output) {
			printf("Found seed %u\n", seed_guess);
			found = true;
			break;
		}
		--seed_guess;
	}
	if (!found) {
		printf("Did not find seed\n");
	}

	return ret;
}
