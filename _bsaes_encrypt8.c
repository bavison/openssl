#include "tester.h"

#define MIN_ROUNDS 2
#define MAX_ROUNDS 16

extern void _bsaes_encrypt8(void);

const unsigned int default_number_of_runs = 100;

static void wrapper(void (*routine)(), void *key, long rounds)
{
    /* Marshall arguments into the appropriate places */
    r[4] = (long) key;
    r[5] = rounds;

    /* Call generic assembly veneer */
    veneer(routine, r, v);
}

void benchmark(void)
{
#define ITERATIONS 1000000

    uint8_t key[128*MAX_ROUNDS - 96];

    /* Ensure buffers are in L1 cache */
    memset(key, 0, sizeof key);

    uint64_t t0 = gettime();
    for (int i = ITERATIONS; i != 0; --i)
        wrapper(do_nothing, key, MAX_ROUNDS);
    uint64_t t1 = gettime();
    for (int i = ITERATIONS; i != 0; --i)
        wrapper(_bsaes_encrypt8, key, MAX_ROUNDS);
    uint64_t t2 = gettime();

    printf("%" PRIu64 "\n", t2 - 2*t1 + t0);
}

void fuzz(unsigned int seed)
{
    long rounds = rand_limited(MIN_ROUNDS, MAX_ROUNDS);
    uint8_t key[128*rounds - 96];

    rand_buffer(key, sizeof key);
    randomise_registers();

    uint32_t rounds32 = rounds;
    DUMP32(rounds32);

    wrapper(_bsaes_encrypt8, key, rounds);

    uint8_t (*first_8_vectors)[8*16] = (void *) v;

    DUMP_ARRAY(*first_8_vectors);
}

