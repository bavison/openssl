#include "tester.h"

#define MIN_ROUNDS 2
#define MAX_ROUNDS 16

extern void _bsaes_key_convert(void);

const unsigned int default_number_of_runs = 100;

static void wrapper(void (*routine)(), void *input_key, long rounds, void *output_key, void **lm_pointer, void **updated_output_key, uint32_t (*pattern)[4], uint32_t (*last_round_key)[4])
{
    /* Marshall arguments into the appropriate places */
    r[4] = (long) input_key;
    r[5] = rounds;
    r[12] = (long) output_key;

    /* Call generic assembly veneer */
    veneer(routine, r, v);

    /* Extract the results we're interested in */
    if (lm_pointer != NULL)
        *lm_pointer = (void *) r[6];
    if (updated_output_key != NULL)
        *updated_output_key = (void *) r[12];
    if (pattern != NULL)
        memcpy(pattern, &v[16*7], sizeof *pattern);
    if (last_round_key != NULL)
#ifdef __aarch64__
        memcpy(last_round_key, &v[16*8], sizeof *last_round_key);
#else
        memcpy(last_round_key, &v[16*15], sizeof *last_round_key);
#endif
}

void benchmark(void)
{
#define ITERATIONS 10000000

    uint8_t input_key[16*(MAX_ROUNDS+1)];
    uint8_t output_key[128*MAX_ROUNDS - 96];

    /* Ensure buffers are in L1 cache */
    memset(input_key, 0, sizeof input_key);
    memset(output_key, 0, sizeof output_key);

    uint64_t t0 = gettime();
    for (int i = ITERATIONS; i != 0; --i)
        wrapper(do_nothing, input_key, MAX_ROUNDS, output_key, NULL, NULL, NULL, NULL);
    uint64_t t1 = gettime();
    for (int i = ITERATIONS; i != 0; --i)
        wrapper(_bsaes_key_convert, input_key, MAX_ROUNDS, output_key, NULL, NULL, NULL, NULL);
    uint64_t t2 = gettime();

    printf("%" PRIu64 "\n", t2 - 2*t1 + t0);
}

void fuzz(unsigned int seed)
{
    long rounds = rand_limited(MIN_ROUNDS, MAX_ROUNDS);
    uint8_t input_key[16*(rounds+1)];
    uint8_t output_key[128*rounds - 96];
    uint32_t pattern[4];
    uint32_t last_round_key[4];
    uint32_t *lm_pointer;
    uint8_t *updated_output_key;

    rand_buffer(input_key, sizeof input_key);
    rand_buffer(output_key, sizeof output_key);
    randomise_registers();

    wrapper(_bsaes_key_convert, input_key, rounds, output_key, (void **) &lm_pointer, (void **) &updated_output_key, &pattern, &last_round_key);

    DUMP_ARRAY(output_key);
    DUMP_ARRAY(pattern);
    DUMP_ARRAY(last_round_key);
    DUMP32(*lm_pointer);
    DUMP_OFFSET(updated_output_key, output_key);
}

