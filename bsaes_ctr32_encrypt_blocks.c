#include "tester.h"

#define AES_MAXNR 14

struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
    int flag;
    char key_schedule[14 * 128 - 96];
};
typedef struct aes_key_st AES_KEY;

void bsaes_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const AES_KEY *key,
                                const unsigned char ivec[16]);

const unsigned int default_number_of_runs = 100;

static __attribute__((noinline)) void wrapper(void (*routine)(const unsigned char *, unsigned char *, size_t, const AES_KEY *, const unsigned char *),
        const unsigned char *in, unsigned char *out,
        size_t len, const AES_KEY *key,
        const unsigned char ivec[16])
{
    routine(in, out, len, key, ivec);
}

void benchmark(void)
{
#define ITERATIONS 200000

    unsigned char in[1024];
    unsigned char out[1024];
    AES_KEY key = { .rounds = 14, .flag = 2 };
    unsigned char counter[16];

    /* Ensure buffers are in L1 cache */
    memset(in, 0, sizeof in);
    memset(out, 0, sizeof out);
    memset(counter, 0, sizeof counter);

    uint64_t t0 = gettime();
    for (int i = ITERATIONS; i != 0; --i)
        wrapper((void (*)(const unsigned char *, unsigned char *, size_t, const AES_KEY *, const unsigned char *)) do_nothing,
                in, out, 1024/16, &key, counter);
    uint64_t t1 = gettime();
    for (int i = ITERATIONS; i != 0; --i)
        wrapper(bsaes_ctr32_encrypt_blocks,
                in, out, 1024/16, &key, counter);
    uint64_t t2 = gettime();

    printf("%" PRIu64 "\n", t2 - 2*t1 + t0);
}

void fuzz(unsigned int seed)
{
    unsigned char in[1024];
    rand_buffer(in, sizeof in);

    unsigned char out[1024];
    rand_buffer(out, sizeof in);

    uint16_t len = rand_limited(1,1024/16);

    AES_KEY key;
    rand_buffer(key.rd_key, sizeof key.rd_key);
    key.rounds = 10 + 2 * rand_limited(0,2);
    key.flag = 0;
    rand_buffer(key.key_schedule, sizeof key.key_schedule);

    unsigned char counter[16];
    rand_buffer(counter, sizeof counter);

    DUMP16(len);

    wrapper(bsaes_ctr32_encrypt_blocks, in, out, len, &key, counter);

    DUMP_ARRAY(out);
    DUMP_OBJECT(key);

    (void) veneer;
    (void) randomise_registers;
}
