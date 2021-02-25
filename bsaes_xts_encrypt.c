#include "tester.h"

#define XTS_CHAIN_TWEAK // used in Linux kernel builds
//#define RANDOM_CANDIDATES

#define AES_MAXNR 14

#ifdef XTS_CHAIN_TWEAK
#define PARAMS(a,b) b
#else
#define PARAMS(a,b) a, b
#endif

struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
    int flag;
    char key_schedule[14 * 128 - 96];
};
typedef struct aes_key_st AES_KEY;

void bsaes_xts_encrypt(const unsigned char *inp, unsigned char *out,
                       size_t len, const AES_KEY *key1,
#ifndef XTS_CHAIN_TWEAK
                       const AES_KEY *key2, const
#endif
                       unsigned char iv[16]);

const unsigned int default_number_of_runs = 200;

static __attribute__((noinline)) void wrapper(void (*routine)(const unsigned char *, unsigned char *, size_t, const AES_KEY *,
#ifndef XTS_CHAIN_TWEAK
                                                              const AES_KEY *, const
#endif
                                                              unsigned char *),
        const unsigned char *in, unsigned char *out,
        size_t len, const AES_KEY *key1,
#ifndef XTS_CHAIN_TWEAK
        const AES_KEY *key2, const
#endif
        unsigned char iv[16])
{
    routine(in, out, len, key1, PARAMS(key2, iv));
}

void benchmark(void)
{
#ifdef RANDOM_CANDIDATES
    extern void (*candidates[100])(const unsigned char *, unsigned char *, size_t, const AES_KEY *,
#ifndef XTS_CHAIN_TWEAK
                                   const AES_KEY *, const
#endif
                                   unsigned char *);
    size_t c = atoi(getenv("CANDIDATE"));
#endif

#define ITERATIONS 200000

    unsigned char in[1024];
    unsigned char out[1024];
    AES_KEY key1 = { .rounds = 14, .flag = 2 };
    AES_KEY key2 = { .rounds = 14, .flag = 2 };
    unsigned char iv[16];
    (void) key2;

    /* Ensure buffers are in L1 cache */
    memset(in, 0, sizeof in);
    memset(out, 0, sizeof out);
    memset(iv, 0, sizeof iv);

    uint64_t t0 = gettime();
    for (int i = ITERATIONS; i != 0; --i)
        wrapper((void (*)(const unsigned char *, unsigned char *, size_t, const AES_KEY *,
#ifndef XTS_CHAIN_TWEAK
                          const AES_KEY *, const
#endif
                          unsigned char *)) do_nothing,
                in, out, 1024, &key1, PARAMS(&key2, iv));
    uint64_t t1 = gettime();
    for (int i = ITERATIONS; i != 0; --i)
#ifdef RANDOM_CANDIDATES
        wrapper(candidates[c-1],
#else
        wrapper(bsaes_xts_encrypt,
#endif
                in, out, 1024, &key1, PARAMS(&key2, iv));
    uint64_t t2 = gettime();

    printf("%" PRIu64 "\n", t2 - 2*t1 + t0);
}

void fuzz(unsigned int seed)
{
    unsigned char in[1024];
    rand_buffer(in, sizeof in);

    unsigned char out[1024];
    rand_buffer(out, sizeof in);

    uint16_t len = rand_limited(16,1024);

    AES_KEY key1;
    rand_buffer(key1.rd_key, sizeof key1.rd_key);
    key1.rounds = 10 + 2 * rand_limited(0,2);
    key1.flag = 0;
    rand_buffer(key1.key_schedule, sizeof key1.key_schedule);

    AES_KEY key2;
    rand_buffer(key2.rd_key, sizeof key2.rd_key);
    key2.rounds = 10 + 2 * rand_limited(0,2);
    key2.flag = 0;
    rand_buffer(key2.key_schedule, sizeof key2.key_schedule);

    unsigned char iv[16];
    rand_buffer(iv, sizeof iv);

    DUMP16(len);

    wrapper(bsaes_xts_encrypt, in, out, len, &key1, PARAMS(&key2, iv));

    DUMP_ARRAY(out);
    DUMP_OBJECT(key1);
    DUMP_OBJECT(key2);
    DUMP_ARRAY(iv);

    (void) veneer;
    (void) randomise_registers;
}
