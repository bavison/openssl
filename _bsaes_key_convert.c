#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/time.h>

#define STR(x) #x

const unsigned int default_number_of_runs;
void benchmark(void);
void fuzz(unsigned int seed);

/** Storage for core registers:
 * AArch32: r0-r12         32-bit long = 32-bit registers
 * AArch64: x0-x3, x9-x17  64-bit long = 64-bit registers
 */
static long r[13];
/** Storage for NEON registers:
 *  q0-q15  16 x 16-byte registers
 *  AArch64's q16-q31 not considered since no analogy in AArch32
 */
static uint8_t v[256];

/** Produce random number with 32 bits of entropy */
static inline uint32_t rand32(void)
{
    /* rand() is technically only required to produce 15 bits of entropy by the
     * C standard, but in practice most implementations produce 31 bits */
    return rand() << 16 ^ rand();
}

/** Produce random number with 64 bits of entropy */
static inline uint64_t rand64(void)
{
    /* rand() is technically only required to produce 15 bits of entropy by the
     * C standard, but in practice most implementations produce 31 bits */
    return (uint64_t) rand() << 48 ^ (uint64_t) rand() << 32 ^ (uint64_t) rand() << 16 ^ rand();
}

/** Produce random number within limmits */
static inline uint32_t rand_limited(uint32_t min, uint32_t max)
{
    return min + rand32() % (max + 1 - min);
}

/** Fill a buffer with random numbers */
static inline void rand_buffer(void *b, size_t s)
{
    /* rand() is technically only required to produce 15 bits of entropy by the
     * C standard, but in practice most implementations produce 31 bits */
    uint16_t *p = b;
    for (; s >= 2; s -= 2)
        *p++ = rand();
    if (s == 1)
        *(uint8_t *)p = rand();
}

/** Find real time in microseconds */
static uint64_t gettime(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (uint64_t) now.tv_sec * 1000000 + now.tv_usec;
}

/** Initialise all registers randomly, to ensure we don't
 *  depend on their values. Generate 64 bits of randomness
 *  for core registers, even in 32-bit mode, to ensure the
 *  RNG remains in step with 64-bit mode.
 */
static void randomise_registers(void)
{
    for (size_t i = 0; i < 13; ++i)
        r[i] = rand64();
    rand_buffer(v, sizeof v);
}

#define DUMP8(x)  do { printf("%u: " STR(x) ": %02"  PRIX8  "\n", seed, x); } while (0)
#define DUMP16(x) do { printf("%u: " STR(x) ": %04"  PRIX16 "\n", seed, x); } while (0)
#define DUMP32(x) do { printf("%u: " STR(x) ": %08"  PRIX32 "\n", seed, x); } while (0)
#define DUMP64(x) do { printf("%u: " STR(x) ": %016" PRIX64 "\n", seed, x); } while (0)
#define DUMP_OFFSET(p, base) do { printf("%u: " STR(x) ": " STR(base) "+%zd\n", seed, (uint8_t *) p - (uint8_t *) base); } while (0)
#define DUMP_ARRAY(b) do { dump_buffer(seed, STR(b), b, sizeof b); } while (0)

static void dump_buffer(unsigned int seed, const char *name, const void *b, size_t s)
{
    const uint8_t *bb = b;
    size_t offset = 0;
    printf("%u: %s:\n", seed, name);
    while (offset < s)
    {
        if ((offset & 15) == 0)
            printf("%08zX :", offset);
        if (offset + 4 <= s)
        {
            printf(" %08X", *(uint32_t *)(bb + offset));
            offset += 4;
        }
        else if ((offset + 1 <= s))
        {
            printf(" %02X", bb[offset]);
            offset += 1;
        }
        if ((offset & 15) == 0 || offset == s)
            printf("\n");
    }
}

/** Reference function that does nothing - useful for subtracting argument marshalling overhead from benchmarks */
void do_nothing(void);
void do_nothing(void)
{
}

/** Facilitate testing of functions with non-standard argument/result marshalling */
static void veneer(void (*routine)(), long r[13], uint8_t v[256])
{
    __asm__ volatile (
#ifdef __arm__
        "sub     sp, sp, #4*1                \n\t"
        "push    {%[v]}                      \n\t"
        "push    {%[r]}                      \n\t"
        "push    {%[routine]}                \n\t"
        "push    {a1-a4,v1-v8,ip,lr}         \n\t"
        "vpush   {d16-d31}                   \n\t"
        "vpush   {d0-d15}                    \n\t"
        "ldr     lr, [sp, #8*32+4*(14+2)]    \n\t"
        "vldmia  lr!, {d0-d15}               \n\t"
        "vldmia  lr, {d16-d31}               \n\t"
        "ldr     lr, [sp, #8*32+4*(14+1)]    \n\t"
        "ldmia   lr, {a1-a4,v1-v8,ip}        \n\t"
        "mov     lr, pc                      \n\t"
        "ldr     pc, [sp, #8*32+4*14]        \n\t"
        "ldr     lr, [sp, #8*32+4*(14+1)]    \n\t"
        "stmia   lr, {a1-a4,v1-v8,ip}        \n\t"
        "ldr     lr, [sp, #8*32+4*(14+2)]    \n\t"
        "vstmia  lr!, {d0-d15}               \n\t"
        "vstmia  lr, {d16-d31}               \n\t"
        "vpop    {d0-d15}                    \n\t"
        "vpop    {d16-d31}                   \n\t"
        "pop     {a1-a4,v1-v8,ip,lr}         \n\t"
        "add     sp, sp, #4*4                \n\t"
#endif
#ifdef __aarch64__
        "stp     %[v], lr, [sp, #-16]!         \n\t"
        "stp     %[routine], %[r], [sp, #-16]! \n\t"
        "stp     x16, x17, [sp, #-16]!         \n\t"
        "stp     x14, x15, [sp, #-16]!         \n\t"
        "stp     x12, x13, [sp, #-16]!         \n\t"
        "stp     x10, x11, [sp, #-16]!         \n\t"
        "stp     x8, x9, [sp, #-16]!           \n\t"
        "stp     x6, x7, [sp, #-16]!           \n\t"
        "stp     x4, x5, [sp, #-16]!           \n\t"
        "stp     x2, x3, [sp, #-16]!           \n\t"
        "stp     x0, x1, [sp, #-16]!           \n\t"
        "stp     q30, q31, [sp, #-32]!         \n\t"
        "stp     q28, q29, [sp, #-32]!         \n\t"
        "stp     q26, q27, [sp, #-32]!         \n\t"
        "stp     q24, q25, [sp, #-32]!         \n\t"
        "stp     q22, q23, [sp, #-32]!         \n\t"
        "stp     q20, q21, [sp, #-32]!         \n\t"
        "stp     q18, q19, [sp, #-32]!         \n\t"
        "stp     q16, q17, [sp, #-32]!         \n\t"
        "stp     q14, q15, [sp, #-32]!         \n\t"
        "stp     q12, q13, [sp, #-32]!         \n\t"
        "stp     q10, q11, [sp, #-32]!         \n\t"
        "stp     q8, q9, [sp, #-32]!           \n\t"
        "stp     q6, q7, [sp, #-32]!           \n\t"
        "stp     q4, q5, [sp, #-32]!           \n\t"
        "stp     q2, q3, [sp, #-32]!           \n\t"
        "stp     q0, q1, [sp, #-32]!           \n\t"
        "ldr     lr, [sp, #16*32+8*(18+2)]     \n\t"
        "ld1     {v0.16b-v3.16b}, [lr], #64    \n\t"
        "ld1     {v4.16b-v7.16b}, [lr], #64    \n\t"
        "ld1     {v8.16b-v11.16b}, [lr], #64   \n\t"
        "ld1     {v12.16b-v15.16b}, [lr]       \n\t"
        "ldr     lr, [sp, #16*32+8*(18+1)]     \n\t"
        "ldp     x0, x1, [lr], #16             \n\t"
        "ldp     x2, x3, [lr], #16             \n\t"
        "ldp     x9, x10, [lr], #16            \n\t"
        "ldp     x11, x12, [lr], #16           \n\t"
        "ldp     x13, x14, [lr], #16           \n\t"
        "ldp     x15, x16, [lr], #16           \n\t"
        "ldr     x17, [lr]                     \n\t"
        "ldr     lr, [sp, #16*32+8*18]         \n\t"
        "blr     lr                            \n\t"
        "ldr     lr, [sp, #16*32+8*(18+1)]     \n\t"
        "stp     x0, x1, [lr], #16             \n\t"
        "stp     x2, x3, [lr], #16             \n\t"
        "stp     x9, x10, [lr], #16            \n\t"
        "stp     x11, x12, [lr], #16           \n\t"
        "stp     x13, x14, [lr], #16           \n\t"
        "stp     x15, x16, [lr], #16           \n\t"
        "str     x17, [lr]                     \n\t"
        "ldr     lr, [sp, #16*32+8*(18+2)]     \n\t"
        "st1     {v0.16b-v3.16b}, [lr], #64    \n\t"
        "st1     {v4.16b-v7.16b}, [lr], #64    \n\t"
        "st1     {v8.16b-v11.16b}, [lr], #64   \n\t"
        "st1     {v12.16b-v15.16b}, [lr]       \n\t"
        "ldp     q0, q1, [sp], #32             \n\t"
        "ldp     q2, q3, [sp], #32             \n\t"
        "ldp     q4, q5, [sp], #32             \n\t"
        "ldp     q6, q7, [sp], #32             \n\t"
        "ldp     q8, q9, [sp], #32             \n\t"
        "ldp     q10, q11, [sp], #32           \n\t"
        "ldp     q12, q13, [sp], #32           \n\t"
        "ldp     q14, q15, [sp], #32           \n\t"
        "ldp     q16, q17, [sp], #32           \n\t"
        "ldp     q18, q19, [sp], #32           \n\t"
        "ldp     q20, q21, [sp], #32           \n\t"
        "ldp     q22, q23, [sp], #32           \n\t"
        "ldp     q24, q25, [sp], #32           \n\t"
        "ldp     q26, q27, [sp], #32           \n\t"
        "ldp     q28, q29, [sp], #32           \n\t"
        "ldp     q30, q31, [sp], #32           \n\t"
        "ldp     x0, x1, [sp], #16             \n\t"
        "ldp     x2, x3, [sp], #16             \n\t"
        "ldp     x4, x5, [sp], #16             \n\t"
        "ldp     x6, x7, [sp], #16             \n\t"
        "ldp     x8, x9, [sp], #16             \n\t"
        "ldp     x10, x11, [sp], #16           \n\t"
        "ldp     x12, x13, [sp], #16           \n\t"
        "ldp     x14, x15, [sp], #16           \n\t"
        "ldp     x16, x17, [sp], #16           \n\t"
        "ldr     lr, [sp, #8*3]                \n\t"
        "add     sp, sp, #8*4                  \n\t"
#endif
    : // Outputs
    : // Inputs
        [routine]"r"(routine),
              [r]"r"(r),
              [v]"r"(v)
    : // Clobbers
        "cc", "memory"
    );
}

int main(int argc, char *argv[])
{
    if ((argc > 1 && strcmp(argv[1], "--help") == 0) || argc >= 4)
    {
        fprintf(stderr, "Syntax:\n"
                        "%s benchmark\n"
                        "or\n"
                        "%s\n"
                        "or\n"
                        "%s <fuzz seed>\n"
                        "or\n"
                        "%s <fuzz seed minimum> <fuzz seed maximum>\n",
                        argv[0], argv[0], argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }
    if (argc == 2 && strcmp(argv[1], "benchmark") == 0)
    {
        benchmark();
        exit(EXIT_SUCCESS);
    }
    unsigned int seed_min = argc >= 2 ? strtoul(argv[1], NULL, 10) : 0;
    unsigned int seed_max = argc >= 3 ? strtoul(argv[2], NULL, 10) + 1 :
                            argc == 2 ? strtoul(argv[1], NULL, 10) + 1 :
                            default_number_of_runs;
    for (unsigned int seed = seed_min; seed < seed_max; ++seed)
    {
        srand(seed);
        fuzz(seed);
    }
    exit(EXIT_SUCCESS);
}



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
        memcpy(last_round_key, &v[16*15], sizeof *last_round_key);
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

//    printf("%" PRIu64 ", %" PRIu64 ", %" PRIu64 "\n", t1-t0, t2-t1, t2 - 2*t1 + t0);
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

