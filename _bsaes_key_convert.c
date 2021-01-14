#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

const unsigned int default_number_of_runs;
void benchmark(void);
void fuzz(void);

/** Produce random number with 32 bits of entropy */
inline uint32_t rand32(void)
{
    /* rand() is technically only required to produce 15 bits of entropy by the
     * C standard, but in practice most implementations produce 31 bits */
    return rand() << 16 ^ rand();
}

/** Produce random number with 64 bits of entropy */
inline uint64_t rand64(void)
{
    /* rand() is technically only required to produce 15 bits of entropy by the
     * C standard, but in practice most implementations produce 31 bits */
    return (uint64_t) rand() << 48 ^ (uint64_t) rand() << 32 ^ (uint64_t) rand() << 16 ^ rand();
}

/** Fill a buffer with random numbers */
inline void rand_buffer(void *b, size_t s)
{
    /* rand() is technically only required to produce 15 bits of entropy by the
     * C standard, but in practice most implementations produce 31 bits */
    uint16_t *p = b;
    for (; s >= 2; s -= 2)
        *p++ = rand();
    if (s == 1)
        *(uint8_t *)p = rand();
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
    }
    exit(EXIT_SUCCESS);
}


const unsigned int default_number_of_runs = 1;

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
        "ldr     lr, [sp, #16*32+8*(17+2)]     \n\t"
        "ld1     {v0.16b-v3.16b}, [lr], #64    \n\t"
        "ld1     {v4.16b-v7.16b}, [lr], #64    \n\t"
        "ld1     {v8.16b-v11.16b}, [lr], #64   \n\t"
        "ld1     {v12.16b-v15.16b}, [lr]       \n\t"
        "ldr     lr, [sp, #16*32+8*(17+1)]     \n\t"
        "ldp     x0, x1, [lr], #16             \n\t"
        "ldp     x2, x3, [lr], #16             \n\t"
        "ldp     x9, x10, [lr], #16            \n\t"
        "ldp     x11, x12, [lr], #16           \n\t"
        "ldp     x13, x14, [lr], #16           \n\t"
        "ldp     x15, x16, [lr], #16           \n\t"
        "ldr     x17, [lr]                     \n\t"
        "ldr     lr, [sp, #16*32+8*17]         \n\t"
        "blr     lr                            \n\t"
        "ldr     lr, [sp, #16*32+8*(17+1)]     \n\t"
        "stp     x0, x1, [lr], #16             \n\t"
        "stp     x2, x3, [lr], #16             \n\t"
        "stp     x9, x10, [lr], #16            \n\t"
        "stp     x11, x12, [lr], #16           \n\t"
        "stp     x13, x14, [lr], #16           \n\t"
        "stp     x15, x16, [lr], #16           \n\t"
        "str     x17, [lr]                     \n\t"
        "ldr     lr, [sp, #16*32+8*(17+2)]     \n\t"
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

static long r[13];
static uint8_t v[256];

static void randomise_registers(void)
{
    /* Initialise all registers randomly, to ensure we don't
     * depend on their values. Generate 64 bits of randomness
     * for core registers, even in 32-bit mode, to ensure the
     * RNG remains in step with 64-bit mode.
     */
    for (size_t i = 0; i < 13; ++i)
        r[i] = rand64();
    rand_buffer(v, sizeof v);
}

extern void _bsaes_key_convert(void);

static void wrapper(void (*routine)(), void *input_key, long counter, void *output_key, void **lm_pointer, void **updated_output_key, uint32_t (*pattern)[4], uint32_t (*last_round_key)[4])
{
    /* Marshall arguments into the appropriate places */
    r[4] = (long) input_key;
    r[5] = counter;
    r[12] = (long) output_key;

    /* Call generic assembly veneer */
    veneer(routine, r, v);

    /* Extract the results we're interested in */
    *lm_pointer = (void *) r[6];
    *updated_output_key = (void *) r[12];
    memcpy(pattern, &v[16*7], sizeof *pattern);
    memcpy(last_round_key, &v[16*15], sizeof *last_round_key);
}

void benchmark(void)
{
}

void fuzz(void)
{
    uint8_t input_key[1024];
    uint8_t output_key[1024];
    uint32_t pattern[4];
    uint32_t last_round_key[4];
    uint32_t *lm_pointer;
    uint8_t *updated_output_key;

    rand_buffer(input_key, sizeof input_key);
    rand_buffer(output_key, sizeof output_key);
    randomise_registers();
    wrapper(_bsaes_key_convert, input_key, 1, output_key, (void **) &lm_pointer, (void **) &updated_output_key, &pattern, &last_round_key);
}

