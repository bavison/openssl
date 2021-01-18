#ifndef __KERNEL__
# include "crypto/arm_arch.h"
#else
#endif

.text

.type   _bsaes_decrypt8,%function
.align  4
_bsaes_decrypt8:
    ret
.size   _bsaes_decrypt8,.-_bsaes_decrypt8

.type   _bsaes_const,%object
.align  6
_bsaes_const:
.LM0_bigendian:
.quad   0x02060a0e03070b0f, 0x0004080c0105090d
.LM0_littleendian:
.quad   0x0105090d0004080c, 0x03070b0f02060a0e
.align  6
.size   _bsaes_const,.-_bsaes_const

.type   _bsaes_encrypt8,%function
.align  4
_bsaes_encrypt8:
    ret
.size   _bsaes_encrypt8,.-_bsaes_encrypt8

// TODO: remove .globl
.globl  _bsaes_key_convert

.type   _bsaes_key_convert,%function
.align  4
// On entry:
//   x9 -> input key (big-endian)
//   x10 = number of rounds
//   x17 -> output key
// On exit:
//   x9, x10 corrupted
//   x11 -> .LM0_bigendian
//   x17 -> last quadword of output key
//   other general-purpose registers preserved
//   v7.8[] = 0x63
//   v15 = last round key (converted to native endianness)
//   other SIMD registers corrupted
_bsaes_key_convert:
        adr     x11, .LM0_bigendian         // adr r6,.LM0
        ld1     {v7.16b}, [x9], #16         // vld1.8  {q7},  [r4]!        @ load round 0 key
        ld1     {v15.16b}, [x9], #16        // vld1.8  {q15}, [r4]!        @ load round 1 key

        movi    v8.16b, #0x01               // vmov.i8 q8,  #0x01          @ bit masks
        movi    v9.16b, #0x02
        movi    v10.16b, #0x04
        movi    v11.16b, #0x08
        movi    v12.16b, #0x10
        movi    v13.16b, #0x20
        ld1     {v14.16b}, [x11]            // vldmia  r6, {q14}       @ .LM0

#ifdef __ARMEL__
        rev32   v7.16b, v7.16b              // vrev32.8    q7,  q7
        rev32   v15.16b, v15.16b            // vrev32.8    q15, q15
#endif
        sub     x10, x10, #1                // sub r5,r5,#1
        st1     {v7.16b}, [x17], #16        // vstmia  r12!, {q7}      @ save round 0 key
                                            // b   .Lkey_loop
                                            //
                                            // .align  4
.Lkey_loop:
        tbl     v7.16b, {v15.16b}, v14.16b // vtbl.8  d14,{q15},d28  vtbl.8  d15,{q15},d29
        movi    v6.16b, #0x40               // vmov.i8 q6,  #0x40
        movi    v15.16b, #0x80              // vmov.i8 q15, #0x80

        cmtst   v0.16b, v7.16b, v8.16b      // vtst.8  q0, q7, q8
        cmtst   v1.16b, v7.16b, v9.16b      // vtst.8  q1, q7, q9
        cmtst   v2.16b, v7.16b, v10.16b     // vtst.8  q2, q7, q10
        cmtst   v3.16b, v7.16b, v11.16b     // vtst.8  q3, q7, q11
        cmtst   v4.16b, v7.16b, v12.16b     // vtst.8  q4, q7, q12
        cmtst   v5.16b, v7.16b, v13.16b     // vtst.8  q5, q7, q13
        cmtst   v6.16b, v7.16b, v6.16b      // vtst.8  q6, q7, q6
        cmtst   v7.16b, v7.16b, v15.16b     // vtst.8  q7, q7, q15
        ld1     {v15.16b}, [x9], #16        // vld1.8  {q15}, [r4]!        @ load next round key
        mvn     v0.16b, v0.16b              // vmvn    q0, q0      @ "pnot"
        mvn     v1.16b, v1.16b              // vmvn    q1, q1
        mvn     v5.16b, v5.16b              // vmvn    q2, q2
        mvn     v6.16b, v6.16b              // vmvn    q3, q3
#ifdef __ARMEL__
        rev32   v15.16b, v15.16b
#endif
        sub     x10, x10, #1                // subs    r5,r5,#1
        st1     {v0.16b-v3.16b}, [x17], #64 // vstmia  r12!,{q0,q1,q2,q3,q4,q5,q6,q7}      @ write bit-sliced round key
        st1     {v4.16b-v7.16b}, [x17], #64
        cbnz    x10, .Lkey_loop             // bne .Lkey_loop

        movi    v7.16b, #0x63               // vmov.i8 q7,#0x63            @ compose .L63
        // don't save last round key
    ret                                     // bx  lr
.size   _bsaes_key_convert,.-_bsaes_key_convert

.globl  bsaes_cbc_encrypt
.type   bsaes_cbc_encrypt,%function
.align  4
bsaes_cbc_encrypt:
    ret
.size   bsaes_cbc_encrypt,.-bsaes_cbc_encrypt

.globl  bsaes_ctr32_encrypt_blocks
.type   bsaes_ctr32_encrypt_blocks,%function
.align  4
bsaes_ctr32_encrypt_blocks:
    ret
.size   bsaes_ctr32_encrypt_blocks,.-bsaes_ctr32_encrypt_blocks

.globl  bsaes_xts_encrypt
.type   bsaes_xts_encrypt,%function
.align  4
bsaes_xts_encrypt:
    ret
.size   bsaes_xts_encrypt,.-bsaes_xts_encrypt

.globl  bsaes_xts_decrypt
.type   bsaes_xts_decrypt,%function
.align  4
bsaes_xts_decrypt:
    ret
.size   bsaes_xts_decrypt,.-bsaes_xts_decrypt
