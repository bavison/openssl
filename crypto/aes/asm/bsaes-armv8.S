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
        adr     x11, .LM0_bigendian
        ld1     {v7.16b}, [x9], #16         // load round 0 key
        ld1     {v15.16b}, [x9], #16        // load round 1 key

        movi    v8.16b, #0x01               // bit masks
        movi    v9.16b, #0x02
        movi    v10.16b, #0x04
        movi    v11.16b, #0x08
        movi    v12.16b, #0x10
        movi    v13.16b, #0x20
        ld1     {v14.16b}, [x11]            // .LM0_bigendian

#ifdef __ARMEL__
        rev32   v7.16b, v7.16b
        rev32   v15.16b, v15.16b
#endif
        sub     x10, x10, #1
        st1     {v7.16b}, [x17], #16        // save round 0 key

.Lkey_loop:
        tbl     v7.16b, {v15.16b}, v14.16b
        movi    v6.16b, #0x40
        movi    v15.16b, #0x80

        cmtst   v0.16b, v7.16b, v8.16b
        cmtst   v1.16b, v7.16b, v9.16b
        cmtst   v2.16b, v7.16b, v10.16b
        cmtst   v3.16b, v7.16b, v11.16b
        cmtst   v4.16b, v7.16b, v12.16b
        cmtst   v5.16b, v7.16b, v13.16b
        cmtst   v6.16b, v7.16b, v6.16b
        cmtst   v7.16b, v7.16b, v15.16b
        ld1     {v15.16b}, [x9], #16        // load next round key
        mvn     v0.16b, v0.16b              // "pnot"
        mvn     v1.16b, v1.16b
        mvn     v5.16b, v5.16b
        mvn     v6.16b, v6.16b
#ifdef __ARMEL__
        rev32   v15.16b, v15.16b
#endif
        sub     x10, x10, #1
        st1     {v0.16b-v3.16b}, [x17], #64 // write bit-sliced round key
        st1     {v4.16b-v7.16b}, [x17], #64
        cbnz    x10, .Lkey_loop

        movi    v7.16b, #0x63               // compose .L63
        // don't save last round key
        ret                                 // bx  lr
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
