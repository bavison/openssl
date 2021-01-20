#ifndef __KERNEL__
# include "crypto/arm_arch.h"
#else
#endif

.text

// TODO: remove .globl
.globl  _bsaes_decrypt8

.type   _bsaes_decrypt8,%function
.align  4
// On entry:
//   r4/x9 -> key (previously expanded using _bsaes_key_convert)
//   r5/x10 = number of rounds
//   q0-q7/v0-v7 input data
// On exit:
//   r4-r6/x9-x11 corrupted
//   other general-purpose registers preserved
//   q0-q7/v0-v7 output data
//   q8-q15/v8-v15 corrupted
//   v16-v31 preserved
_bsaes_decrypt8:
        adr     x11, .LM0ISR
        ld1     {v9.16b}, [x9], #16         // round 0 key

        ld1     {v8.16b}, [x11], #16        // .LM0ISR
        eor     v10.16b, v0.16b, v9.16b     // xor with round0 key
        eor     v11.16b, v1.16b, v9.16b
        tbl     v0.16b, {v10.16b}, v8.16b
        eor     v12.16b, v2.16b, v9.16b
        tbl     v1.16b, {v11.16b}, v8.16b
        eor     v13.16b, v3.16b, v9.16b
        tbl     v2.16b, {v12.16b}, v8.16b
        eor     v14.16b, v4.16b, v9.16b
        tbl     v3.16b, {v13.16b}, v8.16b
        eor     v15.16b, v5.16b, v9.16b
        tbl     v4.16b, {v14.16b}, v8.16b
        eor     v10.16b, v6.16b, v9.16b
        tbl     v5.16b, {v15.16b}, v8.16b
        eor     v11.16b, v7.16b, v9.16b
        tbl     v6.16b, {v10.16b}, v8.16b
        tbl     v7.16b, {v11.16b}, v8.16b
        movi    v8.16b, #0x55               // compose .LBS0
        movi    v9.16b, #0x33               // compose .LBS1
        ushr    v10.2d, v6.2d, #1
        ushr    v11.2d, v4.2d, #1
        eor     v10.16b, v10.16b, v7.16b
        eor     v11.16b, v11.16b, v5.16b
        and     v10.16b, v10.16b, v8.16b
        and     v11.16b, v11.16b, v8.16b
        eor     v7.16b, v7.16b, v10.16b
        shl     v10.2d, v10.2d, #1
        eor     v5.16b, v5.16b, v11.16b
        shl     v11.2d, v11.2d, #1
        eor     v6.16b, v6.16b, v10.16b
        eor     v4.16b, v4.16b, v11.16b
        ushr    v10.2d, v2.2d, #1
        ushr    v11.2d, v0.2d, #1
        eor     v10.16b, v10.16b, v3.16b
        eor     v11.16b, v11.16b, v1.16b
        and     v10.16b, v10.16b, v8.16b
        and     v11.16b, v11.16b, v8.16b
        eor     v3.16b, v3.16b, v10.16b
        shl     v10.2d, v10.2d, #1
        eor     v1.16b, v1.16b, v11.16b
        shl     v11.2d, v11.2d, #1
        eor     v2.16b, v2.16b, v10.16b
        eor     v0.16b, v0.16b, v11.16b
        movi    v8.16b, #0x0f               // compose .LBS2
        ushr    v10.2d, v5.2d, #2
        ushr    v11.2d, v4.2d, #2
        eor     v10.16b, v10.16b, v7.16b
        eor     v11.16b, v11.16b, v6.16b
        and     v10.16b, v10.16b, v9.16b
        and     v11.16b, v11.16b, v9.16b
        eor     v7.16b, v7.16b, v10.16b
        shl     v10.2d, v10.2d, #2
        eor     v6.16b, v6.16b, v11.16b
        shl     v11.2d, v11.2d, #2
        eor     v5.16b, v5.16b, v10.16b
        eor     v4.16b, v4.16b, v11.16b
        ushr    v10.2d, v1.2d, #2
        ushr    v11.2d, v0.2d, #2
        eor     v10.16b, v10.16b, v3.16b
        eor     v11.16b, v11.16b, v2.16b
        and     v10.16b, v10.16b, v9.16b
        and     v11.16b, v11.16b, v9.16b
        eor     v3.16b, v3.16b, v10.16b
        shl     v10.2d, v10.2d, #2
        eor     v2.16b, v2.16b, v11.16b
        shl     v11.2d, v11.2d, #2
        eor     v1.16b, v1.16b, v10.16b
        eor     v0.16b, v0.16b, v11.16b
        ushr    v10.2d, v3.2d, #4
        ushr    v11.2d, v2.2d, #4
        eor     v10.16b, v10.16b, v7.16b
        eor     v11.16b, v11.16b, v6.16b
        and     v10.16b, v10.16b, v8.16b
        and     v11.16b, v11.16b, v8.16b
        eor     v7.16b, v7.16b, v10.16b
        shl     v10.2d, v10.2d, #4
        eor     v6.16b, v6.16b, v11.16b
        shl     v11.2d, v11.2d, #4
        eor     v3.16b, v3.16b, v10.16b
        eor     v2.16b, v2.16b, v11.16b
        ushr    v10.2d, v1.2d, #4
        ushr    v11.2d, v0.2d, #4
        eor     v10.16b, v10.16b, v5.16b
        eor     v11.16b, v11.16b, v4.16b
        and     v10.16b, v10.16b, v8.16b
        and     v11.16b, v11.16b, v8.16b
        eor     v5.16b, v5.16b, v10.16b
        shl     v10.2d, v10.2d, #4
        eor     v4.16b, v4.16b, v11.16b
        shl     v11.2d, v11.2d, #4
        eor     v1.16b, v1.16b, v10.16b
        eor     v0.16b, v0.16b, v11.16b
        sub     x10, x10, #1
        b       .Ldec_sbox
.Ldec_loop:
        ld1     {v8.16b-v11.16b}, [x9], #64
        eor     v8.16b, v8.16b, v0.16b
        eor     v9.16b, v9.16b, v1.16b
        tbl     v0.16b, {v8.16b}, v12.16b
        ld1     {v8.16b}, [x9], #16
        eor     v10.16b, v10.16b, v2.16b
        tbl     v1.16b, {v9.16b}, v12.16b
        ld1     {v9.16b}, [x9], #16
        eor     v11.16b, v11.16b, v3.16b
        tbl     v2.16b, {v10.16b}, v12.16b
        ld1     {v10.16b}, [x9], #16
        tbl     v3.16b, {v11.16b}, v12.16b
        ld1     {v11.16b}, [x9], #16
        eor     v8.16b, v8.16b, v4.16b
        eor     v9.16b, v9.16b, v5.16b
        tbl     v4.16b, {v8.16b}, v12.16b
        eor     v10.16b, v10.16b, v6.16b
        tbl     v5.16b, {v9.16b}, v12.16b
        eor     v11.16b, v11.16b, v7.16b
        tbl     v6.16b, {v10.16b}, v12.16b
        tbl     v7.16b, {v11.16b}, v12.16b
.Ldec_sbox:
        eor     v1.16b, v1.16b, v4.16b
        eor     v3.16b, v3.16b, v4.16b

        eor     v4.16b, v4.16b, v7.16b
        eor     v1.16b, v1.16b, v6.16b
        eor     v2.16b, v2.16b, v7.16b
        eor     v6.16b, v6.16b, v4.16b

        eor     v0.16b, v0.16b, v1.16b
        eor     v2.16b, v2.16b, v5.16b
        eor     v7.16b, v7.16b, v6.16b
        eor     v3.16b, v3.16b, v0.16b
        eor     v5.16b, v5.16b, v0.16b
        eor     v1.16b, v1.16b, v3.16b
        eor     v11.16b, v3.16b, v0.16b
        eor     v10.16b, v7.16b, v4.16b
        eor     v9.16b, v1.16b, v6.16b
        eor     v13.16b, v4.16b, v0.16b
        mov     v8.16b, v10.16b
        eor     v12.16b, v5.16b, v2.16b

        orr     v10.16b, v10.16b, v9.16b
        eor     v15.16b, v11.16b, v8.16b
        and     v14.16b, v11.16b, v12.16b
        orr     v11.16b, v11.16b, v12.16b
        eor     v12.16b, v12.16b, v9.16b
        and     v8.16b, v8.16b, v9.16b
        eor     v9.16b, v6.16b, v2.16b
        and     v15.16b, v15.16b, v12.16b
        and     v13.16b, v13.16b, v9.16b
        eor     v9.16b, v3.16b, v7.16b
        eor     v12.16b, v1.16b, v5.16b
        eor     v11.16b, v11.16b, v13.16b
        eor     v10.16b, v10.16b, v13.16b
        and     v13.16b, v9.16b, v12.16b
        orr     v9.16b, v9.16b, v12.16b
        eor     v11.16b, v11.16b, v15.16b
        eor     v8.16b, v8.16b, v13.16b
        eor     v10.16b, v10.16b, v14.16b
        eor     v9.16b, v9.16b, v15.16b
        eor     v8.16b, v8.16b, v14.16b
        and     v12.16b, v4.16b, v6.16b
        eor     v9.16b, v9.16b, v14.16b
        and     v13.16b, v0.16b, v2.16b
        and     v14.16b, v7.16b, v1.16b
        orr     v15.16b, v3.16b, v5.16b
        eor     v11.16b, v11.16b, v12.16b
        eor     v9.16b, v9.16b, v14.16b
        eor     v8.16b, v8.16b, v15.16b
        eor     v10.16b, v10.16b, v13.16b

        // Inv_GF16  0,  1,  2,  3, s0, s1, s2, s3

        // new smaller inversion

        and     v14.16b, v11.16b, v9.16b
        mov     v12.16b, v8.16b

        eor     v13.16b, v10.16b, v14.16b
        eor     v15.16b, v8.16b, v14.16b
        eor     v14.16b, v8.16b, v14.16b    // v14.16b=v15.16b

        bsl     v13.16b, v9.16b, v8.16b
        bsl     v15.16b, v11.16b, v10.16b
        eor     v11.16b, v11.16b, v10.16b

        bsl     v12.16b, v13.16b, v14.16b
        bsl     v8.16b, v14.16b, v13.16b

        and     v14.16b, v12.16b, v15.16b
        eor     v9.16b, v9.16b, v8.16b

        eor     v14.16b, v14.16b, v11.16b
        eor     v12.16b, v5.16b, v2.16b
        eor     v8.16b, v1.16b, v6.16b
        eor     v10.16b, v15.16b, v14.16b
        and     v10.16b, v10.16b, v5.16b
        eor     v5.16b, v5.16b, v1.16b
        and     v11.16b, v1.16b, v15.16b
        and     v5.16b, v5.16b, v14.16b
        eor     v1.16b, v11.16b, v10.16b
        eor     v5.16b, v5.16b, v11.16b
        eor     v15.16b, v15.16b, v13.16b
        eor     v14.16b, v14.16b, v9.16b
        eor     v11.16b, v15.16b, v14.16b
        eor     v10.16b, v13.16b, v9.16b
        and     v11.16b, v11.16b, v12.16b
        and     v10.16b, v10.16b, v2.16b
        eor     v12.16b, v12.16b, v8.16b
        eor     v2.16b, v2.16b, v6.16b
        and     v8.16b, v8.16b, v15.16b
        and     v6.16b, v6.16b, v13.16b
        and     v12.16b, v12.16b, v14.16b
        and     v2.16b, v2.16b, v9.16b
        eor     v8.16b, v8.16b, v12.16b
        eor     v2.16b, v2.16b, v6.16b
        eor     v12.16b, v12.16b, v11.16b
        eor     v6.16b, v6.16b, v10.16b
        eor     v5.16b, v5.16b, v12.16b
        eor     v2.16b, v2.16b, v12.16b
        eor     v1.16b, v1.16b, v8.16b
        eor     v6.16b, v6.16b, v8.16b

        eor     v12.16b, v3.16b, v0.16b
        eor     v8.16b, v7.16b, v4.16b
        eor     v11.16b, v15.16b, v14.16b
        eor     v10.16b, v13.16b, v9.16b
        and     v11.16b, v11.16b, v12.16b
        and     v10.16b, v10.16b, v0.16b
        eor     v12.16b, v12.16b, v8.16b
        eor     v0.16b, v0.16b, v4.16b
        and     v8.16b, v8.16b, v15.16b
        and     v4.16b, v4.16b, v13.16b
        and     v12.16b, v12.16b, v14.16b
        and     v0.16b, v0.16b, v9.16b
        eor     v8.16b, v8.16b, v12.16b
        eor     v0.16b, v0.16b, v4.16b
        eor     v12.16b, v12.16b, v11.16b
        eor     v4.16b, v4.16b, v10.16b
        eor     v15.16b, v15.16b, v13.16b
        eor     v14.16b, v14.16b, v9.16b
        eor     v10.16b, v15.16b, v14.16b
        and     v10.16b, v10.16b, v3.16b
        eor     v3.16b, v3.16b, v7.16b
        and     v11.16b, v7.16b, v15.16b
        and     v3.16b, v3.16b, v14.16b
        eor     v7.16b, v11.16b, v10.16b
        eor     v3.16b, v3.16b, v11.16b
        eor     v3.16b, v3.16b, v12.16b
        eor     v0.16b, v0.16b, v12.16b
        eor     v7.16b, v7.16b, v8.16b
        eor     v4.16b, v4.16b, v8.16b
        eor     v1.16b, v1.16b, v7.16b
        eor     v6.16b, v6.16b, v5.16b

        eor     v4.16b, v4.16b, v1.16b
        eor     v2.16b, v2.16b, v7.16b
        eor     v5.16b, v5.16b, v7.16b
        eor     v4.16b, v4.16b, v2.16b
        eor     v7.16b, v7.16b, v0.16b
        eor     v4.16b, v4.16b, v5.16b
        eor     v3.16b, v3.16b, v6.16b
        eor     v6.16b, v6.16b, v1.16b
        eor     v3.16b, v3.16b, v4.16b

        eor     v4.16b, v4.16b, v0.16b
        eor     v7.16b, v7.16b, v3.16b
        subs    x10, x10, #1
        bcc     .Ldec_done
        // multiplication by 0x05-0x00-0x04-0x00
        ext     v8.16b, v0.16b, v0.16b, #8
        ext     v14.16b, v3.16b, v3.16b, #8
        ext     v15.16b, v5.16b, v5.16b, #8
        eor     v8.16b, v8.16b, v0.16b
        ext     v9.16b, v1.16b, v1.16b, #8
        eor     v14.16b, v14.16b, v3.16b
        ext     v10.16b, v6.16b, v6.16b, #8
        eor     v15.16b, v15.16b, v5.16b
        ext     v11.16b, v4.16b, v4.16b, #8
        eor     v9.16b, v9.16b, v1.16b
        ext     v12.16b, v2.16b, v2.16b, #8
        eor     v10.16b, v10.16b, v6.16b
        ext     v13.16b, v7.16b, v7.16b, #8
        eor     v11.16b, v11.16b, v4.16b
        eor     v12.16b, v12.16b, v2.16b
        eor     v13.16b, v13.16b, v7.16b

        eor     v0.16b, v0.16b, v14.16b
        eor     v1.16b, v1.16b, v14.16b
        eor     v6.16b, v6.16b, v8.16b
        eor     v2.16b, v2.16b, v10.16b
        eor     v4.16b, v4.16b, v9.16b
        eor     v1.16b, v1.16b, v15.16b
        eor     v6.16b, v6.16b, v15.16b
        eor     v2.16b, v2.16b, v14.16b
        eor     v7.16b, v7.16b, v11.16b
        eor     v4.16b, v4.16b, v14.16b
        eor     v3.16b, v3.16b, v12.16b
        eor     v2.16b, v2.16b, v15.16b
        eor     v7.16b, v7.16b, v15.16b
        eor     v5.16b, v5.16b, v13.16b
        ext     v8.16b, v0.16b, v0.16b, #12 // x0 <<< 32
        ext     v9.16b, v1.16b, v1.16b, #12
        eor     v0.16b, v0.16b, v8.16b      // x0 ^ (x0 <<< 32)
        ext     v10.16b, v6.16b, v6.16b, #12
        eor     v1.16b, v1.16b, v9.16b
        ext     v11.16b, v4.16b, v4.16b, #12
        eor     v6.16b, v6.16b, v10.16b
        ext     v12.16b, v2.16b, v2.16b, #12
        eor     v4.16b, v4.16b, v11.16b
        ext     v13.16b, v7.16b, v7.16b, #12
        eor     v2.16b, v2.16b, v12.16b
        ext     v14.16b, v3.16b, v3.16b, #12
        eor     v7.16b, v7.16b, v13.16b
        ext     v15.16b, v5.16b, v5.16b, #12
        eor     v3.16b, v3.16b, v14.16b

        eor     v9.16b, v9.16b, v0.16b
        eor     v5.16b, v5.16b, v15.16b
        ext     v0.16b, v0.16b, v0.16b, #8      // (x0 ^ (x0 <<< 32)) <<< 64)
        eor     v10.16b, v10.16b, v1.16b
        eor     v8.16b, v8.16b, v5.16b
        eor     v9.16b, v9.16b, v5.16b
        ext     v1.16b, v1.16b, v1.16b, #8
        eor     v13.16b, v13.16b, v2.16b
        eor     v0.16b, v0.16b, v8.16b
        eor     v14.16b, v14.16b, v7.16b
        eor     v1.16b, v1.16b, v9.16b
        ext     v8.16b, v2.16b, v2.16b, #8
        eor     v12.16b, v12.16b, v4.16b
        ext     v9.16b, v7.16b, v7.16b, #8
        eor     v15.16b, v15.16b, v3.16b
        ext     v2.16b, v4.16b, v4.16b, #8
        eor     v11.16b, v11.16b, v6.16b
        ext     v7.16b, v5.16b, v5.16b, #8
        eor     v12.16b, v12.16b, v5.16b
        ext     v4.16b, v3.16b, v3.16b, #8
        eor     v11.16b, v11.16b, v5.16b
        ext     v3.16b, v6.16b, v6.16b, #8
        eor     v5.16b, v9.16b, v13.16b
        eor     v11.16b, v11.16b, v2.16b
        eor     v7.16b, v7.16b, v15.16b
        eor     v6.16b, v4.16b, v14.16b
        eor     v4.16b, v8.16b, v12.16b
        eor     v2.16b, v3.16b, v10.16b
        mov     v3.16b, v11.16b
        // mov     v5.16b, v9.16b
        ld1     {v12.16b}, [x11]            // load from .LISR in common case (x10 > 0)
        bne     .Ldec_loop
        add     x11, x11, #0x10
        ld1     {v12.16b}, [x11]            // load from .LISRM0 on last round (x10 == 0)
        b       .Ldec_loop
.Ldec_done:
        movi    v8.16b, #0x55               // compose .LBS0
        movi    v9.16b, #0x33               // compose .LBS1
        ushr    v10.2d, v3.2d, #1
        ushr    v11.2d, v2.2d, #1
        eor     v10.16b, v10.16b, v5.16b
        eor     v11.16b, v11.16b, v7.16b
        and     v10.16b, v10.16b, v8.16b
        and     v11.16b, v11.16b, v8.16b
        eor     v5.16b, v5.16b, v10.16b
        shl     v10.2d, v10.2d, #1
        eor     v7.16b, v7.16b, v11.16b
        shl     v11.2d, v11.2d, #1
        eor     v3.16b, v3.16b, v10.16b
        eor     v2.16b, v2.16b, v11.16b
        ushr    v10.2d, v6.2d, #1
        ushr    v11.2d, v0.2d, #1
        eor     v10.16b, v10.16b, v4.16b
        eor     v11.16b, v11.16b, v1.16b
        and     v10.16b, v10.16b, v8.16b
        and     v11.16b, v11.16b, v8.16b
        eor     v4.16b, v4.16b, v10.16b
        shl     v10.2d, v10.2d, #1
        eor     v1.16b, v1.16b, v11.16b
        shl     v11.2d, v11.2d, #1
        eor     v6.16b, v6.16b, v10.16b
        eor     v0.16b, v0.16b, v11.16b
        movi    v8.16b, #0x0f               // compose .LBS2
        ushr    v10.2d, v7.2d, #2
        ushr    v11.2d, v2.2d, #2
        eor     v10.16b, v10.16b, v5.16b
        eor     v11.16b, v11.16b, v3.16b
        and     v10.16b, v10.16b, v9.16b
        and     v11.16b, v11.16b, v9.16b
        eor     v5.16b, v5.16b, v10.16b
        shl     v10.2d, v10.2d, #2
        eor     v3.16b, v3.16b, v11.16b
        shl     v11.2d, v11.2d, #2
        eor     v7.16b, v7.16b, v10.16b
        eor     v2.16b, v2.16b, v11.16b
        ushr    v10.2d, v1.2d, #2
        ushr    v11.2d, v0.2d, #2
        eor     v10.16b, v10.16b, v4.16b
        eor     v11.16b, v11.16b, v6.16b
        and     v10.16b, v10.16b, v9.16b
        and     v11.16b, v11.16b, v9.16b
        eor     v4.16b, v4.16b, v10.16b
        shl     v10.2d, v10.2d, #2
        eor     v6.16b, v6.16b, v11.16b
        shl     v11.2d, v11.2d, #2
        eor     v1.16b, v1.16b, v10.16b
        eor     v0.16b, v0.16b, v11.16b
        ushr    v10.2d, v4.2d, #4
        ushr    v11.2d, v6.2d, #4
        eor     v10.16b, v10.16b, v5.16b
        eor     v11.16b, v11.16b, v3.16b
        and     v10.16b, v10.16b, v8.16b
        and     v11.16b, v11.16b, v8.16b
        eor     v5.16b, v5.16b, v10.16b
        shl     v10.2d, v10.2d, #4
        eor     v3.16b, v3.16b, v11.16b
        shl     v11.2d, v11.2d, #4
        eor     v4.16b, v4.16b, v10.16b
        eor     v6.16b, v6.16b, v11.16b
        ushr    v10.2d, v1.2d, #4
        ushr    v11.2d, v0.2d, #4
        eor     v10.16b, v10.16b, v7.16b
        eor     v11.16b, v11.16b, v2.16b
        and     v10.16b, v10.16b, v8.16b
        and     v11.16b, v11.16b, v8.16b
        eor     v7.16b, v7.16b, v10.16b
        shl     v10.2d, v10.2d, #4
        eor     v2.16b, v2.16b, v11.16b
        shl     v11.2d, v11.2d, #4
        eor     v1.16b, v1.16b, v10.16b
        eor     v0.16b, v0.16b, v11.16b
        ld1     {v8.16b}, [x9]              // last round key
        eor     v6.16b, v6.16b, v8.16b
        eor     v4.16b, v4.16b, v8.16b
        eor     v2.16b, v2.16b, v8.16b
        eor     v7.16b, v7.16b, v8.16b
        eor     v3.16b, v3.16b, v8.16b
        eor     v5.16b, v5.16b, v8.16b
        eor     v0.16b, v0.16b, v8.16b
        eor     v1.16b, v1.16b, v8.16b
        ret
.size   _bsaes_decrypt8,.-_bsaes_decrypt8

.type   _bsaes_const,%object
.align  6
_bsaes_const:
// InvShiftRows constants
// Used in _bsaes_decrypt8, which assumes contiguity
// .LM0ISR used with round 0 key
// .LISR   used with middle round keys
// .LISRM0 used with final round key
.LM0ISR:
.quad   0x0a0e0206070b0f03, 0x0004080c0d010509
.LISR:
.quad   0x0504070602010003, 0x0f0e0d0c080b0a09
.LISRM0:
.quad   0x01040b0e0205080f, 0x0306090c00070a0d

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
//   x17 -> output key (native endianness)
// On exit:
//   x9, x10 corrupted
//   x11 -> .LM0_bigendian
//   x17 -> last quadword of output key
//   other general-purpose registers preserved
//   v2-v6 preserved
//   v7.16b[] = 0x63
//   v8-v14 preserved
//   v15 = last round key (converted to native endianness)
//   other SIMD registers corrupted
_bsaes_key_convert:
#ifdef __ARMEL__
        adr     x11, .LM0_littleendian
#else
        adr     x11, .LM0_bigendian
#endif
        ld1     {v0.16b}, [x9], #16         // load round 0 key
        ld1     {v1.16b}, [x11]             // .LM0
        ld1     {v15.16b}, [x9], #16        // load round 1 key

        movi    v7.16b, #0x63               // compose .L63
        movi    v16.16b, #0x01              // bit masks
        movi    v17.16b, #0x02
        movi    v18.16b, #0x04
        movi    v19.16b, #0x08
        movi    v20.16b, #0x10
        movi    v21.16b, #0x20
        movi    v22.16b, #0x40
        movi    v23.16b, #0x80

#ifdef __ARMEL__
        rev32   v0.16b, v0.16b
#endif
        sub     x10, x10, #1
        st1     {v0.16b}, [x17], #16        // save round 0 key

.Lkey_loop:
        tbl     v0.16b, {v15.16b}, v1.16b
        ld1     {v15.16b}, [x9], #16        // load next round key

        eor     v0.16b, v0.16b, v7.16b
        cmtst   v24.16b, v0.16b, v16.16b
        cmtst   v25.16b, v0.16b, v17.16b
        cmtst   v26.16b, v0.16b, v18.16b
        cmtst   v27.16b, v0.16b, v19.16b
        cmtst   v28.16b, v0.16b, v20.16b
        cmtst   v29.16b, v0.16b, v21.16b
        cmtst   v30.16b, v0.16b, v22.16b
        cmtst   v31.16b, v0.16b, v23.16b
        sub     x10, x10, #1
        st1     {v24.16b-v27.16b}, [x17], #64 // write bit-sliced round key
        st1     {v28.16b-v31.16b}, [x17], #64
        cbnz    x10, .Lkey_loop

        // don't save last round key
#ifdef __ARMEL__
        rev32   v15.16b, v15.16b
        adr     x11, .LM0_bigendian
#endif
        ret
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
