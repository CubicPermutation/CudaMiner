/* $Id: keccak.c 259 2011-07-19 22:11:27Z tp $ */
/*
 * Keccak implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>

#include "cuda_sph_keccak.h"

/*
 * Parameters:
 *
 *  SPH_KECCAK_64          use a 64-bit type
 *  SPH_KECCAK_UNROLL      number of loops to unroll (0/undef for full unroll)
 *  SPH_KECCAK_INTERLEAVE  use bit-interleaving (32-bit type only)
 *  SPH_KECCAK_NOCOPY      do not copy the state into local variables
 * 
 * If there is no usable 64-bit type, the code automatically switches
 * back to the 32-bit implementation.
 *
 * Some tests on an Intel Core2 Q6600 (both 64-bit and 32-bit, 32 kB L1
 * code cache), a PowerPC (G3, 32 kB L1 code cache), an ARM920T core
 * (16 kB L1 code cache), and a small MIPS-compatible CPU (Broadcom BCM3302,
 * 8 kB L1 code cache), seem to show that the following are optimal:
 *
 * -- x86, 64-bit: use the 64-bit implementation, unroll 8 rounds,
 * do not copy the state; unrolling 2, 6 or all rounds also provides
 * near-optimal performance.
 * -- x86, 32-bit: use the 32-bit implementation, unroll 6 rounds,
 * interleave, do not copy the state. Unrolling 1, 2, 4 or 8 rounds
 * also provides near-optimal performance.
 * -- PowerPC: use the 64-bit implementation, unroll 8 rounds,
 * copy the state. Unrolling 4 or 6 rounds is near-optimal.
 * -- ARM: use the 64-bit implementation, unroll 2 or 4 rounds,
 * copy the state.
 * -- MIPS: use the 64-bit implementation, unroll 2 rounds, copy
 * the state. Unrolling only 1 round is also near-optimal.
 *
 * Also, interleaving does not always yield actual improvements when
 * using a 32-bit implementation; in particular when the architecture
 * does not offer a native rotation opcode (interleaving replaces one
 * 64-bit rotation with two 32-bit rotations, which is a gain only if
 * there is a native 32-bit rotation opcode and not a native 64-bit
 * rotation opcode; also, interleaving implies a small overhead when
 * processing input words).
 *
 * To sum up:
 * -- when possible, use the 64-bit code
 * -- exception: on 32-bit x86, use 32-bit code
 * -- when using 32-bit code, use interleaving
 * -- copy the state, except on x86
 * -- unroll 8 rounds on "big" machine, 2 rounds on "small" machines
 */

#define AND64(d, a, b)   (d = a & b)
#define OR64(d, a, b)    (d = a | b)
#define NOT64(d, s)      (d = SPH_T64(~s))

#define P0    a00, a01, a02, a03, a04, a10, a11, a12, a13, a14, a20, a21, \
        a22, a23, a24, a30, a31, a32, a33, a34, a40, a41, a42, a43, a44
#define P1    a00, a30, a10, a40, a20, a11, a41, a21, a01, a31, a22, a02, \
              a32, a12, a42, a33, a13, a43, a23, a03, a44, a24, a04, a34, a14
#define P2    a00, a33, a11, a44, a22, a41, a24, a02, a30, a13, a32, a10, \
              a43, a21, a04, a23, a01, a34, a12, a40, a14, a42, a20, a03, a31
#define P3    a00, a23, a41, a14, a32, a24, a42, a10, a33, a01, a43, a11, \
              a34, a02, a20, a12, a30, a03, a21, a44, a31, a04, a22, a40, a13
#define P4    a00, a12, a24, a31, a43, a42, a04, a11, a23, a30, a34, a41, \
              a03, a10, a22, a21, a33, a40, a02, a14, a13, a20, a32, a44, a01
#define P5    a00, a21, a42, a13, a34, a04, a20, a41, a12, a33, a03, a24, \
              a40, a11, a32, a02, a23, a44, a10, a31, a01, a22, a43, a14, a30
#define P6    a00, a02, a04, a01, a03, a20, a22, a24, a21, a23, a40, a42, \
              a44, a41, a43, a10, a12, a14, a11, a13, a30, a32, a34, a31, a33
#define P7    a00, a10, a20, a30, a40, a22, a32, a42, a02, a12, a44, a04, \
              a14, a24, a34, a11, a21, a31, a41, a01, a33, a43, a03, a13, a23
#define P8    a00, a11, a22, a33, a44, a32, a43, a04, a10, a21, a14, a20, \
              a31, a42, a03, a41, a02, a13, a24, a30, a23, a34, a40, a01, a12
#define P9    a00, a41, a32, a23, a14, a43, a34, a20, a11, a02, a31, a22, \
              a13, a04, a40, a24, a10, a01, a42, a33, a12, a03, a44, a30, a21
#define P10   a00, a24, a43, a12, a31, a34, a03, a22, a41, a10, a13, a32, \
              a01, a20, a44, a42, a11, a30, a04, a23, a21, a40, a14, a33, a02
#define P11   a00, a42, a34, a21, a13, a03, a40, a32, a24, a11, a01, a43, \
              a30, a22, a14, a04, a41, a33, a20, a12, a02, a44, a31, a23, a10
#define P12   a00, a04, a03, a02, a01, a40, a44, a43, a42, a41, a30, a34, \
              a33, a32, a31, a20, a24, a23, a22, a21, a10, a14, a13, a12, a11
#define P13   a00, a20, a40, a10, a30, a44, a14, a34, a04, a24, a33, a03, \
              a23, a43, a13, a22, a42, a12, a32, a02, a11, a31, a01, a21, a41
#define P14   a00, a22, a44, a11, a33, a14, a31, a03, a20, a42, a23, a40, \
              a12, a34, a01, a32, a04, a21, a43, a10, a41, a13, a30, a02, a24
#define P15   a00, a32, a14, a41, a23, a31, a13, a40, a22, a04, a12, a44, \
              a21, a03, a30, a43, a20, a02, a34, a11, a24, a01, a33, a10, a42
#define P16   a00, a43, a31, a24, a12, a13, a01, a44, a32, a20, a21, a14, \
              a02, a40, a33, a34, a22, a10, a03, a41, a42, a30, a23, a11, a04
#define P17   a00, a34, a13, a42, a21, a01, a30, a14, a43, a22, a02, a31, \
              a10, a44, a23, a03, a32, a11, a40, a24, a04, a33, a12, a41, a20
#define P18   a00, a03, a01, a04, a02, a30, a33, a31, a34, a32, a10, a13, \
              a11, a14, a12, a40, a43, a41, a44, a42, a20, a23, a21, a24, a22
#define P19   a00, a40, a30, a20, a10, a33, a23, a13, a03, a43, a11, a01, \
              a41, a31, a21, a44, a34, a24, a14, a04, a22, a12, a02, a42, a32
#define P20   a00, a44, a33, a22, a11, a23, a12, a01, a40, a34, a41, a30, \
              a24, a13, a02, a14, a03, a42, a31, a20, a32, a21, a10, a04, a43
#define P21   a00, a14, a23, a32, a41, a12, a21, a30, a44, a03, a24, a33, \
              a42, a01, a10, a31, a40, a04, a13, a22, a43, a02, a11, a20, a34
#define P22   a00, a31, a12, a43, a24, a21, a02, a33, a14, a40, a42, a23, \
              a04, a30, a11, a13, a44, a20, a01, a32, a34, a10, a41, a22, a03
#define P23   a00, a13, a21, a34, a42, a02, a10, a23, a31, a44, a04, a12, \
              a20, a33, a41, a01, a14, a22, a30, a43, a03, a11, a24, a32, a40

/*
 * The KHI macro integrates the "lane complement" optimization. On input,
 * some words are complemented:
 *    a00 a01 a02 a04 a13 a20 a21 a22 a30 a33 a34 a43
 * On output, the following words are complemented:
 *    a04 a10 a20 a22 a23 a31
 *
 * The (implicit) permutation and the theta expansion will bring back
 * the input mask for the next round.
 */

#define KHI_XO(d, a, b, c)   do { \
		DECL64(kt); \
		OR64(kt, b, c); \
		XOR64(d, a, kt); \
	} while (0)

#define KHI_XA(d, a, b, c)   do { \
		DECL64(kt); \
		AND64(kt, b, c); \
		XOR64(d, a, kt); \
	} while (0)

#define LPAR   (
#define RPAR   )

void keccak_init(sph_keccak_context *kc, unsigned out_size) {
	int i;

	for (i = 0; i < 25; i ++)
		kc->wide[i] = 0;
	/*
	 * Initialization for the "lane complement".
	 */
	kc->wide[ 1] = (0xFFFFFFFFFFFFFFFFULL);
	kc->wide[ 2] = (0xFFFFFFFFFFFFFFFFULL);
	kc->wide[ 8] = (0xFFFFFFFFFFFFFFFFULL);
	kc->wide[12] = (0xFFFFFFFFFFFFFFFFULL);
	kc->wide[17] = (0xFFFFFFFFFFFFFFFFULL);
	kc->wide[20] = (0xFFFFFFFFFFFFFFFFULL);

	kc->ptr = 0;
	kc->lim = 200 - (out_size >> 2);
}

#define a00   (kc->wide[ 0])
#define a10   (kc->wide[ 1])
#define a20   (kc->wide[ 2])
#define a30   (kc->wide[ 3])
#define a40   (kc->wide[ 4])
#define a01   (kc->wide[ 5])
#define a11   (kc->wide[ 6])
#define a21   (kc->wide[ 7])
#define a31   (kc->wide[ 8])
#define a41   (kc->wide[ 9])
#define a02   (kc->wide[10])
#define a12   (kc->wide[11])
#define a22   (kc->wide[12])
#define a32   (kc->wide[13])
#define a42   (kc->wide[14])
#define a03   (kc->wide[15])
#define a13   (kc->wide[16])
#define a23   (kc->wide[17])
#define a33   (kc->wide[18])
#define a43   (kc->wide[19])
#define a04   (kc->wide[20])
#define a14   (kc->wide[21])
#define a24   (kc->wide[22])
#define a34   (kc->wide[23])
#define a44   (kc->wide[24])

#define KHI(b00, b01, b02, b03, b04, b10, b11, b12, b13, b14, \
	b20, b21, b22, b23, b24, b30, b31, b32, b33, b34, \
	b40, b41, b42, b43, b44) \
	do { \
		DECL64(c0); \
		DECL64(c1); \
		DECL64(c2); \
		DECL64(c3); \
		DECL64(c4); \
		DECL64(bnn); \
		NOT64(bnn, b20); \
		KHI_XO(c0, b00, b10, b20); \
		KHI_XO(c1, b10, bnn, b30); \
		KHI_XA(c2, b20, b30, b40); \
		KHI_XO(c3, b30, b40, b00); \
		KHI_XA(c4, b40, b00, b10); \
		MOV64(b00, c0); \
		MOV64(b10, c1); \
		MOV64(b20, c2); \
		MOV64(b30, c3); \
		MOV64(b40, c4); \
		NOT64(bnn, b41); \
		KHI_XO(c0, b01, b11, b21); \
		KHI_XA(c1, b11, b21, b31); \
		KHI_XO(c2, b21, b31, bnn); \
		KHI_XO(c3, b31, b41, b01); \
		KHI_XA(c4, b41, b01, b11); \
		MOV64(b01, c0); \
		MOV64(b11, c1); \
		MOV64(b21, c2); \
		MOV64(b31, c3); \
		MOV64(b41, c4); \
		NOT64(bnn, b32); \
		KHI_XO(c0, b02, b12, b22); \
		KHI_XA(c1, b12, b22, b32); \
		KHI_XA(c2, b22, bnn, b42); \
		KHI_XO(c3, bnn, b42, b02); \
		KHI_XA(c4, b42, b02, b12); \
		MOV64(b02, c0); \
		MOV64(b12, c1); \
		MOV64(b22, c2); \
		MOV64(b32, c3); \
		MOV64(b42, c4); \
		NOT64(bnn, b33); \
		KHI_XA(c0, b03, b13, b23); \
		KHI_XO(c1, b13, b23, b33); \
		KHI_XO(c2, b23, bnn, b43); \
		KHI_XA(c3, bnn, b43, b03); \
		KHI_XO(c4, b43, b03, b13); \
		MOV64(b03, c0); \
		MOV64(b13, c1); \
		MOV64(b23, c2); \
		MOV64(b33, c3); \
		MOV64(b43, c4); \
		NOT64(bnn, b14); \
		KHI_XA(c0, b04, bnn, b24); \
		KHI_XO(c1, bnn, b24, b34); \
		KHI_XA(c2, b24, b34, b44); \
		KHI_XO(c3, b34, b44, b04); \
		KHI_XA(c4, b44, b04, b14); \
		MOV64(b04, c0); \
		MOV64(b14, c1); \
		MOV64(b24, c2); \
		MOV64(b34, c3); \
		MOV64(b44, c4); \
	} while (0)

static const uint_64 RC[] = {
	0x0000000000000001ULL, 0x0000000000008082ULL,
	0x800000000000808AULL, 0x8000000080008000ULL,
	0x000000000000808BULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008AULL, 0x0000000000000088ULL,
	0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL,
	0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800AULL, 0x800000008000000AULL,
	0x8000000080008081ULL, 0x8000000000008080ULL,
	0x0000000080000001ULL, 0x8000000080008008ULL
};

#define RHO(b00, b01, b02, b03, b04, b10, b11, b12, b13, b14, \
	b20, b21, b22, b23, b24, b30, b31, b32, b33, b34, \
	b40, b41, b42, b43, b44) \
	do { \
		/* ROL64(b00, b00,  0); */ \
		ROL64(b01, b01, 36); \
		ROL64(b02, b02,  3); \
		ROL64(b03, b03, 41); \
		ROL64(b04, b04, 18); \
		ROL64(b10, b10,  1); \
		ROL64(b11, b11, 44); \
		ROL64(b12, b12, 10); \
		ROL64(b13, b13, 45); \
		ROL64(b14, b14,  2); \
		ROL64(b20, b20, 62); \
		ROL64(b21, b21,  6); \
		ROL64(b22, b22, 43); \
		ROL64(b23, b23, 15); \
		ROL64(b24, b24, 61); \
		ROL64(b30, b30, 28); \
		ROL64(b31, b31, 55); \
		ROL64(b32, b32, 25); \
		ROL64(b33, b33, 21); \
		ROL64(b34, b34, 56); \
		ROL64(b40, b40, 27); \
		ROL64(b41, b41, 20); \
		ROL64(b42, b42, 39); \
		ROL64(b43, b43,  8); \
		ROL64(b44, b44, 14); \
	} while (0)

#define THETA(b00, b01, b02, b03, b04, b10, b11, b12, b13, b14, \
	b20, b21, b22, b23, b24, b30, b31, b32, b33, b34, \
	b40, b41, b42, b43, b44) \
	do { \
		DECL64(t0); \
		DECL64(t1); \
		DECL64(t2); \
		DECL64(t3); \
		DECL64(t4); \
		TH_ELT(t0, b40, b41, b42, b43, b44, b10, b11, b12, b13, b14); \
		TH_ELT(t1, b00, b01, b02, b03, b04, b20, b21, b22, b23, b24); \
		TH_ELT(t2, b10, b11, b12, b13, b14, b30, b31, b32, b33, b34); \
		TH_ELT(t3, b20, b21, b22, b23, b24, b40, b41, b42, b43, b44); \
		TH_ELT(t4, b30, b31, b32, b33, b34, b00, b01, b02, b03, b04); \
		XOR64(b00, b00, t0); \
		XOR64(b01, b01, t0); \
		XOR64(b02, b02, t0); \
		XOR64(b03, b03, t0); \
		XOR64(b04, b04, t0); \
		XOR64(b10, b10, t1); \
		XOR64(b11, b11, t1); \
		XOR64(b12, b12, t1); \
		XOR64(b13, b13, t1); \
		XOR64(b14, b14, t1); \
		XOR64(b20, b20, t2); \
		XOR64(b21, b21, t2); \
		XOR64(b22, b22, t2); \
		XOR64(b23, b23, t2); \
		XOR64(b24, b24, t2); \
		XOR64(b30, b30, t3); \
		XOR64(b31, b31, t3); \
		XOR64(b32, b32, t3); \
		XOR64(b33, b33, t3); \
		XOR64(b34, b34, t3); \
		XOR64(b40, b40, t4); \
		XOR64(b41, b41, t4); \
		XOR64(b42, b42, t4); \
		XOR64(b43, b43, t4); \
		XOR64(b44, b44, t4); \
	} while (0)

#define DECL64(x)        uint_64 x

#define SPH_C64(x)    ((uint_64)(x ## ULL))

#define SPH_T64(x)    ((x) & SPH_C64(0xFFFFFFFFFFFFFFFF))

#define SPH_ROTL64(x, n)   SPH_T64(((x) << (n)) | ((x) >> (64 - (n))))

#define ROL64(d, v, n)   (d = SPH_ROTL64(v, n))

#define TH_ELT(t, c0, c1, c2, c3, c4, d0, d1, d2, d3, d4)   do { \
		DECL64(tt0); \
		DECL64(tt1); \
		DECL64(tt2); \
		DECL64(tt3); \
		XOR64(tt0, d0, d1); \
		XOR64(tt1, d2, d3); \
		XOR64(tt0, tt0, d4); \
		XOR64(tt0, tt0, tt1); \
		ROL64(tt0, tt0, 1); \
		XOR64(tt2, c0, c1); \
		XOR64(tt3, c2, c3); \
		XOR64(tt0, tt0, c4); \
		XOR64(tt2, tt2, tt3); \
		XOR64(t, tt0, tt2); \
	} while (0)

#define IOTA(r)   XOR64_IOTA(a00, a00, r)
#define XOR64_IOTA       XOR64
#define XOR64(d, a, b)   (d = a ^ b)

#define KF_ELT(r, s, k)   do { \
		THETA LPAR P ## r RPAR; \
		RHO LPAR P ## r RPAR; \
		KHI LPAR P ## s RPAR; \
		IOTA(k); \
	} while (0)

#define MOV64(d, s)      (d = s)

#define P8_TO_P0   do { \
		DECL64(t); \
		MOV64(t, a01); \
		MOV64(a01, a11); \
		MOV64(a11, a43); \
		MOV64(a43, t); \
		MOV64(t, a02); \
		MOV64(a02, a22); \
		MOV64(a22, a31); \
		MOV64(a31, t); \
		MOV64(t, a03); \
		MOV64(a03, a33); \
		MOV64(a33, a24); \
		MOV64(a24, t); \
		MOV64(t, a04); \
		MOV64(a04, a44); \
		MOV64(a44, a12); \
		MOV64(a12, t); \
		MOV64(t, a10); \
		MOV64(a10, a32); \
		MOV64(a32, a13); \
		MOV64(a13, t); \
		MOV64(t, a14); \
		MOV64(a14, a21); \
		MOV64(a21, a20); \
		MOV64(a20, t); \
		MOV64(t, a23); \
		MOV64(a23, a42); \
		MOV64(a42, a40); \
		MOV64(a40, t); \
		MOV64(t, a30); \
		MOV64(a30, a41); \
		MOV64(a41, a34); \
		MOV64(a34, t); \
	} while (0)

#define KECCAK_F_1600_   do { \
		int j; \
		for (j = 0; j < 24; j += 8) { \
			KF_ELT( 0,  1, RC[j + 0]); \
			KF_ELT( 1,  2, RC[j + 1]); \
			KF_ELT( 2,  3, RC[j + 2]); \
			KF_ELT( 3,  4, RC[j + 3]); \
			KF_ELT( 4,  5, RC[j + 4]); \
			KF_ELT( 5,  6, RC[j + 5]); \
			KF_ELT( 6,  7, RC[j + 6]); \
			KF_ELT( 7,  8, RC[j + 7]); \
			P8_TO_P0; \
		} \
	} while (0)

#define DO(x)   x

#define KECCAK_F_1600   DO(KECCAK_F_1600_)

void keccak_core(sph_keccak_context *kc, uchar_8 *data, size_t len, size_t lim) {
	uchar_8 *buf;
	size_t ptr;

	buf = kc->buf;
	ptr = kc->ptr;

	if (len < (lim - ptr)) {
		for (int i=0; i<len; i++) {
			(buf + ptr)[i] = data[i];
		}
		kc->ptr = ptr + len;
		return;
	}

	while (len > 0) {
		size_t clen;

		clen = (lim - ptr);
		if (clen > len) {
			clen = len;
		}
		for (int i=0; i<clen; i++) {
			(buf + ptr)[i] = data[i];
		}
		ptr += clen;
		data = (uchar_8*)data + clen;
		len -= clen;
		if (ptr == lim) {
			{
				size_t j; \
				for (j = 0; j < (lim); j += 8) {
					kc->wide[j >> 3] ^= *(const uint_64 *)(buf + j);
				}
			}
			KECCAK_F_1600;
			ptr = 0;
		}
	}
	kc->ptr = ptr;
}

void keccak_close(sph_keccak_context *kc, unsigned ub, unsigned n, uchar_8 *dst) {
	unsigned eb;
	union {
		uchar_8 tmp[72 + 1];
		uint_64 dummy;   /* for alignment */
	} u;
	size_t j;

	eb = (0x100 | (ub & 0xFF)) >> (8 - n);
	if (kc->ptr == (72 - 1)) {
		if (n == 7) {
			u.tmp[0] = eb;
			for (int i=0; i<72 - 1; i++) {
				(u.tmp+1)[i] = 0;
			}
			u.tmp[72] = 0x80;
			j = 1 + 72;
		} else {
			u.tmp[0] = eb | 0x80;
			j = 1;
		}
	} else {
		j = 72 - kc->ptr;
		u.tmp[0] = eb;
		for (int i=0; i<j - 2; i++) {
			(u.tmp+1)[i] = 0;
		}
		u.tmp[j - 1] = 0x80;
	}
	keccak_core(kc, u.tmp, j, 72);
	/* Finalize the "lane complement" */
	kc->wide[ 1] = ~kc->wide[ 1];
	kc->wide[ 2] = ~kc->wide[ 2];
	kc->wide[ 8] = ~kc->wide[ 8];
	kc->wide[12] = ~kc->wide[12];
	kc->wide[17] = ~kc->wide[17];
	kc->wide[20] = ~kc->wide[20];
	for (j = 0; j < 64; j += 8) {
		*(uint_64*)(u.tmp + j) = kc->wide[j >> 3];
	}
	for (int i=0; i<64; i++) {
		dst[i] = u.tmp[i];
	}
	keccak_init(kc, (unsigned)64 << 3);
}

void keccak512_80(uchar_8 *data, uchar_8 *hash) {
	sph_keccak_context ctx_keccak;
	keccak_init(&ctx_keccak, 512);
	keccak_core(&ctx_keccak, hash, 64, 72);
	keccak_close(&ctx_keccak, 0, 0, hash);
}


