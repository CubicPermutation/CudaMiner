/* $Id: sph_jh.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * JH interface. JH is a family of functions which differ by
 * their output size; this implementation defines JH for output
 * sizes 224, 256, 384 and 512 bits.
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
 * @file     sph_jh.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_JH_H__
#define SPH_JH_H__

#include <stddef.h>
#include "sph_types.h"
#include "types.h"


/**
 * This structure is a context for JH computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a JH computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running JH computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
	unsigned char buf[64];    /* first field, for alignment */
	size_t ptr;
	union {
		uint_64 wide[16];
		uint_32 narrow[32];
	} H;
	sph_u64 block_count;
} sph_jh_context;


/**
 * Initialize a JH-512 context. This process performs no memory allocation.
 *
 * @param cc   the JH-512 context (pointer to a
 *             <code>sph_jh512_context</code>)
 */
void sph_jh512_init(sph_jh_context *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the JH-512 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_jh512(sph_jh_context *cc, uchar_8 *data, size_t len);

/**
 * Terminate the current JH-512 computation and output the result into
 * the provided buffer. The destination buffer must be wide enough to
 * accomodate the result (64 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the JH-512 context
 * @param dst   the destination buffer
 */
void sph_jh512_close(sph_jh_context *cc, uchar_8 *dst);

/**
 * Add a few additional bits (0 to 7) to the current computation, then
 * terminate it and output the result in the provided buffer, which must
 * be wide enough to accomodate the result (64 bytes). If bit number i
 * in <code>ub</code> has value 2^i, then the extra bits are those
 * numbered 7 downto 8-n (this is the big-endian convention at the byte
 * level). The context is automatically reinitialized.
 *
 * @param cc    the JH-512 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the destination buffer
 */
void sph_jh512_addbits_and_close(
	void *cc, unsigned ub, unsigned n, void *dst);

#endif
