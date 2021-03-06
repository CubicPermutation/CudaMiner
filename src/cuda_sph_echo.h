/* $Id: sph_echo.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * ECHO interface. ECHO is a family of functions which differ by
 * their output size; this implementation defines ECHO for output
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
 * @file     sph_echo.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

//#ifndef SPH_ECHO_H__
//#define SPH_ECHO_H__

#pragma once

#include <stddef.h>
#include "sph_types.h"
#include "types.h"


/**
 * This structure is a context for ECHO computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * an ECHO computation has been performed, the context can be reused for
 * another computation. This specific structure is used for ECHO-384
 * and ECHO-512.
 *
 * The contents of this structure are private. A running ECHO computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
	uchar_8 buf[128];    /* first field, for alignment */
	size_t ptr;
	union {
		uint_32 Vs[8][4];
		uint_64 Vb[8][2];
	} u;
	uint_32 C0, C1, C2, C3;
} sph_echo_big_context;

void echo512_80(uchar_8 *data, uchar_8 *hash);

