/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NEON-accelerated copy_page for AArch64.
 *
 * Copies 256 bytes per iteration using 128-bit NEON register pairs,
 * with non-temporal stores to avoid polluting the data cache.
 * Caller must have called kernel_neon_begin() before entry.
 *
 * Copyright (C) 2025 techyguyperplexable
 */

#include <linux/linkage.h>
#include <linux/const.h>
#include <asm/assembler.h>
#include <asm/page.h>

/*
 * NEON copy_page: copy a 4KB page from src to dest
 *
 * Parameters:
 *	x0 - dest (page-aligned)
 *	x1 - src  (page-aligned)
 *
 * Clobbers: x0, x1, x2, q0-q15
 */
ENTRY(copy_page_neon)
	mov	x2, #(PAGE_SIZE / 256)	// 16 iterations for 4KB
1:
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x1, #32]
	ldp	q4, q5, [x1, #64]
	ldp	q6, q7, [x1, #96]
	ldp	q8, q9, [x1, #128]
	ldp	q10, q11, [x1, #160]
	ldp	q12, q13, [x1, #192]
	ldp	q14, q15, [x1, #224]

	stnp	q0, q1, [x0]
	stnp	q2, q3, [x0, #32]
	stnp	q4, q5, [x0, #64]
	stnp	q6, q7, [x0, #96]
	stnp	q8, q9, [x0, #128]
	stnp	q10, q11, [x0, #160]
	stnp	q12, q13, [x0, #192]
	stnp	q14, q15, [x0, #224]

	add	x1, x1, #256
	add	x0, x0, #256
	subs	x2, x2, #1
	b.ne	1b

	ret
ENDPROC(copy_page_neon)
