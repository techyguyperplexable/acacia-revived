// SPDX-License-Identifier: GPL-2.0
/*
 * copy_page dispatcher: NEON fast path with scalar fallback.
 *
 * When SIMD is available (process context, not in hardirq/softirq with
 * NEON already active), we use the NEON path which moves 256 bytes per
 * loop iteration using 128-bit register pairs with non-temporal stores.
 *
 * When SIMD is unavailable (hardirq, NMI, nested NEON), we fall back
 * to the scalar implementation using general-purpose registers.
 *
 * Copyright (C) 2025 techyguyperplexable
 */

#include <linux/export.h>
#include <linux/types.h>
#include <asm/neon.h>
#include <asm/simd.h>
#include <asm/page.h>

asmlinkage void copy_page_neon(void *to, const void *from);
asmlinkage void copy_page_scalar(void *to, const void *from);

void copy_page(void *to, const void *from)
{
	if (may_use_simd()) {
		kernel_neon_begin();
		copy_page_neon(to, from);
		kernel_neon_end();
	} else {
		copy_page_scalar(to, from);
	}
}
EXPORT_SYMBOL(copy_page);
