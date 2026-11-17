/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/linkage.h>
#include <asm/asm.h>

/* void __asm_vector_memcpy(void *dst, const void *src, size_t len) */
SYM_FUNC_START(__asm_vector_memcpy)
1:
	vsetvli	t0, a2, e8, m8, ta, ma
	vle8.v	v0, (a1)
	sub	a2, a2, t0
	add	a1, a1, t0
	vse8.v	v0, (a0)
	add	a0, a0, t0
	bnez	a2, 1b
	ret
SYM_FUNC_END(__asm_vector_memcpy)
