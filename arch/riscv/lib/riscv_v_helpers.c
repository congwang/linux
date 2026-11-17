// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 SiFive
 * Author: Andy Chiu <andy.chiu@sifive.com>
 */
#include <linux/linkage.h>
#include <linux/minmax.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include <asm/asm.h>
#include <asm/asm-prototypes.h>
#include <asm/simd.h>
#include <asm/vector.h>

/*
 * A vector section that is not preemptible keeps softirqs off, or preemption
 * on PREEMPT_RT. Bounds how long one copy does that.
 */
#define VECTOR_MEMCPY_SECTION	SZ_256K

/*
 * Giving up the user's vector state and bringing it back on the return to
 * user space costs about as much as the vector section itself.
 */
#define VECTOR_MEMCPY_USER_THRESHOLD	(2 * CONFIG_RISCV_ISA_V_MEMCPY_THRESHOLD)

static bool memcpy_overlaps(const void *p, size_t n, const void *area, size_t size)
{
	return area && p < area + size && area < p + n;
}

/*
 * kernel_vector_begin() and kernel_vector_end() write to the task struct,
 * to the user register frame on the task's stack and to the task's vector
 * save areas. A copy of those would read or overwrite that state while it
 * is in flux.
 */
static bool touches_vector_state(const void *p, size_t n)
{
	struct thread_struct *thread = &current->thread;

	return memcpy_overlaps(p, n, current, sizeof(*current)) ||
	       memcpy_overlaps(p, n, task_pt_regs(current), sizeof(struct pt_regs)) ||
	       memcpy_overlaps(p, n, thread->vstate.datap, riscv_v_vsize) ||
	       memcpy_overlaps(p, n, thread->kernel_vstate.datap, riscv_v_vsize);
}

/* The registers hold user state that a vector section has to save. */
static bool user_vstate_is_live(void)
{
	struct pt_regs *regs = task_pt_regs(current);

	return riscv_v_vstate_query(regs) &&
	       !__riscv_v_vstate_check(regs->status, INITIAL) &&
	       !test_thread_flag(TIF_RISCV_V_DEFER_RESTORE);
}

static bool memcpy_may_use_vector(const void *dst, const void *src, size_t n)
{
	/*
	 * Interrupts off is allowed for kernel-mode vector, but it is where
	 * entry code and lock debugging run, which must not end up here.
	 *
	 * Any vector flag means that the registers are spoken for: by a
	 * vector section, preemptible or not, that this copy runs inside
	 * or has interrupted, or by a KVM vcpu. Using them would mean
	 * saving theirs first.
	 */
	if (!may_use_simd() || irqs_disabled() || riscv_v_flags())
		return false;

	if (n < VECTOR_MEMCPY_USER_THRESHOLD && user_vstate_is_live())
		return false;

	return !touches_vector_state(dst, n) && !touches_vector_state(src, n);
}

/*
 * Reached from memcpy() for copies of RISCV_ISA_V_MEMCPY_THRESHOLD or more.
 * memcpy() cannot be traced, and the tracers that copy with it rely on that.
 */
asmlinkage notrace void *enter_vector_memcpy(void *dst, const void *src, size_t n)
{
	void *ret = dst;

	if (!memcpy_may_use_vector(dst, src, n))
		return __memcpy_scalar(dst, src, n);

	do {
		size_t len = min(n, VECTOR_MEMCPY_SECTION);

		kernel_vector_begin();
		__asm_vector_memcpy(dst, src, len);
		kernel_vector_end();

		dst += len;
		src += len;
		n -= len;
	} while (n);

	return ret;
}

#ifdef CONFIG_MMU
size_t riscv_v_usercopy_threshold = CONFIG_RISCV_ISA_V_UCOPY_THRESHOLD;
int __asm_vector_usercopy(void *dst, void *src, size_t n);
int __asm_vector_usercopy_sum_enabled(void *dst, void *src, size_t n);
int fallback_scalar_usercopy(void *dst, void *src, size_t n);
int fallback_scalar_usercopy_sum_enabled(void *dst, void *src, size_t n);
asmlinkage int enter_vector_usercopy(void *dst, void *src, size_t n,
				     bool enable_sum)
{
	size_t remain, copied;

	/* skip has_vector() check because it has been done by the asm  */
	if (!may_use_simd())
		goto fallback;

	kernel_vector_begin();
	remain = enable_sum ? __asm_vector_usercopy(dst, src, n) :
			      __asm_vector_usercopy_sum_enabled(dst, src, n);
	kernel_vector_end();

	if (remain) {
		copied = n - remain;
		dst += copied;
		src += copied;
		n = remain;
		goto fallback;
	}

	return remain;

fallback:
	return enable_sum ? fallback_scalar_usercopy(dst, src, n) :
			    fallback_scalar_usercopy_sum_enabled(dst, src, n);
}
#endif
