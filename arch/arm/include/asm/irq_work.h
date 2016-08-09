#ifndef __ASM_ARM_IRQ_WORK_H
#define __ASM_ARM_IRQ_WORK_H

#include <asm/smp_plat.h>

static inline bool arch_irq_work_has_interrupt(void)
{
#ifdef CONFIG_SMP
	return !!__smp_cross_call;
#else
	return false;
#endif
}

#endif /* _ASM_ARM_IRQ_WORK_H */
