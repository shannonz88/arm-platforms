#ifndef ARM_PLAT_LOCALTIMER_H
#define ARM_PLAT_LOCALTIMER_H

#ifdef CONFIG_LOCAL_TIMERS
void versatile_local_timer_init(void __iomem *base);
#else
static inline void versatile_local_timer_init(void __iomem *base)
{
}
#endif

#endif
