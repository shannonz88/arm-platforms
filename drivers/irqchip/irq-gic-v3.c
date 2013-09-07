/*
 * Copyright (C) 2013 ARM Limited, All Rights Reserved.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/stringify.h>

#include <linux/irqchip/arm-gic-v3.h>

#include <asm/cputype.h>
#include <asm/exception.h>
#include <asm/smp_plat.h>

#include "irqchip.h"

struct gic_chip_data {
	void __iomem		*dist_base;
	void __iomem		**redist_base;
	void __percpu __iomem	**rdist;
	struct irq_domain	*domain;
	u64			redist_stride;
	u32			redist_regions;
	unsigned int		irq_nr;
};

static struct gic_chip_data gic_data __read_mostly;

#define gic_data_rdist_rd_base()	(*__this_cpu_ptr(gic_data.rdist))
#define gic_data_rdist_sgi_base()	(gic_data_rdist_rd_base() + SZ_64K)

static DEFINE_RAW_SPINLOCK(dist_lock);

#define reg(x)		__stringify(x)

#define DEFAULT_PMR_VALUE	0xf0

static inline void __iomem *gic_dist_base(struct irq_data *d)
{
	if (d->hwirq < 32)	/* SGI+PPI -> SGI_base for this CPU */
		return gic_data_rdist_sgi_base();

	if (d->hwirq <= 1023)	/* SPI -> dist_base */
		return gic_data.dist_base;

	if (d->hwirq >= 8192)
		BUG();		/* LPI Detected!!! */

	return NULL;
}

static inline unsigned int gic_irq(struct irq_data *d)
{
	return d->hwirq;
}

static void gic_do_wait_for_rwp(void __iomem *base)
{
	u32 val;

	do {
		val = readl_relaxed(base + GICD_CTLR);
		cpu_relax();
	} while (val & GICD_CTLR_RWP);
}

/* Wait for completion of a distributor change */
static void gic_dist_wait_for_rwp(void)
{
	gic_do_wait_for_rwp(gic_data.dist_base);
}

/* Wait for completion of a redistributor change */
static void gic_redist_wait_for_rwp(void)
{
	gic_do_wait_for_rwp(gic_data_rdist_rd_base());
}

static void gic_wait_for_rwp(int irq)
{
	if (irq < 32)
		gic_redist_wait_for_rwp();
	else
		gic_dist_wait_for_rwp();
}

/* Low level accessors */
static void gic_write_eoir(u64 irq)
{
	asm volatile("msr " reg(ICC_EOIR1_EL1) ", %0" : : "r" (irq));
	isb();
}

static u64 gic_read_iar(void)
{
	u64 irqstat;

	asm volatile("mrs %0, " reg(ICC_IAR1_EL1) : "=r" (irqstat));
	return irqstat;
}

static void gic_write_pmr(u64 val)
{
	asm volatile("msr " reg(ICC_PMR_EL1) ", %0" : : "r" (val));
	isb();
}

static void gic_write_ctlr(u64 val)
{
	asm volatile("msr " reg(ICC_CTLR_EL1) ", %0" : : "r" (val));
	isb();
}

static void gic_write_grpen1(u64 val)
{
	asm volatile("msr " reg(ICC_GRPEN1_EL1) ", %0" : : "r" (val));
	isb();
}

static void gic_write_sgi1r(u64 val)
{
	asm volatile("msr " reg(ICC_SGI1R_EL1) ", %0" : : "r" (val));
	isb();
}

static void gic_enable_sre(void)
{
	u64 val;

	asm volatile("mrs %0, " reg(ICC_SRE_EL1) : "=r" (val));
	val |= GICC_SRE_EL1_SRE;
	asm volatile("msr " reg(ICC_SRE_EL1) ", %0" : : "r" (val));
	isb();
}

static void gic_enable_redist(void)
{
	void __iomem *rbase;
	u32 val;

	rbase = gic_data_rdist_rd_base();

	/* Wake up this CPU redistributor */
	val = readl_relaxed(rbase + GICR_WAKER);
	val &= ~GICR_WAKER_ProcessorSleep;
	writel_relaxed(val, rbase + GICR_WAKER);

	do {
		val = readl_relaxed(rbase + GICR_WAKER);
		cpu_relax();
	} while (val & GICR_WAKER_ChildrenAsleep);
}

/*
 * Routines to acknowledge, disable and enable interrupts
 */
static void gic_mask_irq(struct irq_data *d)
{
	u32 mask = 1 << (gic_irq(d) % 32);

	raw_spin_lock(&dist_lock);
	writel_relaxed(mask, gic_dist_base(d) + GICD_ICENABLER + (gic_irq(d) / 32) * 4);
	gic_wait_for_rwp(gic_irq(d));
	raw_spin_unlock(&dist_lock);
}

static void gic_unmask_irq(struct irq_data *d)
{
	u32 mask = 1 << (gic_irq(d) % 32);

	raw_spin_lock(&dist_lock);
	writel_relaxed(mask, gic_dist_base(d) + GICD_ISENABLER + (gic_irq(d) / 32) * 4);
	gic_wait_for_rwp(gic_irq(d));
	raw_spin_unlock(&dist_lock);
}

static void gic_eoi_irq(struct irq_data *d)
{
	gic_write_eoir(gic_irq(d));
}

static int gic_set_type(struct irq_data *d, unsigned int type)
{
	void __iomem *base = gic_dist_base(d);
	unsigned int irq = gic_irq(d);
	u32 enablemask = 1 << (irq % 32);
	u32 enableoff = (irq / 32) * 4;
	u32 confmask = 0x2 << ((irq % 16) * 2);
	u32 confoff = (irq / 16) * 4;
	bool enabled = false;
	u32 val;

	/* Interrupt configuration for SGIs can't be changed */
	if (irq < 16)
		return -EINVAL;

	if (type != IRQ_TYPE_LEVEL_HIGH && type != IRQ_TYPE_EDGE_RISING)
		return -EINVAL;

	raw_spin_lock(&dist_lock);

	val = readl_relaxed(base + GICD_ICFGR + confoff);
	if (type == IRQ_TYPE_LEVEL_HIGH)
		val &= ~confmask;
	else if (type == IRQ_TYPE_EDGE_RISING)
		val |= confmask;

	/*
	 * As recommended by the spec, disable the interrupt before changing
	 * the configuration
	 */
	if (readl_relaxed(base + GICD_ISENABLER + enableoff) & enablemask) {
		writel_relaxed(enablemask, base + GICD_ICENABLER + enableoff);
		gic_wait_for_rwp(irq);
		enabled = true;
	}

	writel_relaxed(val, base + GICD_ICFGR + confoff);

	if (enabled) {
		writel_relaxed(enablemask, base + GICD_ISENABLER + enableoff);
		gic_wait_for_rwp(irq);
	}

	raw_spin_unlock(&dist_lock);

	return 0;
}

static int gic_retrigger(struct irq_data *d)
{
	return -ENXIO;
}

static u64 gic_mpidr_to_affinity(u64 mpidr)
{
	/* Make sure we don't broadcast the interrupt */
	return mpidr & ~GICD_IROUTER_SPI_MODE_ANY;
}

static asmlinkage void __exception_irq_entry gic_handle_irq(struct pt_regs *regs)
{
	u64 irqstat, irqnr;

	do {
		irqstat = gic_read_iar();
		irqnr = irqstat & 0x3ff;

		if (likely(irqnr > 15 && irqnr < 1021)) {
			irqnr = irq_find_mapping(gic_data.domain, irqnr);
			handle_IRQ(irqnr, regs);
			continue;
		}
		if (irqnr < 16) {
			gic_write_eoir(irqnr);
#ifdef CONFIG_SMP
			handle_IPI(irqnr, regs);
#else
			WARN_ONCE(true, "Unexpected SGI received!\n");
#endif
			continue;
		}
	} while (irqnr != 0x3ff);
}

static void __init gic_dist_init(void)
{
	unsigned int i;
	u64 affinity;
	int gic_irqs = gic_data.irq_nr;
	void __iomem *base = gic_data.dist_base;

	/* Disable the distributor */
	writel_relaxed(0, base + GICD_CTLR);

	/*
	 * Set all global interrupts to be level triggered, active low.
	 */
	for (i = 32; i < gic_data.irq_nr; i += 16)
		writel_relaxed(0, base + GICD_ICFGR + i / 4);

	/*
	 * Set priority on all global interrupts.
	 */
	for (i = 32; i < gic_irqs; i += 4)
		writel_relaxed(0xa0a0a0a0, base + GICD_IPRIORITYR + i);

	/*
	 * Disable all interrupts.  Leave the PPI and SGIs alone
	 * as these enables are banked registers.
	 */
	for (i = 32; i < gic_irqs; i += 32)
		writel_relaxed(0xffffffff, base + GICD_ICENABLER + i / 8);

	gic_dist_wait_for_rwp();

	writel_relaxed(GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_G1A | GICD_CTLR_ENABLE_G1,
		       base + GICD_CTLR);

	/*
	 * Set all global interrupts to the boot CPU only. ARE must be
	 * enabled.
	 */
	affinity = gic_mpidr_to_affinity(read_cpuid_mpidr());
	for (i = 32; i < gic_data.irq_nr; i++)
		writeq_relaxed(affinity, base + GICD_IROUTER + i * 8);
}

static int __init gic_populate_rdist(void)
{
	u64 mpidr = cpu_logical_map(smp_processor_id());
	u64 typer;
	u64 aff;
	int i;

	aff  = mpidr & ((1 << 24) - 1);
	aff |= (mpidr >> 8) & (0xffUL << 24);

	for (i = 0; i < gic_data.redist_regions; i++) {
		void __iomem *ptr = gic_data.redist_base[i];
		u32 reg;

		reg = readl_relaxed(ptr + GICR_PIDR);
		if ((reg & 0xff) != GICR_PIDR0_GICv3) { /* We're in trouble... */
			pr_warn("No redistributor present @%p\n", ptr);
			break;
		}

		do {
			typer = readq_relaxed(ptr + GICR_TYPER);
			if ((typer >> 32) == aff) {
				*__this_cpu_ptr(gic_data.rdist) = ptr;
				pr_info("CPU%d: found redistributor %llx @%p\n",
					smp_processor_id(),
					(unsigned long long) mpidr, ptr);
				return 0;
			}

			if (gic_data.redist_stride) {
				ptr += gic_data.redist_stride;
			} else {
				ptr += SZ_64K * 2; /* Skip RD_base + SGI_base */
				if (typer & GICR_TYPER_VLPIS)
					ptr += SZ_64K * 2; /* Skip VLPI_base + reserved page */
			}
		} while (!(typer & GICR_TYPER_LAST));
	}

	/* We couldn't even deal with ourselves... */
	WARN(true, "CPU%d: mpidr %lx has no re-distributor!\n",
	     smp_processor_id(), (unsigned long)mpidr);
	return -ENODEV;
}

static void __init gic_cpu_init(void)
{
	void __iomem *rbase;
	int i;

	/* Register ourselves with the rest of the world */
	if (gic_populate_rdist())
		return;

	gic_enable_redist();

	rbase = gic_data_rdist_sgi_base();

	/*
	 * Set priority on PPI and SGI interrupts
	 */
	for (i = 0; i < 32; i += 4)
		writel_relaxed(0xa0a0a0a0, rbase + GICR_IPRIORITYR0 + i * 4 / 4);

	/*
	 * Disable all PPI interrupts, ensure all SGI interrupts are
	 * enabled.
	 */
	writel_relaxed(0xffff0000, rbase + GICR_ICENABLER0);
	writel_relaxed(0x0000ffff, rbase + GICR_ISENABLER0);

	gic_redist_wait_for_rwp();

	/* Enable system registers */
	gic_enable_sre();

	/* Set priority mask register */
	gic_write_pmr(DEFAULT_PMR_VALUE);

	/* EOI drops priority too (mode 0) */
	gic_write_ctlr(GICC_CTLR_EL1_EOImode_drop_dir);

	/* ... and let's hit the road... */
	gic_write_grpen1(1);
}

#ifdef CONFIG_SMP
static int __init gic_secondary_init(struct notifier_block *nfb,
				     unsigned long action, void *hcpu)
{
	if (action == CPU_STARTING || action == CPU_STARTING_FROZEN)
		gic_cpu_init();
	return NOTIFY_OK;
}

/*
 * Notifier for enabling the GIC CPU interface. Set an arbitrarily high
 * priority because the GIC needs to be up before the ARM generic timers.
 */
static struct notifier_block __initdata gic_cpu_notifier = {
	.notifier_call = gic_secondary_init,
	.priority = 100,
};

static u16 gic_compute_target_list(int *base_cpu, const struct cpumask *mask,
				   u64 cluster_id)
{
	int cpu = *base_cpu;
	u64 mpidr = cpu_logical_map(cpu);
	u16 tlist = 0;

	while (cpu < nr_cpu_ids) {
		/*
		 * If we ever get a cluster of more than 16 CPUs, just
		 * scream and skip that CPU.
		 */
		if (WARN_ON((mpidr & 0xff) >= 16))
			goto out;

		tlist |= 1 << (mpidr & 0xf);

		cpu = cpumask_next(cpu, mask);
		mpidr = cpu_logical_map(cpu);

		if (cluster_id != (mpidr & ~0xffUL)) {
			cpu--;
			goto out;
		}
	}
out:
	*base_cpu = cpu;
	return tlist;
}

static void gic_send_sgi(u64 cluster_id, u16 tlist, unsigned int irq)
{
	u64 val;

	val  = (cluster_id & 0xff00ff0000UL) << 16; /* Aff3 + Aff2 */
	val |= (cluster_id & 0xff00) << 8;	    /* Aff1 */
	val |= irq << 24;
	val |= tlist;

	pr_debug("CPU%d: ICC_SGI1R_EL1 %llx\n", smp_processor_id(), val);
	gic_write_sgi1r(val);
}

static void gic_raise_softirq(const struct cpumask *mask, unsigned int irq)
{
	int cpu;

	if (WARN_ON(irq >= 16))
		return;

	/*
	 * Ensure that stores to Normal memory are visible to the
	 * other CPUs before issuing the IPI.
	 */
	dsb();

	for_each_cpu_mask(cpu, *mask) {
		u64 cluster_id = cpu_logical_map(cpu) & ~0xffUL;
		u16 tlist;

		tlist = gic_compute_target_list(&cpu, mask, cluster_id);
		gic_send_sgi(cluster_id, tlist, irq);
	}
}

static void gic_smp_init(void)
{
	set_smp_cross_call(gic_raise_softirq);
	register_cpu_notifier(&gic_cpu_notifier);
}

static int gic_set_affinity(struct irq_data *d, const struct cpumask *mask_val,
			    bool force)
{
	unsigned int cpu = cpumask_any_and(mask_val, cpu_online_mask);
	void __iomem *reg;
	u64 val;

	if (gic_irq(d) < 32)
		return -EINVAL;

	reg = gic_dist_base(d) + GICD_IROUTER + (gic_irq(d) * 8);
	val = gic_mpidr_to_affinity(cpu_logical_map(cpu));

	writeq_relaxed(val, reg);

	return IRQ_SET_MASK_OK;
}
#else
#define gic_set_affinity	NULL
#define gic_smp_init()		do { } while(0)
#endif

static struct irq_chip gic_chip = {
	.name			= "GICv3",
	.irq_mask		= gic_mask_irq,
	.irq_unmask		= gic_unmask_irq,
	.irq_eoi		= gic_eoi_irq,
	.irq_set_type		= gic_set_type,
	.irq_retrigger		= gic_retrigger,
	.irq_set_affinity	= gic_set_affinity,
};

static int gic_irq_domain_map(struct irq_domain *d, unsigned int irq,
				irq_hw_number_t hw)
{
	if (hw < 32) {
		irq_set_percpu_devid(irq);
		irq_set_chip_and_handler(irq, &gic_chip,
					 handle_percpu_devid_irq);
		set_irq_flags(irq, IRQF_VALID | IRQF_NOAUTOEN);
	} else {
		irq_set_chip_and_handler(irq, &gic_chip,
					 handle_fasteoi_irq);
		set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
	}
	irq_set_chip_data(irq, d->host_data);
	return 0;
}

static int gic_irq_domain_xlate(struct irq_domain *d,
				struct device_node *controller,
				const u32 *intspec, unsigned int intsize,
				unsigned long *out_hwirq, unsigned int *out_type)
{
	if (d->of_node != controller)
		return -EINVAL;
	if (intsize < 3)
		return -EINVAL;

	switch(intspec[0]) {
	case 0:			/* SPI */
		*out_hwirq = intspec[1] + 32;
		break;
	case 1:			/* PPI */
		*out_hwirq = intspec[1] + 16;
		break;
	default:
		return -EINVAL;
	}

	*out_type = intspec[2] & IRQ_TYPE_SENSE_MASK;
	return 0;
}

static const struct irq_domain_ops gic_irq_domain_ops = {
	.map = gic_irq_domain_map,
	.xlate = gic_irq_domain_xlate,
};

static int __init gic_of_init(struct device_node *node, struct device_node *parent)
{
	void __iomem *dist_base;
	void __iomem **redist_base;
	u64 redist_stride;
	u32 redist_regions;
	u32 reg;
	int gic_irqs;
	int err;
	int i;

	dist_base = of_iomap(node, 0);
	if (!dist_base) {
		pr_warn("%s: unable to map gic dist registers\n",
			node->full_name);
		return -ENXIO;
	}

	reg = readl_relaxed(dist_base + GICD_PIDR);
	if ((reg & 0xff) != GICD_PIDR0_GICv3) {
		pr_warn("%s: no distributor detected, giving up\n",
			node->full_name);
		err = -ENODEV;
		goto out_unmap_dist;
	}

	if (of_property_read_u32(node, "#redistributor-regions", &redist_regions))
		redist_regions = 1;

	redist_base = kzalloc(sizeof(*redist_base) * redist_regions, GFP_KERNEL);
	if (!redist_base) {
		err = -ENOMEM;
		goto out_unmap_dist;
	}

	for (i = 0; i < redist_regions; i++) {
		redist_base[i] = of_iomap(node, 1 + i);
		if (!redist_base[i]) {
			pr_warn("%s: couldn't map region %d\n",
				node->full_name, i);
			err = -ENODEV;
			goto out_unmap_rdist;
		}
	}

	if (of_property_read_u64(node, "redistributor-stride", &redist_stride))
		redist_stride = 0;

	gic_data.dist_base = dist_base;
	gic_data.redist_base = redist_base;
	gic_data.redist_regions = redist_regions;
	gic_data.redist_stride = redist_stride;

	/*
	 * Find out how many interrupts are supported.
	 * The GIC only supports up to 1020 interrupt sources (SGI+PPI+SPI)
	 */
	gic_irqs = readl_relaxed(gic_data.dist_base + GICD_TYPER) & 0x1f;
	gic_irqs = (gic_irqs + 1) * 32;
	if (gic_irqs > 1020)
		gic_irqs = 1020;
	gic_data.irq_nr = gic_irqs;

	gic_data.domain = irq_domain_add_linear(node, gic_irqs - 16,
						&gic_irq_domain_ops, &gic_data);
	gic_data.rdist = alloc_percpu(void __iomem *);

	if (WARN_ON(!gic_data.domain) || WARN_ON(!gic_data.rdist)) {
		err = -ENOMEM;
		goto out_free;
	}

	set_handle_irq(gic_handle_irq);

	gic_smp_init();
	gic_dist_init();
	gic_cpu_init();

	return 0;

out_free:
	free_percpu(gic_data.rdist);
out_unmap_rdist:
	for (i = 0; i < redist_regions; i++)
		if (redist_base[i])
			iounmap(redist_base[i]);
	kfree(redist_base);
out_unmap_dist:
	iounmap(dist_base);
	return err;
}

IRQCHIP_DECLARE(gic_v3, "arm,gic-v3", gic_of_init);
