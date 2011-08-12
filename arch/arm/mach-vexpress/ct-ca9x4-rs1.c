/*
 * Versatile Express Cortex A9 Quad Core Tile RS1 (FastModel) Support
 */
#include <linux/init.h>
#include <linux/cpumask.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/amba/bus.h>
#include <linux/amba/clcd.h>

#include <asm/cacheflush.h>
#include <asm/clkdev.h>
#include <asm/hardware/cache-l2x0.h>
#include <asm/hardware/gic.h>
#include <asm/smp_scu.h>
#include <asm/smp_twd.h>

#include <mach/clkdev.h>
#include <mach/ct-ca9x4-rs1.h>

#include <asm/mach/map.h>

#include "core.h"

#include <mach/motherboard.h>

#include <plat/clcd.h>

static struct map_desc ct_ca9x4_rs1_io_desc[] __initdata = {
	{
		.virtual	= __MMIO_P2V(CT_CA9X4_RS1_MPIC),
		.pfn		= __phys_to_pfn(CT_CA9X4_RS1_MPIC),
		.length		= SZ_64K,
		.type		= MT_DEVICE,
	}, {
		.virtual	= __MMIO_P2V(CT_CA9X4_RS1_L2CC),
		.pfn		= __phys_to_pfn(CT_CA9X4_RS1_L2CC),
		.length		= SZ_4K,
		.type		= MT_DEVICE,
	},
};

static void __init ct_ca9x4_rs1_map_io(void)
{
	iotable_init(ct_ca9x4_rs1_io_desc, ARRAY_SIZE(ct_ca9x4_rs1_io_desc));
}

static void __init ct_ca9x4_rs1_init_early(void)
{
}

static void __init ct_ca9x4_rs1_init_irq(void)
{
	gic_init(0, 29, MMIO_P2V(A9_RS1_MPCORE_GIC_DIST),
		 MMIO_P2V(A9_RS1_MPCORE_GIC_CPU));
}

static struct amba_device *ct_ca9x4_rs1_amba_devs[] __initdata = {
};

static void __init ct_ca9x4_rs1_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ct_ca9x4_rs1_amba_devs); i++)
		amba_device_register(ct_ca9x4_rs1_amba_devs[i], &iomem_resource);
}

#ifdef CONFIG_SMP
static void ct_ca9x4_rs1_init_cpu_map(void)
{
	int i, ncores = scu_get_core_count(MMIO_P2V(A9_RS1_MPCORE_SCU));

	for (i = 0; i < ncores; ++i)
		set_cpu_possible(i, true);
}

static void ct_ca9x4_rs1_smp_enable(unsigned int max_cpus)
{
	int i;
	for (i = 0; i < max_cpus; i++)
		set_cpu_present(i, true);

	scu_enable(MMIO_P2V(A9_RS1_MPCORE_SCU));
}
#endif

static struct ct_id ct_ca9x4_rs1_ids[] = {
	{
		.id	= 0x0c000000,
		.mask	= V2M_CT_ID_MASK,
	},
	{ },
};

struct ct_desc ct_ca9x4_rs1_desc __initdata = {
	.id_table	= ct_ca9x4_rs1_ids,
	.name		= "CA9x4-FastModel",
	.map_io		= ct_ca9x4_rs1_map_io,
	.init_early	= ct_ca9x4_rs1_init_early,
	.init_irq	= ct_ca9x4_rs1_init_irq,
	.init_tile	= ct_ca9x4_rs1_init,
#ifdef CONFIG_SMP
	.init_cpu_map	= ct_ca9x4_rs1_init_cpu_map,
	.smp_enable	= ct_ca9x4_rs1_smp_enable,
#endif
};
