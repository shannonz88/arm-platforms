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

#include <linux/bitmap.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/percpu.h>
#include <linux/slab.h>

#include <linux/irqchip/arm-gic-v3.h>

#include <asm/cacheflush.h>
#include <asm/cputype.h>
#include <asm/exception.h>

#include "irqchip.h"

struct its_collection {
	u64			target_address;
	u16			col_id;
};

struct its_node {
	raw_spinlock_t		lock;
	struct list_head	entry;
	struct msi_chip		msi_chip;
	void __iomem		*base;
	unsigned long		phys_base;
	struct its_cmd_block	*cmd_base;
	struct its_cmd_block	*cmd_write;
	void			*tables[GITS_BASER_NR_REGS];
	struct its_collection	*collections;
	u64			flags;
};

#define ITS_ITT_SIZE		SZ_256
struct its_itt {
	/*
	 * The kernel doesn't really care about this. Only the size
	 * and the alignment actually matters.
	 */
	u8			table[ITS_ITT_SIZE];
} __aligned(ITS_ITT_SIZE);

struct its_device {
	struct its_itt		*itt;
	struct its_node		*its;
	struct its_collection	*collection;
	u32			device_id;
};

struct its_cmd_desc {
	union {
		struct {
			struct its_device *dev;
			u32 id;
		} its_inv_cmd;

		struct {
			struct its_device *dev;
			u32 id;
		} its_int_cmd;

		struct {
			struct its_device *dev;
			int valid;
		} its_mapd_cmd;

		struct {
			struct its_collection *col;
			int valid;
		} its_mapc_cmd;

		struct {
			struct its_device *dev;
			u32 id;
		} its_mapi_cmd;

		struct {
			struct its_device *dev;
			struct its_collection *col;
			u32 id;
		} its_movi_cmd;

		struct {
			struct its_device *dev;
			u32 id;
		} its_discard_cmd;

		struct {
			struct its_collection *col;
		} its_invall_cmd;
	};
};

struct its_cmd_block {
	u64	raw_cmd[4];
};

#define ITS_CMD_QUEUE_SZ		SZ_64K
#define ITS_CMD_QUEUE_NR_ENTRIES	(ITS_CMD_QUEUE_SZ / sizeof(struct its_cmd_block))

typedef struct its_collection *(*its_cmd_builder_t)(struct its_cmd_block *,
						    struct its_cmd_desc *);

static LIST_HEAD(its_nodes);
static DEFINE_SPINLOCK(its_lock);
static struct kmem_cache *its_itt_cache;
static struct device_node *gic_root_node;
static struct rdist *gic_rdist;

#define gic_data_rdist()		(__this_cpu_ptr(gic_rdist->rdist))
#define gic_data_rdist_rd_base()	(gic_data_rdist()->rd_base)

static void its_encode_cmd(struct its_cmd_block *cmd, u8 cmd_nr)
{
	cmd->raw_cmd[0] &= ~0xffUL;
	cmd->raw_cmd[0] |= cmd_nr;
}

static void its_encode_devid(struct its_cmd_block *cmd, u32 devid)
{
	cmd->raw_cmd[0] &= ~(0xffffUL << 32);
	cmd->raw_cmd[0] |= ((u64)devid) << 32;
}

static void its_encode_id(struct its_cmd_block *cmd, u32 id)
{
	cmd->raw_cmd[1] &= ~0xffffffffUL;
	cmd->raw_cmd[1] |= id;
}

static void its_encode_size(struct its_cmd_block *cmd, u8 size)
{
	cmd->raw_cmd[1] &= ~0x1fUL;
	cmd->raw_cmd[1] |= size & 0x1f;
}

static void its_encode_itt(struct its_cmd_block *cmd, u64 itt_addr)
{
	cmd->raw_cmd[2] &= ~0xffffffffffffUL;
	cmd->raw_cmd[2] |= itt_addr & 0xffffffffff00UL;
}

static void its_encode_valid(struct its_cmd_block *cmd, int valid)
{
	cmd->raw_cmd[2] &= ~(1UL << 63);
	cmd->raw_cmd[2] |= ((u64)!!valid) << 63;
}

static void its_encode_target(struct its_cmd_block *cmd, u64 target_addr)
{
	cmd->raw_cmd[2] &= ~(0xffffffffUL << 16);
	cmd->raw_cmd[2] |= (target_addr & (0xffffffffUL << 16));
}

static void its_encode_collection(struct its_cmd_block *cmd, u16 col)
{
	cmd->raw_cmd[2] &= ~0xffffUL;
	cmd->raw_cmd[2] |= col;
}

static inline void its_fixup_cmd(struct its_cmd_block *cmd)
{
#ifdef CONFIG_CPU_BIG_ENDIAN
	cmd->raw_cmd[0] = cpu_to_le64(cmd->raw_cmd[0]);
	cmd->raw_cmd[1] = cpu_to_le64(cmd->raw_cmd[1]);
	cmd->raw_cmd[2] = cpu_to_le64(cmd->raw_cmd[2]);
	cmd->raw_cmd[3] = cpu_to_le64(cmd->raw_cmd[3]);
#endif
}

static struct its_collection *its_build_mapd_cmd(struct its_cmd_block *cmd,
						 struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_MAPD);
	its_encode_devid(cmd, desc->its_mapd_cmd.dev->device_id);
	its_encode_size(cmd, 15); /* FIXME - we hardcode 16 bits here */
	its_encode_itt(cmd, virt_to_phys(desc->its_mapd_cmd.dev->itt));
	its_encode_valid(cmd, desc->its_mapd_cmd.valid);

	its_fixup_cmd(cmd);

	return desc->its_mapd_cmd.dev->collection;
}

static struct its_collection *its_build_mapc_cmd(struct its_cmd_block *cmd,
						 struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_MAPC);
	its_encode_collection(cmd, desc->its_mapc_cmd.col->col_id);
	its_encode_target(cmd, desc->its_mapc_cmd.col->target_address);
	its_encode_valid(cmd, desc->its_mapc_cmd.valid);

	its_fixup_cmd(cmd);

	return desc->its_mapc_cmd.col;
}

static struct its_collection *its_build_mapi_cmd(struct its_cmd_block *cmd,
						 struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_MAPI);
	its_encode_devid(cmd, desc->its_mapi_cmd.dev->device_id);
	its_encode_id(cmd, desc->its_mapi_cmd.id);
	its_encode_collection(cmd, desc->its_mapi_cmd.dev->collection->col_id);

	its_fixup_cmd(cmd);

	return desc->its_mapi_cmd.dev->collection;
}

static struct its_collection *its_build_movi_cmd(struct its_cmd_block *cmd,
						 struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_MOVI);
	its_encode_devid(cmd, desc->its_movi_cmd.dev->device_id);
	its_encode_id(cmd, desc->its_movi_cmd.id);
	its_encode_collection(cmd, desc->its_movi_cmd.col->col_id);

	its_fixup_cmd(cmd);

	return desc->its_movi_cmd.dev->collection;
}

static struct its_collection *its_build_discard_cmd(struct its_cmd_block *cmd,
						    struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_DISCARD);
	its_encode_devid(cmd, desc->its_discard_cmd.dev->device_id);
	its_encode_id(cmd, desc->its_discard_cmd.id);

	its_fixup_cmd(cmd);

	return desc->its_discard_cmd.dev->collection;
}

static struct its_collection *its_build_inv_cmd(struct its_cmd_block *cmd,
						struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_INV);
	its_encode_devid(cmd, desc->its_inv_cmd.dev->device_id);
	its_encode_id(cmd, desc->its_inv_cmd.id);

	its_fixup_cmd(cmd);

	return desc->its_inv_cmd.dev->collection;
}

static struct its_collection *its_build_invall_cmd(struct its_cmd_block *cmd,
						   struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_INVALL);
	its_encode_collection(cmd, desc->its_mapc_cmd.col->col_id);

	its_fixup_cmd(cmd);

	return NULL;
}

static struct its_collection *its_build_int_cmd(struct its_cmd_block *cmd,
						struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_INT);
	its_encode_devid(cmd, desc->its_int_cmd.dev->device_id);
	its_encode_id(cmd, desc->its_int_cmd.id);

	its_fixup_cmd(cmd);

	return desc->its_int_cmd.dev->collection;
}

static u64 its_cmd_ptr_to_offset(struct its_node *its,
				 struct its_cmd_block *ptr)
{
	return (ptr - its->cmd_base) * sizeof(*ptr);
}

static int its_queue_full(struct its_node *its)
{
	int widx;
	int ridx;

	widx = its->cmd_write - its->cmd_base;
	ridx = readl_relaxed(its->base + GITS_CREADR) / sizeof(struct its_cmd_block);

	/* This is incredibly unlikely to happen, unless the ITS locks up. */
	if (((widx + 1) % ITS_CMD_QUEUE_NR_ENTRIES) == ridx) {
		pr_err("ITS: full queue %d %d\n", widx, ridx);
		return 1;
	}

	return 0;
}

static struct its_cmd_block *its_allocate_entry(struct its_node *its)
{
	struct its_cmd_block *cmd;

	while (its_queue_full(its))
		cpu_relax();

	cmd = its->cmd_write++;

	/* Handle queue wrapping */
	if (its->cmd_write == (its->cmd_base + ITS_CMD_QUEUE_NR_ENTRIES))
		its->cmd_write = its->cmd_base;

	return cmd;
}

static struct its_cmd_block *its_post_commands(struct its_node *its)
{
	u64 wr = its_cmd_ptr_to_offset(its, its->cmd_write);

	writel_relaxed(wr, its->base + GITS_CWRITER);

	return its->cmd_write;
}

static void its_flush_cmd(struct its_node *its, struct its_cmd_block *cmd)
{
	/*
	 * Make sure the commands written to memory are observable by
	 * the ITS. The its parameter is unused for now, but could be
	 * useful if we ever get devices with various levels of
	 * coherency...
	 */
	__flush_dcache_area(cmd, sizeof(*cmd));
}

static void its_wait_for_range_completion(struct its_node *its,
					  struct its_cmd_block *from,
					  struct its_cmd_block *to)
{
	u64 rd_idx, from_idx, to_idx;

	from_idx = its_cmd_ptr_to_offset(its, from);
	to_idx = its_cmd_ptr_to_offset(its, to);

	while (1) {
		rd_idx = readl_relaxed(its->base + GITS_CREADR);
		if (rd_idx >= to_idx || rd_idx < from_idx)
			break;

		cpu_relax();
	}
}

static void its_send_single_command(struct its_node *its,
				    its_cmd_builder_t builder,
				    struct its_cmd_desc *desc)
{
	struct its_cmd_block *cmd, *sync_cmd, *next_cmd;
	struct its_collection *sync_col;

	raw_spin_lock(&its->lock);

	cmd = its_allocate_entry(its);
	sync_col = builder(cmd, desc);
	its_flush_cmd(its, cmd);

	if (sync_col) {
		sync_cmd = its_allocate_entry(its);
		its_encode_cmd(sync_cmd, GITS_CMD_SYNC);
		its_encode_target(sync_cmd, sync_col->target_address);
		its_fixup_cmd(sync_cmd);
		its_flush_cmd(its, sync_cmd);
	}

	next_cmd = its_post_commands(its);
	raw_spin_unlock(&its->lock);

	its_wait_for_range_completion(its, cmd, next_cmd);
}

static void its_send_inv(struct its_device *dev, u32 lpi)
{
	struct its_cmd_desc desc;

	desc.its_inv_cmd.dev = dev;
	desc.its_inv_cmd.id = lpi;

	its_send_single_command(dev->its, its_build_inv_cmd, &desc);
}

static void its_send_int(struct its_device *dev, u32 id)
{
	struct its_cmd_desc desc;

	desc.its_int_cmd.dev = dev;
	desc.its_int_cmd.id = id;

	its_send_single_command(dev->its, its_build_int_cmd, &desc);
}

static void its_send_mapd(struct its_device *dev, int valid)
{
	struct its_cmd_desc desc;

	desc.its_mapd_cmd.dev = dev;
	desc.its_mapd_cmd.valid = !!valid;

	its_send_single_command(dev->its, its_build_mapd_cmd, &desc);
}

static void its_send_mapc(struct its_node *its, struct its_collection *col,
			  int valid)
{
	struct its_cmd_desc desc;

	desc.its_mapc_cmd.col = col;
	desc.its_mapc_cmd.valid = !!valid;

	its_send_single_command(its, its_build_mapc_cmd, &desc);
}

static void its_send_mapi(struct its_device *dev, u32 irq_id)
{
	struct its_cmd_desc desc;

	desc.its_mapi_cmd.dev = dev;
	desc.its_mapi_cmd.id = irq_id;

	its_send_single_command(dev->its, its_build_mapi_cmd, &desc);
}

static void its_send_movi(struct its_device *dev,
			  struct its_collection *col, u32 irq_id)
{
	struct its_cmd_desc desc;

	desc.its_movi_cmd.dev = dev;
	desc.its_movi_cmd.col = col;
	desc.its_movi_cmd.id = irq_id;

	its_send_single_command(dev->its, its_build_movi_cmd, &desc);
}

static void its_send_discard(struct its_device *dev, u32 irq_id)
{
	struct its_cmd_desc desc;

	desc.its_discard_cmd.dev = dev;
	desc.its_discard_cmd.id = irq_id;

	its_send_single_command(dev->its, its_build_discard_cmd, &desc);
}

static void its_send_invall(struct its_node *its, struct its_collection *col)
{
	struct its_cmd_desc desc;

	desc.its_invall_cmd.col = col;

	its_send_single_command(its, its_build_invall_cmd, &desc);
}

/*
 * How we allocate LPIs:
 *
 * The GIC has id_bits bits for interrupt identifiers. From there, we
 * must subtract 8192 which are reserved for SGIs/PPIs/SPIs. Then, as
 * we allocate LPIs by chunks of 32, we can shift the whole thing by 5
 * bits to the right.
 *
 * This gives us (((1UL << id_bits) - 8192) >> 5) possible allocations.
 */
static unsigned long *lpi_bitmap;
static u32 lpi_chunks;
static DEFINE_SPINLOCK(lpi_lock);
static struct irq_domain *lpi_domain;

static void lpi_set_config(struct irq_data *d, int enable)
{
	struct its_device *its_dev = irq_data_get_irq_handler_data(d);
	u8 *cfg = page_address(gic_rdist->prop_page) + d->hwirq - 8192;

	if (enable)
		*cfg |= (1 << 0);
	else
		*cfg &= ~(1 << 0);

	/*
	 * Make the above write visible to the redistributors.
	 * And yes, we're flushing exactly: One. Single. Byte.
	 * Humpf...
	 */
	__flush_dcache_area(cfg, sizeof(*cfg));
	its_send_inv(its_dev, d->hwirq);
}

static void its_mask_irq(struct irq_data *d)
{
	lpi_set_config(d, 0);
}

static void its_unmask_irq(struct irq_data *d)
{
	lpi_set_config(d, 1);
}

static void its_eoi_irq(struct irq_data *d)
{
	gic_write_eoir(d->hwirq);
}

static int its_set_affinity(struct irq_data *d, const struct cpumask *mask_val,
			    bool force)
{
	unsigned int cpu = cpumask_any_and(mask_val, cpu_online_mask);
	struct its_device *its_dev = irq_data_get_irq_handler_data(d);
	struct its_collection *target_col;

	target_col = &its_dev->its->collections[cpu];
	its_send_movi(its_dev, target_col, d->hwirq);
	its_dev->collection = target_col;

	return IRQ_SET_MASK_OK;
}

static struct irq_chip its_irq_chip = {
	.name			= "ITS",
	.irq_mask		= its_mask_irq,
	.irq_unmask		= its_unmask_irq,
	.irq_eoi		= its_eoi_irq,
	.irq_set_affinity	= its_set_affinity,
};

void its_handle_lpi(u64 irqnr, struct pt_regs *regs)
{
	irqnr = irq_find_mapping(lpi_domain, irqnr);
	handle_IRQ(irqnr, regs);
}

static int its_lpi_to_chunk(int lpi)
{
	return (lpi - 8192) >> 5;
}

static int its_chunk_to_lpi(int chunk)
{
	return (chunk << 5) + 8192;
}

static int its_lpi_map(struct irq_domain *domain, unsigned int irq,
		       irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &its_irq_chip, handle_fasteoi_irq);
	set_irq_flags(irq, IRQF_VALID);
	irq_set_chip_data(irq, domain->host_data);
	return 0;
}

static const struct irq_domain_ops its_lpi_domain_ops = {
	.map	= its_lpi_map,
};

static int its_lpi_init(u32 id_bits)
{
	struct its_node *its;

	lpi_chunks = its_lpi_to_chunk(1UL << id_bits);

	lpi_bitmap = kzalloc(lpi_chunks / 8, GFP_KERNEL);
	if (!lpi_bitmap) {
		lpi_chunks = 0;
		return -ENOMEM;
	}

	/*
	 * Hack alert! We want a irq_domain, but we can't attach it to
	 * the GIC root node, as that interferes badly with the GIC's
	 * irq_domain. Dazed and confused. Instead, use the node of
	 * the first ITS we have. Irk...
	 */
	its = list_first_entry(&its_nodes, struct its_node, entry);
	lpi_domain = irq_domain_add_linear(its->msi_chip.of_node,
					   (1UL << id_bits) - 8192,
					   &its_lpi_domain_ops, NULL);
	if (!lpi_domain) {
		kfree(lpi_bitmap);
		return -ENOMEM;
	}

	pr_info("ITS: Allocated %d chunks for LPIs\n", (int)lpi_chunks);
	return 0;
}

static int its_lpi_alloc(void)
{
	int lpi;

	spin_lock(&lpi_lock);

	lpi = find_first_zero_bit(lpi_bitmap, lpi_chunks);
	if (lpi < lpi_chunks) {
		set_bit(lpi, lpi_bitmap);
		lpi = its_chunk_to_lpi(lpi);
	} else {
		lpi = -ENOSPC;
	}

	spin_unlock(&lpi_lock);

	return lpi;
}

static void its_lpi_free(int lpi)
{
	spin_lock(&lpi_lock);

	lpi = its_lpi_to_chunk(lpi);
	BUG_ON(lpi > lpi_chunks);
	if (test_bit(lpi, lpi_bitmap)) {
		clear_bit(lpi, lpi_bitmap);
	} else {
		pr_err("Bad LPI chunk %d\n", lpi);
	}

	spin_unlock(&lpi_lock);
}

/*
 * We allocate 64kB for PROPBASE.  That gives us at most 64K
 * interrupts to deal with. PENDBASE has to be 64kB aligned.
 */
#define LPI_PROPBASE_SZ		SZ_64K
#define LPI_PENDBASE_SZ		max((LPI_PROPBASE_SZ / 8 + SZ_1K), SZ_64K)
#define LPI_NRBITS		(get_order(LPI_PENDBASE_SZ + SZ_8K) + PAGE_SHIFT - 1)

static int gic_rdist_supports_plpis(void)
{
	return !!(readl_relaxed(gic_data_rdist_rd_base() + GICR_TYPER) & GICR_TYPER_PLPIS);
}

static int __init its_alloc_lpi_tables(void)
{
	gic_rdist->prop_page = alloc_pages(GFP_NOWAIT,
					   get_order(LPI_PROPBASE_SZ));
	if (!gic_rdist->prop_page) {
		pr_err("Failed to allocate PROPBASE\n");
		return -ENOMEM;
	}

	pr_info("GIC: using LPI property table @%llx\n",
		page_to_phys(gic_rdist->prop_page));

	/* Priority 0xa0, Group-1, disabled */
	memset(page_address(gic_rdist->prop_page), 0xa2, LPI_PROPBASE_SZ);

	return 0;
}

static void its_cpu_init_lpis(void)
{
	void __iomem *rbase = gic_data_rdist_rd_base();
	struct page *pend_page;
	u64 val;

	/* If we didn't allocate the pending table yet, do it now */
	pend_page = gic_data_rdist()->pend_page;
	if (!pend_page) {
		if (!gic_rdist_supports_plpis()) {
			pr_info("CPU%d: LPIs not supported\n",
				smp_processor_id());
			return;
		}

		pend_page = alloc_pages(GFP_NOWAIT | __GFP_ZERO,
					get_order(LPI_PENDBASE_SZ));
		if (!pend_page) {
			pr_err("Failed to allocate PENDBASE for CPU%d\n",
			       smp_processor_id());
			return;
		}

		pr_info("CPU%d: using LPI pending table @%llx\n",
			smp_processor_id(), page_to_phys(pend_page));
		gic_data_rdist()->pend_page = pend_page;
	}

	/* Disable LPIs */
	val = readl_relaxed(rbase + GICR_CTLR);
	val &= ~(1U << 0);
	writel_relaxed(val, rbase + GICR_CTLR);

	/*
	 * Make sure any change to the table is observable by the GIC.
	 */
	dsb();

	/* set PROPBASE */
	val = (page_to_phys(gic_rdist->prop_page) |
	       GICR_PROPBASER_InnerShareable |
	       GICR_PROPBASER_WaWb |
	       (LPI_NRBITS & 0x1f));

	writeq_relaxed(val, rbase + GICR_PROPBASER);

	/* set PENDBASE */
	val = (page_to_phys(pend_page) |
	       GICR_PROPBASER_InnerShareable |
	       GICR_PROPBASER_WaWb);

	writeq_relaxed(val, rbase + GICR_PENDBASER);

	/* Enable LPIs */
	val = readl_relaxed(rbase + GICR_CTLR);
	val |= (1U << 0);
	writel_relaxed(val, rbase + GICR_CTLR);

	/* Make sure the GIC has seen the above */
	dsb();
}

static void its_cpu_init_collection(void)
{
	struct list_head *entry;
	struct its_node *its;

	spin_lock(&its_lock);

	list_for_each(entry, &its_nodes) {
		int cpu = smp_processor_id();
		u64 target;

		/*
		 * We now have to bind each collection to its target
		 * redistributor.
		 */
		its = list_entry(entry, struct its_node, entry);

		if (readq_relaxed(its->base + GITS_TYPER) & GITS_TYPER_PTA) {
			/*
			 * This ITS wants the physical address of the
			 * redistributor.
			 */
			target = gic_data_rdist()->phys_base;
		} else {
			/*
			 * This ITS wants a linear CPU number.
			 */
			target = readq_relaxed(gic_data_rdist_rd_base() + GICR_TYPER);
			target >>= 8;
			target &= 0xffff;
		}

		/* Perform collection mapping */
		its->collections[cpu].target_address = target;
		its->collections[cpu].col_id = cpu;

		its_send_mapc(its, &its->collections[cpu], 1);
		its_send_invall(its, &its->collections[cpu]);
	}

	spin_unlock(&its_lock);
}

static const char *its_base_type_string[] = {
	[0]	= "Unimplemented",
	[1]	= "Devices",
	[2]	= "Virtual CPUs",
	[3]	= "Physical CPUs",
	[4]	= "Interrupt Collections",
	[5] 	= "Reserved",
	[6] 	= "Reserved",
	[7] 	= "Reserved",
};

static void its_free_tables(struct its_node *its)
{
	int i;

	for (i = 0; i < GITS_BASER_NR_REGS; i++) {
		if (its->tables[i]) {
			free_page((unsigned long)its->tables[i]);
			its->tables[i] = NULL;
		}
	}
}

static int its_alloc_tables(struct its_node *its)
{
	int err;
	int i;
	int psz = PAGE_SIZE;
	u64 shr = GITS_BASER_InnerShareable;

	for (i = 0; i < GITS_BASER_NR_REGS; i++) {
		u64 val = readq_relaxed(its->base + GITS_BASER + i * 8);
		u64 tmp;
		int type = (val >> 56) & 7;
		int entry_size = ((val >> 48) & 0xff) + 1;
		void *base;

		if (!type)
			continue;

		/* We're lazy and only allocate a single page for now */
		base = (void *)get_zeroed_page(GFP_KERNEL);
		if (!base) {
			err = -ENOMEM;
			goto out_free;
		}

		its->tables[i] = base;

retry_baser:
		val = (virt_to_phys(base) 		|
		       ((u64)type << 56)		|
		       ((u64)(entry_size - 1) << 48)	|
		       GITS_BASER_WaWb			|
		       shr				|
		       GITS_BASER_VALID);

		switch (psz) {
		case SZ_4K:
			val |= GITS_BASER_PAGE_SIZE_4K;
			break;
		case SZ_16K:
			val |= GITS_BASER_PAGE_SIZE_16K;
			break;
		case SZ_64K:
			val |= GITS_BASER_PAGE_SIZE_64K;
			break;
		}

		val |= (PAGE_SIZE / psz) - 1;

		writeq_relaxed(val, its->base + GITS_BASER + i * 8);
		tmp = readq_relaxed(its->base + GITS_BASER + i * 8);

		if ((val ^ tmp) & (3 << 10)) {
			/*
			 * Shareability didn't stick. Just use
			 * whatever the read reported, which is likely
			 * to be the only thing this redistributor
			 * supports.
			 */
			shr = tmp & (3 << 10);
			goto retry_baser;
		}

		if ((val ^ tmp) & (3 << 8)) {
			/*
			 * Page size didn't stick. Let's try a smaller
			 * size and retry. If we reach 4K, then
			 * something is horribly wrong...
			 */
			switch (psz) {
			case SZ_16K:
				psz = SZ_4K;
				goto retry_baser;
			case SZ_64K:
				psz = SZ_16K;
				goto retry_baser;
			}
		}

		if (val != tmp) {
			pr_err("ITS: %s: GITS_BASER%d doesn't stick: %lx %lx\n",
			       its->msi_chip.of_node->full_name, i,
			       (unsigned long) val, (unsigned long) tmp);
			err = -ENXIO;
			goto out_free;
		}

		pr_info("ITS: allocated %d %s @%lx (psz %dK)\n",
			(int)PAGE_SIZE / entry_size,
			its_base_type_string[type],
			(unsigned long)virt_to_phys(base),
			psz / 1024);
	}

	return 0;

out_free:
	its_free_tables(its);

	return err;
}

static int its_alloc_collections(struct its_node *its)
{
	its->collections = kzalloc(nr_cpu_ids * sizeof(*its->collections),
				   GFP_KERNEL);
	if (!its->collections)
		return -ENOMEM;

	return 0;
}

static int its_probe(struct device_node *node)
{
	struct resource res;
	struct its_node *its;
	void __iomem *its_base;
	u32 val;
	u64 baser;
	int err;

	err = of_address_to_resource(node, 0, &res);
	if (err) {
		pr_warn("%s: no regs?\n", node->full_name);
		return -ENXIO;
	}

	its_base = ioremap(res.start, resource_size(&res));
	if (!its_base) {
		pr_warn("%s: unable to map registers\n", node->full_name);
		return -ENOMEM;
	}

	val = readl_relaxed(its_base + GITS_PIDR);
	if ((val & 0xff) != GITS_PIDR0_GICv3) {
		pr_warn("%s: no ITS detected, giving up\n", node->full_name);
		err = -ENODEV;
		goto out_unmap;
	}

	pr_info("ITS: %s\n", node->full_name);

	its = kzalloc(sizeof(*its), GFP_KERNEL);
	if (!its) {
		err = -ENOMEM;
		goto out_unmap;
	}

	raw_spin_lock_init(&its->lock);
	INIT_LIST_HEAD(&its->entry);
	its->base = its_base;
	its->phys_base = res.start;
	its->msi_chip.of_node = node;

	its->cmd_base = kzalloc(ITS_CMD_QUEUE_SZ, GFP_KERNEL);
	if (!its->cmd_base) {
		err = -ENOMEM;
		goto out_free_its;
	}
	its->cmd_write = its->cmd_base;

	err = its_alloc_tables(its);
	if (err)
		goto out_free_cmd;

	err = its_alloc_collections(its);
	if (err)
		goto out_free_tables;

	baser = (virt_to_phys(its->cmd_base)	|
		 GITS_CBASER_WaWb		|
		 GITS_CBASER_InnerShareable	|
		 (ITS_CMD_QUEUE_SZ / SZ_4K - 1)	|
		 GITS_CBASER_VALID);

	writeq_relaxed(baser, its->base + GITS_CBASER);
	writeq_relaxed(0, its->base + GITS_CWRITER);
	writel_relaxed(1, its->base + GITS_CTLR);

	spin_lock(&its_lock);
	list_add(&its->entry, &its_nodes);
	spin_unlock(&its_lock);

	return 0;

out_free_tables:
	its_free_tables(its);
out_free_cmd:
	kfree(its->cmd_base);
out_free_its:
	kfree(its);
out_unmap:
	iounmap(its_base);
	pr_err("ITS: failed probing %s (%d)\n", node->full_name, err);
	return err;
}

static struct its_device *its_alloc_device(struct its_node *its, u32 dev_id,
					   int *hwirq, unsigned int *irq)
{
	struct its_device *dev;
	struct its_itt *itt;
	int cpu;
	int err;

	*hwirq = its_lpi_alloc();
	if (*hwirq < 0)
		return NULL;

	*irq = irq_create_mapping(lpi_domain, *hwirq);
	if (!*irq) {
		err = -EINVAL;
		goto out_free_lpi;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	itt = kmem_cache_zalloc(its_itt_cache, GFP_KERNEL);

	if (!dev || !itt) {
		kfree(dev);
		kfree(itt);
		goto out_free_mapping;
	}

	dev->its = its;
	dev->itt = itt;
	dev->device_id = dev_id;

	/* Bind the device to the first possible CPU */
	cpu = cpumask_first(cpu_online_mask);
	dev->collection = &its->collections[cpu];

	/* Map device to its ITT */
	its_send_mapd(dev, 1);

	/* Map device to the GIC irq ID */
	its_send_mapi(dev, *hwirq);

	return dev;

out_free_mapping:
	irq_dispose_mapping(*irq);
out_free_lpi:
	its_lpi_free(*hwirq);
	return NULL;
}

static void its_free_device(struct its_device *its_dev)
{
	kmem_cache_free(its_itt_cache, its_dev->itt);
	kfree(its_dev);
}

static void its_msi_teardown_irq(struct msi_chip *chip, unsigned int irq)
{
	struct irq_data *d = irq_get_irq_data(irq);
	struct its_device *its_dev = irq_data_get_irq_handler_data(d);

	/* Stop the delivery of interrupts */
	its_send_discard(its_dev, d->hwirq);

	/* Unmap device/itt */
	its_send_mapd(its_dev, 0);

	its_free_device(its_dev);
	its_lpi_free(d->hwirq);
	irq_dispose_mapping(irq);
}

/* FIXME: Use proper API once it is available in the kernel... */
#define PCI_REQUESTER_ID(dev)	(((dev)->bus->number << 8) | (dev)->devfn)

static int its_msi_setup_irq(struct msi_chip *chip,
			     struct pci_dev *pdev,
			     struct msi_desc *desc)
{
	struct its_node *its = container_of(chip, struct its_node, msi_chip);
	struct its_device *its_dev;
	struct msi_msg msg;
	unsigned int irq;
	u64 addr;
	int hwirq;

	its_dev = its_alloc_device(its, PCI_REQUESTER_ID(pdev), &hwirq, &irq);
	if (!its_dev)
		return -ENOMEM;

	irq_set_msi_desc(irq, desc);
	irq_set_handler_data(irq, its_dev);

	addr = its->phys_base + GITS_TRANSLATER;

	msg.address_lo		= addr & 0xfffffffUL;
	msg.address_hi		= addr >> 32;
	msg.data		= hwirq;

	write_msi_msg(irq, &msg);
	return 0;
}

int its_cpu_init(void)
{
	if (!list_empty(&its_nodes)) {
		its_cpu_init_lpis();
		its_cpu_init_collection();
	}

	return 0;
}

static struct of_device_id its_device_id[] = {
	{	.compatible	= "arm,gic-v3-its",	},
	{},
};

int its_init(struct device_node *node, struct rdist *rdist)
{
	struct device_node *np;


	for (np = of_find_matching_node(node, its_device_id); np;
	     np = of_find_matching_node(np, its_device_id)) {
		its_probe(np);
	}

	if (list_empty(&its_nodes)) {
		pr_info("ITS: No ITS available, not enabling LPIs\n");
		return -ENXIO;
	}

	gic_rdist = rdist;
	gic_root_node = node;

	its_itt_cache = KMEM_CACHE(its_itt, 0);
	its_alloc_lpi_tables();
	its_lpi_init(rdist->id_bits);

	return 0;
}

static int its_msi_probe(struct platform_device *pdev)
{
	struct list_head *entry;
	struct its_node *its = NULL;
	int err;

	/* Look for this node in the ITS list */
	spin_lock(&its_lock);

	list_for_each(entry, &its_nodes) {
		struct its_node *tmp;
		tmp = list_entry(entry, struct its_node, entry);
		if (tmp->msi_chip.of_node != pdev->dev.of_node)
			continue;

		its = tmp;
		break;
	}

	spin_unlock(&its_lock);

	if (!its)
		return -ENODEV;

	if (IS_ENABLED(CONFIG_PCI_MSI)) { /* Remove this once we have PCI... */
		its->msi_chip.dev		= &pdev->dev;
		its->msi_chip.setup_irq		= its_msi_setup_irq;
		its->msi_chip.teardown_irq	= its_msi_teardown_irq;

		err = of_pci_msi_chip_add(&its->msi_chip);
		if (err)
			return err;
	}

	dev_info(&pdev->dev, "matched %s\n", pdev->dev.of_node->full_name);
	return 0;
}

static struct platform_driver its_msi_driver = {
	.driver = {
		.name		= "its-msi",
		.owner		= THIS_MODULE,
		.of_match_table	= its_device_id,
	},
	.probe			= its_msi_probe,
};

static int __init its_msi_device_init(void)
{
	int err;

	if (!gic_root_node)	/* No GICv3 */
		return 0;

	err = of_platform_populate(gic_root_node, its_device_id, NULL, NULL);
	if (err) {
		pr_err("ITS: failed to register platform devices (%d)\n", err);
		return err;
	}

	err = platform_driver_register(&its_msi_driver);
	if (err) {
		pr_err("ITS: failed to register platform driver (%d)\n", err);
		return err;
	}

	return 0;
}

arch_initcall(its_msi_device_init);
