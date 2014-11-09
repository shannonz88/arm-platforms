/*
 * ARM GIC v2m MSI(-X) support
 * Support for Message Signaled Interrupts for systems that
 * implement ARM Generic Interrupt Controller: GICv2m.
 *
 * Copyright (C) 2014 Advanced Micro Devices, Inc.
 * Authors: Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>
 *	    Harish Kasiviswanathan <harish.kasiviswanathan@amd.com>
 *	    Brandon Anderson <brandon.anderson@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#define pr_fmt(fmt) "GICv2m: " fmt

#include <linux/bitmap.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <asm/hardirq.h>
#include <asm/irq.h>
#include <asm/msi.h>

#include "irqchip.h"
#include "irq-gic-v2m.h"

/*
* MSI_TYPER:
*     [31:26] Reserved
*     [25:16] lowest SPI assigned to MSI
*     [15:10] Reserved
*     [9:0]   Numer of SPIs assigned to MSI
*/
#define V2M_MSI_TYPER		       0x008
#define V2M_MSI_TYPER_BASE_SHIFT       16
#define V2M_MSI_TYPER_BASE_MASK	       0x3FF
#define V2M_MSI_TYPER_NUM_MASK	       0x3FF
#define V2M_MSI_SETSPI_NS	       0x040
#define V2M_MIN_SPI		       32
#define V2M_MAX_SPI		       1019

#define V2M_MSI_TYPER_BASE_SPI(x)      \
	       (((x) >> V2M_MSI_TYPER_BASE_SHIFT) & V2M_MSI_TYPER_BASE_MASK)

#define V2M_MSI_TYPER_NUM_SPI(x)       ((x) & V2M_MSI_TYPER_NUM_MASK)

struct v2m_data {
	spinlock_t msi_cnt_lock;
	struct msi_controller mchip;
	struct resource res;	/* GICv2m resource */
	void __iomem *base;	/* GICv2m virt address */
	unsigned int spi_start;	/* The SPI number that MSIs start */
	unsigned int nr_spis;	/* The number of SPIs for MSIs */
	unsigned long *bm;	/* MSI vector bitmap */
	struct irq_domain *domain;
};

static void gicv2m_unalloc_msi(struct msi_chip *chip, unsigned int hwirq)
{
	int pos;
	struct v2m_data *v2m = container_of(chip, struct v2m_data, mchip);

	pos = hwirq - v2m->spi_start;
	if (unlikely(pos < 0 || pos >= v2m->nr_spis)) {
		pr_err("Failed to teardown msi. Invalid hwirq %d\n", hwirq);
	} else {
		spin_lock(&v2m->msi_cnt_lock);
		bitmap_clear(v2m->bm, pos, 1);
		spin_unlock(&v2m->msi_cnt_lock);
	}
}

static void gicv2m_teardown_msi_irq(struct msi_chip *chip, unsigned int virq)
{
	struct irq_data *irq_data = irq_get_irq_data(virq);

	if (WARN(!irq_data, "GICv2m virq %u doesn't exist.\n", virq))
		return;

	gicv2m_unalloc_msi(chip, irq_data->hwirq);
	irq_domain_free_irqs(virq, 1);
}

static int gicv2m_setup_msi_irq(struct msi_chip *chip, struct pci_dev *pdev,
				struct msi_desc *desc)
{
	int hwirq, offset;
	int virq;
	struct v2m_data *v2m = container_of(chip, struct v2m_data, mchip);
	struct of_phandle_args args;

	spin_lock(&v2m->msi_cnt_lock);
	offset = bitmap_find_free_region(v2m->bm, v2m->nr_spis, 0);
	spin_unlock(&v2m->msi_cnt_lock);
	if (offset < 0)
		return offset;

	hwirq = v2m->spi_start + offset;

	/*
	 * The struct of_phandle_args is used to pass hwirq info
	 * to the parent GIC domain via irq_domain_alloc_irqs_parent().
	 */
	args.np = NULL;
	args.args_count = 3;
	args.args[0] = 0;
	args.args[1] = hwirq - 32;
	args.args[2] = IRQ_TYPE_EDGE_RISING;

	virq = irq_domain_alloc_irqs(v2m->domain, 1, NUMA_NO_NODE, &args);
	if (virq < 0) {
		gicv2m_unalloc_msi(chip, hwirq);
		return virq;
	}

	irq_domain_set_hwirq_and_chip(v2m->domain, virq, hwirq,
				      &gic_msi_chip, v2m);
	irq_set_msi_desc(virq, desc);
	irq_set_irq_type(virq, IRQ_TYPE_EDGE_RISING);

	return 0;
}

void gicv2m_compose_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct v2m_data *v2m;
	phys_addr_t addr;

	v2m = container_of(data->chip_data, struct v2m_data, mchip);
	addr = v2m->res.start + V2M_MSI_SETSPI_NS;

	msg->address_hi = (u32) (addr >> 32);
	msg->address_lo = (u32) (addr);
	msg->data = data->hwirq;
}

static int gicv2m_domain_alloc(struct irq_domain *d, unsigned int virq,
			       unsigned int nr_irqs, void *arg)
{
	int i, ret, irq;

	for (i = 0; i < nr_irqs; i++) {
		irq = virq + i;
		irq_set_chip_and_handler_name(irq, &gic_msi_chip,
					      handle_fasteoi_irq, "fasteoi");
	}

	ret = irq_domain_alloc_irqs_parent(d, virq, nr_irqs, arg);
	if (ret < 0)
		pr_err("Failed to allocate parent IRQ domain\n");

	return ret;
}

static void gicv2m_domain_free(struct irq_domain *d, unsigned int virq,
			       unsigned int nr_irqs)
{
	int i, irq;

	for (i = 0; i < nr_irqs; i++) {
		irq = virq + i;
		irq_set_handler(irq, NULL);
		irq_domain_set_hwirq_and_chip(d, irq, 0, NULL, NULL);
	}

	irq_domain_free_irqs_parent(d, virq, nr_irqs);
}

static bool is_msi_spi_valid(u32 base, u32 num)
{
	if (base < V2M_MIN_SPI) {
		pr_err("Invalid MSI base SPI (base:%u)\n", base);
		return false;
	}

	if ((num == 0) || (base + num > V2M_MAX_SPI)) {
		pr_err("Number of SPIs (%u) exceed maximum (%u)\n",
		       num, V2M_MAX_SPI - V2M_MIN_SPI + 1);
		return false;
	}

	return true;
}

static int __init gicv2m_init_one(struct device_node *node,
				  struct irq_domain *parent)
{
	int ret;
	struct v2m_data *v2m;

	v2m = kzalloc(sizeof(struct v2m_data), GFP_KERNEL);
	if (!v2m) {
		pr_err("Failed to allocate struct v2m_data.\n");
		return -ENOMEM;
	}

	v2m->mchip.owner = THIS_MODULE;
	v2m->mchip.of_node = node;
	v2m->mchip.setup_irq = gicv2m_setup_msi_irq;
	v2m->mchip.teardown_irq = gicv2m_teardown_msi_irq;
	ret = of_address_to_resource(node, 0, &v2m->res);
	if (ret) {
		pr_err("Failed to allocate v2m resource.\n");
		goto err_free_v2m;
	}

	v2m->base = ioremap(v2m->res.start, resource_size(&v2m->res));
	if (!v2m->base) {
		pr_err("Failed to map GICv2m resource\n");
		ret = -EINVAL;
		goto err_free_v2m;
	}

	ret = of_pci_msi_chip_add(&v2m->mchip);
	if (ret) {
		pr_info("Failed to add msi_chip.\n");
		goto err_iounmap;
	}

	if (!of_property_read_u32(node, "arm,msi-base-spi", &v2m->spi_start) &&
	    !of_property_read_u32(node, "arm,msi-num-spis", &v2m->nr_spis)) {
		pr_info("Overriding V2M MSI_TYPER (base:%u, num:%u)\n",
			v2m->spi_start, v2m->nr_spis);
	} else {
		u32 typer = readl_relaxed(v2m->base + V2M_MSI_TYPER);

		v2m->spi_start = V2M_MSI_TYPER_BASE_SPI(typer);
		v2m->nr_spis = V2M_MSI_TYPER_NUM_SPI(typer);
	}

	if (!is_msi_spi_valid(v2m->spi_start, v2m->nr_spis)) {
		ret = -EINVAL;
		goto err_chip_rm;
	}

	v2m->bm = kzalloc(sizeof(long) * BITS_TO_LONGS(v2m->nr_spis),
			  GFP_KERNEL);
	if (!v2m->bm) {
		ret = -ENOMEM;
		goto err_chip_rm;
	}

	v2m->domain = msi_create_irq_domain(node, &gic_msi_chip, parent);
	if (!v2m->domain) {
		pr_err("Failed to create GICv2m domain\n");
		ret = -EINVAL;
		goto err_free_bm;
	}

	spin_lock_init(&v2m->msi_cnt_lock);

	pr_info("Node %s: range[%#lx:%#lx], SPI[%d:%d]\n", node->name,
		(unsigned long)v2m->res.start, (unsigned long)v2m->res.end,
		v2m->spi_start, (v2m->spi_start + v2m->nr_spis));

	return 0;

 err_free_bm:
	kfree(v2m->bm);
 err_chip_rm:
	of_pci_msi_chip_remove(&v2m->mchip);
 err_iounmap:
	iounmap(v2m->base);
 err_free_v2m:
	kfree(v2m);
	return ret;
}

int __init gicv2m_of_init(struct device_node *node, struct irq_domain *parent)
{
	int ret = 0;
	struct device_node *child = NULL;

	gic_msi_chip.irq_compose_msi_msg = &gicv2m_compose_msi_msg;

	msi_domain_ops.alloc = &gicv2m_domain_alloc;
	msi_domain_ops.free = &gicv2m_domain_free;

	for (;;) {
		child = of_get_next_child(node, child);
		if (!child)
			break;

		if (!of_device_is_compatible(child, "arm,gic-v2m-frame"))
			continue;

		if (!of_find_property(child, "msi-controller", NULL))
			continue;

		ret = gicv2m_init_one(child, parent);
		if (ret) {
			of_node_put(node);
			break;
		}
	}
	return ret;
}
