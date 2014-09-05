/*
 * Support of MSI, HPET and DMAR interrupts.
 *
 * Copyright (C) 1997, 1998, 1999, 2000, 2009 Ingo Molnar, Hajnalka Szabo
 *	Moved from arch/x86/kernel/apic/io_apic.c.
 * Jiang Liu <jiang.liu@linux.intel.com>
 *	Add support of hierarchy irqdomain
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/dmar.h>
#include <linux/hpet.h>
#include <linux/msi.h>
#include <linux/irqdomain.h>
#include <asm/msidef.h>
#include <asm/hpet.h>
#include <asm/hw_irq.h>
#include <asm/apic.h>
#include <asm/irq_remapping.h>

static struct irq_domain *msi_default_domain;

static void msi_reset_irq_data_and_handler(struct irq_domain *domain, int virq)
{
	struct irq_data *irq_data = irq_domain_get_irq_data(domain, virq);

	if (irq_data);
		irq_domain_reset_irq_data(irq_data);
	irq_set_handler_data(virq, NULL);
	irq_set_handler(virq, NULL);
}

static void native_compose_msi_msg(struct irq_cfg *cfg, struct msi_msg *msg)
{
	msg->address_hi = MSI_ADDR_BASE_HI;

	if (x2apic_enabled())
		msg->address_hi |= MSI_ADDR_EXT_DEST_ID(cfg->dest_apicid);

	msg->address_lo =
		MSI_ADDR_BASE_LO |
		((apic->irq_dest_mode == 0) ?
			MSI_ADDR_DEST_MODE_PHYSICAL :
			MSI_ADDR_DEST_MODE_LOGICAL) |
		((apic->irq_delivery_mode != dest_LowestPrio) ?
			MSI_ADDR_REDIRECTION_CPU :
			MSI_ADDR_REDIRECTION_LOWPRI) |
		MSI_ADDR_DEST_ID(cfg->dest_apicid);

	msg->data =
		MSI_DATA_TRIGGER_EDGE |
		MSI_DATA_LEVEL_ASSERT |
		((apic->irq_delivery_mode != dest_LowestPrio) ?
			MSI_DATA_DELIVERY_FIXED :
			MSI_DATA_DELIVERY_LOWPRI) |
		MSI_DATA_VECTOR(cfg->vector);
}

static void msi_update_msg(struct msi_msg *msg, struct irq_data *irq_data)
{
	struct irq_cfg *cfg = irqd_cfg(irq_data);

	msg->data &= ~MSI_DATA_VECTOR_MASK;
	msg->data |= MSI_DATA_VECTOR(cfg->vector);
	msg->address_lo &= ~MSI_ADDR_DEST_ID_MASK;
	msg->address_lo |= MSI_ADDR_DEST_ID(cfg->dest_apicid);
}

static bool msi_irq_remapped(struct irq_data *irq_data)
{
	return irq_remapping_domain_is_remapped(irq_data->domain);
}

static int msi_set_affinity(struct irq_data *data, const struct cpumask *mask,
			    bool force)
{
	struct irq_data *parent = data->parent_data;
	int ret;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	/* No need to reprogram MSI registers if interrupt is remapped */
	if (ret >= 0 && !msi_irq_remapped(data)) {
		struct msi_msg msg;

		__get_cached_msi_msg(data->msi_desc, &msg);
		msi_update_msg(&msg, data);
		__write_msi_msg(data->msi_desc, &msg);
	}

	return ret;
}

/*
 * IRQ Chip for MSI PCI/PCI-X/PCI-Express Devices,
 * which implement the MSI or MSI-X Capability Structure.
 */
static struct irq_chip msi_chip = {
	.name			= "PCI-MSI",
	.irq_unmask		= unmask_msi_irq,
	.irq_mask		= mask_msi_irq,
	.irq_ack		= irq_chip_ack_parent,
	.irq_set_affinity	= msi_set_affinity,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_print_chip		= irq_remapping_print_chip,
};

static inline irq_hw_number_t
get_hwirq_from_pcidev(struct pci_dev *pdev, struct msi_desc *msidesc)
{
	return (irq_hw_number_t)msidesc->msi_attrib.entry_nr |
		PCI_DEVID(pdev->bus->number, pdev->devfn) << 11 |
		(pci_domain_nr(pdev->bus) & 0xFFFFFFFF) << 27;
}

static int msi_domain_alloc(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs, void *arg)
{
	int i, ret;
	irq_hw_number_t hwirq;
	struct irq_alloc_info *info = arg;

	hwirq = get_hwirq_from_pcidev(info->msi_dev, info->msi_desc);
	if (irq_find_mapping(domain, hwirq) > 0)
		return -EEXIST;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, info);
	if (ret < 0)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		irq_set_msi_desc_off(virq, i, info->msi_desc);
		irq_domain_set_hwirq_and_chip(domain, virq + i, hwirq + i,
					      &msi_chip, (void *)(long)i);
		__irq_set_handler(virq + i, handle_edge_irq, 0, "edge");
		dev_dbg(&info->msi_dev->dev, "irq %d for MSI/MSI-X\n",
			virq + i);
	}

	return ret;
}

static void msi_domain_free(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs)
{
	int i;
	struct msi_desc *msidesc = irq_get_msi_desc(virq);

	if (msidesc)
		msidesc->irq = 0;
	for (i = 0; i < nr_irqs; i++)
		msi_reset_irq_data_and_handler(domain, virq + i);
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

static int msi_domain_activate(struct irq_domain *domain,
			       struct irq_data *irq_data)
{
	struct msi_msg msg;
	struct irq_cfg *cfg = irqd_cfg(irq_data);

	/*
	 * irq_data->chip_data is MSI/MSIx offset.
	 * MSI-X message is written per-IRQ, the offset is always 0.
	 * MSI message denotes a contiguous group of IRQs, written for 0th IRQ.
	 */
	if (irq_data->chip_data)
		return 0;

	if (msi_irq_remapped(irq_data))
		irq_remapping_get_msi_entry(irq_data->parent_data, &msg);
	else
		native_compose_msi_msg(cfg, &msg);
	write_msi_msg(irq_data->irq, &msg);

	return 0;
}

static int msi_domain_deactivate(struct irq_domain *domain,
				 struct irq_data *irq_data)
{
	struct msi_msg msg;

	if (irq_data->chip_data)
		return 0;

	memset(&msg, 0, sizeof(msg));
	write_msi_msg(irq_data->irq, &msg);

	return 0;
}

static struct irq_domain_ops msi_domain_ops = {
	.alloc = msi_domain_alloc,
	.free = msi_domain_free,
	.activate = msi_domain_activate,
	.deactivate = msi_domain_deactivate,
};

int native_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	int irq, cnt, nvec_pow2;
	struct irq_domain *domain;
	struct msi_desc *msidesc;
	struct irq_alloc_info info;
	int node = dev_to_node(&dev->dev);

	if (disable_apic)
		return -ENOSYS;

	init_irq_alloc_info(&info, NULL);
	info.msi_dev = dev;
	if (type == PCI_CAP_ID_MSI) {
		msidesc = list_entry(dev->msi_list.next, struct msi_desc, list);
		WARN_ON(!list_is_singular(&dev->msi_list));
		WARN_ON(msidesc->irq);
		WARN_ON(msidesc->msi_attrib.multiple);
		WARN_ON(msidesc->nvec_used);
		info.type = X86_IRQ_ALLOC_TYPE_MSI;
		cnt = nvec;
	} else {
		info.type = X86_IRQ_ALLOC_TYPE_MSIX;
		cnt = 1;
	}

	domain = irq_remapping_get_irq_domain(&info);
	if (domain == NULL) {
		/*
		 * Multiple MSI vectors only supported with interrupt
		 * remapping
		 */
		if (type == PCI_CAP_ID_MSI && nvec > 1)
			return 1;
		domain = msi_default_domain;
	}
	if (domain == NULL)
		return -ENOSYS;

	list_for_each_entry(msidesc, &dev->msi_list, list) {
		info.msi_desc = msidesc;
		irq = irq_domain_alloc_irqs(domain, cnt, node, &info);
		if (irq <= 0)
			return -ENOSPC;
	}

	if (type == PCI_CAP_ID_MSI) {
		nvec_pow2 = __roundup_pow_of_two(nvec);
		msidesc->msi_attrib.multiple = ilog2(nvec_pow2);
		msidesc->nvec_used = nvec;
	}

	return 0;
}

void native_teardown_msi_irq(unsigned int irq)
{
	irq_domain_free_irqs(irq, 1);
}

static struct irq_domain *msi_create_domain(struct irq_domain *parent,
					    bool remapped)
{
	struct irq_domain *domain;

	domain = irq_domain_add_tree(NULL, &msi_domain_ops, NULL);
	if (domain) {
		domain->parent = parent;
		if (remapped)
			irq_remapping_domain_set_remapped(domain);
	}

	return domain;
}

void arch_init_msi_domain(struct irq_domain *parent)
{
	if (disable_apic)
		return;

	msi_default_domain = msi_create_domain(parent, false);
	if (!msi_default_domain)
		pr_warn("failed to initialize irqdomain for MSI/MSI-x.\n");
}

#ifdef CONFIG_IRQ_REMAP
struct irq_domain *arch_create_msi_irq_domain(struct irq_domain *parent)
{
	return msi_create_domain(parent, true);
}
#endif

#ifdef CONFIG_DMAR_TABLE
static int
dmar_msi_set_affinity(struct irq_data *data, const struct cpumask *mask,
		      bool force)
{
	struct irq_cfg *cfg = irqd_cfg(data);
	unsigned int dest, irq = data->irq;
	struct msi_msg msg;
	int ret;

	ret = apic_set_affinity(data, mask, &dest);
	if (ret)
		return ret;

	dmar_msi_read(irq, &msg);

	msg.data &= ~MSI_DATA_VECTOR_MASK;
	msg.data |= MSI_DATA_VECTOR(cfg->vector);
	msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
	msg.address_lo |= MSI_ADDR_DEST_ID(dest);
	msg.address_hi = MSI_ADDR_BASE_HI | MSI_ADDR_EXT_DEST_ID(dest);

	dmar_msi_write(irq, &msg);

	return IRQ_SET_MASK_OK_NOCOPY;
}

static struct irq_chip dmar_msi_type = {
	.name			= "DMAR_MSI",
	.irq_unmask		= dmar_msi_unmask,
	.irq_mask		= dmar_msi_mask,
	.irq_ack		= apic_ack_edge,
	.irq_set_affinity	= dmar_msi_set_affinity,
	.irq_retrigger		= apic_retrigger_irq,
};

int arch_setup_dmar_msi(unsigned int irq)
{
	struct msi_msg msg;
	struct irq_cfg *cfg = irq_cfg(irq);

	native_compose_msi_msg(cfg, &msg);
	dmar_msi_write(irq, &msg);
	irq_set_chip_and_handler_name(irq, &dmar_msi_type, handle_edge_irq,
				      "edge");
	return 0;
}

int dmar_alloc_hwirq(void)
{
	return irq_domain_alloc_irqs(NULL, 1, NUMA_NO_NODE, NULL);
}

void dmar_free_hwirq(int irq)
{
	irq_domain_free_irqs(irq, 1);
}
#endif

/*
 * MSI message composition
 */
#ifdef CONFIG_HPET_TIMER
static inline int hpet_dev_id(struct irq_domain *domain)
{
	return (int)(long)domain->host_data;
}

static int hpet_msi_set_affinity(struct irq_data *data,
				 const struct cpumask *mask, bool force)
{
	struct irq_data *parent = data->parent_data;
	struct msi_msg msg;
	int ret;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	/* No need to rewrite HPET registers if interrupt is remapped */
	if (ret >= 0 && !msi_irq_remapped(data)) {
		hpet_msi_read(data->handler_data, &msg);
		msi_update_msg(&msg, data);
		hpet_msi_write(data->handler_data, &msg);
	}

	return ret;
}

static struct irq_chip hpet_msi_type = {
	.name = "HPET_MSI",
	.irq_unmask = hpet_msi_unmask,
	.irq_mask = hpet_msi_mask,
	.irq_ack = irq_chip_ack_parent,
	.irq_set_affinity = hpet_msi_set_affinity,
	.irq_retrigger = irq_chip_retrigger_hierarchy,
	.irq_print_chip = irq_remapping_print_chip,
};

static int hpet_domain_alloc(struct irq_domain *domain, unsigned int virq,
			     unsigned int nr_irqs, void *arg)
{
	struct irq_alloc_info *info = arg;
	int ret;

	if (nr_irqs > 1 || !info || info->type != X86_IRQ_ALLOC_TYPE_HPET)
		return -EINVAL;
	if (irq_find_mapping(domain, info->hpet_index)) {
		pr_warn("IRQ for HPET%d already exists.\n", info->hpet_index);
		return -EEXIST;
	}

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, arg);
	if (ret >= 0) {
		irq_set_status_flags(virq, IRQ_MOVE_PCNTXT);
		irq_domain_set_hwirq_and_chip(domain, virq, info->hpet_index,
					      &hpet_msi_type, NULL);
		irq_set_handler_data(virq, info->hpet_data);
		__irq_set_handler(virq, handle_edge_irq, 0, "edge");
	}

	return ret;
}

static void hpet_domain_free(struct irq_domain *domain, unsigned int virq,
			     unsigned int nr_irqs)
{
	BUG_ON(nr_irqs > 1);
	msi_reset_irq_data_and_handler(domain, virq);
	irq_clear_status_flags(virq, IRQ_MOVE_PCNTXT);
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

static int hpet_domain_activate(struct irq_domain *domain,
				struct irq_data *irq_data)
{
	struct msi_msg msg;
	struct irq_cfg *cfg = irqd_cfg(irq_data);

	if (msi_irq_remapped(irq_data))
		irq_remapping_get_msi_entry(irq_data->parent_data, &msg);
	else
		native_compose_msi_msg(cfg, &msg);
	hpet_msi_write(irq_get_handler_data(irq_data->irq), &msg);

	return 0;
}

static int hpet_domain_deactivate(struct irq_domain *domain,
				  struct irq_data *irq_data)
{
	struct msi_msg msg;

	memset(&msg, 0, sizeof(msg));
	hpet_msi_write(irq_get_handler_data(irq_data->irq), &msg);

	return 0;
}

static struct irq_domain_ops hpet_domain_ops = {
	.alloc = hpet_domain_alloc,
	.free = hpet_domain_free,
	.activate = hpet_domain_activate,
	.deactivate = hpet_domain_deactivate,
};

struct irq_domain *hpet_create_irq_domain(int hpet_id)
{
	struct irq_domain *parent, *domain;
	struct irq_alloc_info info;
	bool remapped = false;

	init_irq_alloc_info(&info, NULL);
	info.type = X86_IRQ_ALLOC_TYPE_HPET;
	info.hpet_id = hpet_id;
	parent = irq_remapping_get_ir_irq_domain(&info);
	if (parent)
		remapped = true;
	else
		parent = x86_vector_domain;
	if (!parent)
		return NULL;

	domain = irq_domain_add_tree(NULL, &hpet_domain_ops,
				     (void *)(long)hpet_id);
	if (domain) {
		domain->parent = parent;
		if (remapped)
			irq_remapping_domain_set_remapped(domain);
	}

	return domain;
}

int hpet_assign_irq(struct irq_domain *domain, struct hpet_dev *dev,
		    int dev_num)
{
	struct irq_alloc_info info;

	init_irq_alloc_info(&info, NULL);
	info.type = X86_IRQ_ALLOC_TYPE_HPET;
	info.hpet_data = dev;
	info.hpet_id = hpet_dev_id(domain);
	info.hpet_index = dev_num;

	return irq_domain_alloc_irqs(domain, 1, NUMA_NO_NODE, NULL);
}
#endif
