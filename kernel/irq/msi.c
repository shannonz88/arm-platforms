/*
 * linux/kernel/irq/msi.c
 *
 * Copyright (C) 2014 Intel Corp.
 * Author: Jiang Liu <jiang.liu@linux.intel.com>
 *
 * This file is licensed under GPLv2.
 *
 * This file contains common code to support Message Signalled Interrupt for
 * PCI compatible and non PCI compatible devices.
 */
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>

#ifdef CONFIG_GENERIC_MSI_IRQ_DOMAIN
int msi_domain_set_affinity(struct irq_data *irq_data,
			    const struct cpumask *mask, bool force)
{
	struct irq_data *parent = irq_data->parent_data;
	struct msi_msg msg;
	int ret;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	if (ret >= 0 && ret != IRQ_SET_MASK_OK_DONE) {
		BUG_ON(irq_chip_compose_msi_msg(irq_data, &msg));
		irq_chip_write_msi_msg(irq_data, &msg);
	}

	return ret;
}

static void msi_domain_activate(struct irq_domain *domain,
				struct irq_data *irq_data)
{
	struct msi_msg msg;

	BUG_ON(irq_chip_compose_msi_msg(irq_data, &msg));
	irq_chip_write_msi_msg(irq_data, &msg);
}

static void msi_domain_deactivate(struct irq_domain *domain,
				  struct irq_data *irq_data)
{
	struct msi_msg msg;

	memset(&msg, 0, sizeof(msg));
	irq_chip_write_msi_msg(irq_data, &msg);
}

static int msi_domain_alloc(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs, void *arg)
{
	struct msi_domain_info *info = domain->host_data;
	struct msi_domain_ops *ops = info->ops;
	irq_hw_number_t hwirq = ops->get_hwirq(info, arg);
	int i, ret;

	if (irq_find_mapping(domain, hwirq) > 0)
		return -EEXIST;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, arg);
	if (ret < 0)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		ret = ops->msi_init(domain, info, virq + i, hwirq + i, arg);
		if (ret < 0) {
			if (ops->msi_free) {
				for (i--; i > 0; i--)
					ops->msi_free(domain, info, virq + i);
			}
			irq_domain_free_irqs_top(domain, virq, nr_irqs);
			return ret;
		}
	}

	return 0;
}

static void msi_domain_free(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs)
{
	struct msi_domain_info *info = domain->host_data;
	int i;

	if (info->ops->msi_free) {
		for (i = 0; i < nr_irqs; i++)
			info->ops->msi_free(domain, info, virq + i);
	}
	irq_domain_free_irqs_top(domain, virq, nr_irqs);
}

static struct irq_domain_ops msi_domain_ops = {
	.alloc		= msi_domain_alloc,
	.free		= msi_domain_free,
	.activate	= msi_domain_activate,
	.deactivate	= msi_domain_deactivate,
};

struct irq_domain *msi_create_irq_domain(struct device_node *of_node,
					 struct msi_domain_info *info,
					 struct irq_domain *parent)
{
	struct irq_domain *domain;

	domain = irq_domain_add_tree(of_node, &msi_domain_ops, info);
	if (domain)
		domain->parent = parent;

	return domain;
}

struct msi_domain_info *msi_get_domain_info(struct irq_domain *domain)
{
	return (struct msi_domain_info *)domain->host_data;
}

#endif /* CONFIG_GENERIC_MSI_IRQ_DOMAIN */
