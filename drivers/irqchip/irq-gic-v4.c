/*
 * Copyright (C) 2016 ARM Limited, All Rights Reserved.
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

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>

#include <linux/irqchip/arm-gic-v4.h>

static struct irq_domain *its_vpe_domain;

static struct irq_chip its_vcpu_irq_chip = {
	.name			= "GICv4-vcpu",
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.irq_set_vcpu_affinity	= irq_chip_set_vcpu_affinity_parent,
};

static int its_vcpu_irq_domain_alloc(struct irq_domain *domain,
				     unsigned int virq,
				     unsigned int nr_irqs, void *args)
{
	msi_alloc_info_t info;
	struct its_vpe **vpes = args;
	int err, i;

	info.desc = NULL;
	info.scratchpad[0].ptr = vpes;

	/* Allocate LPIs at the redistributor level */
	err = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, &info);
	if (err)
		return err;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_hwirq_and_chip(domain, virq + i, i,
					      &its_vcpu_irq_chip, vpes[i]);
	}

	return 0;
}

static void its_vcpu_irq_domain_free(struct irq_domain *domain,
				     unsigned int virq,
				     unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *data = irq_domain_get_irq_data(domain,
								virq + i);

		irq_domain_reset_irq_data(data);
	}

	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

static const struct irq_domain_ops vcpu_domain_ops = {
	.alloc	= its_vcpu_irq_domain_alloc,
	.free	= its_vcpu_irq_domain_free,
};

int its_alloc_vcpu_irqs(struct its_vm *vm, struct its_vpe **vpes, int nr_vpes)
{
	int vpe_base_irq, i;

	vm->domain = irq_domain_create_hierarchy(its_vpe_domain, 0, nr_vpes,
						 NULL, &vcpu_domain_ops,
						 vpes);
	if (!vm->domain)
		return -ENOMEM;

	for (i = 0; i < nr_vpes; i++) {
		vpes[i]->its_vm = vm;
		vpes[i]->idai = true;
	}

	vpe_base_irq = __irq_domain_alloc_irqs(vm->domain, -1, nr_vpes,
					       NUMA_NO_NODE, vpes,
					       false, NULL);
	return vpe_base_irq;
}

void its_free_vcpu_irqs(struct its_vm *vm, int nr_vpes)
{
	unsigned int irq;

	irq = irq_find_mapping(vm->domain, 0);
	if (!irq)
		return;

	irq_domain_free_irqs(irq, nr_vpes);
}
