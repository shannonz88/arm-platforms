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

/*
 * WARNING: The blurb below assumes that you understand the
 * intricacies of GICv3, GICv4, and how a guest's view of a GICv3 gets
 * translated into GICv4 commands. So it effectively targets at most
 * two individuals. You know who you are.
 *
 * The core GICv4 code is designed to *avoid* exposing too much of the
 * core GIC code (that would in turn leak into the hypervisor code),
 * and instead provide a hypervisor agnostic interface to the HW (of
 * course, the astute reader will quickly realize that hypervisor
 * agnostic actually means KVM-specific - what were you thinking?).
 *
 * In order to achieve a modicum of isolation, we try to hide most of
 * the GICv4 "stuff" behind normal irqchip operations:
 *
 * - Any guest-visible VLPI is backed by a Linux interrupt (and a
 *   physical LPI which gets unmapped when the guest maps the
 *   VLPI). This allows the same DevID/EventID pair to be either
 *   mapped to the LPI (host) or the VLPI (guest).
 *
 * - Enabling/disabling a VLPI is done by issuing mask/unmask calls.
 *
 * - Guest INT/CLEAR commands are implemented through
 *   irq_set_irqchip_state().
 *
 * - The *bizarre* stuff (mapping/unmapping an interrupt to a VLPI, or
 *   issuing an INV after changing a priority) gets shoved into the
 *   irq_set_vcpu_affinity() method. While this is quite horrible
 *   (let's face it, this is the irqchip version of an ioctl), it
 *   confines the crap to a single location. And map/unmap really is
 *   about setting the affinity of a VLPI to a vcpu, so only INV is
 *   majorly out of place. So there.
 *
 * But handling VLPIs is only one side of the job of the GICv4
 * code. The other (darker) side is to take care of the doorbell
 * interrupts which are delivered when a VLPI targeting a non-running
 * vcpu is being made pending.
 *
 * The choice made here is that each vcpu (VPE in old northern GICv4
 * dialect) gets a single doorbell LPI, no matter how many interrupts
 * are targeting it. This has a nice property, which is that the
 * interrupt becomes a handle for the VPE, and that the hypervisor
 * code can manipulate it through the normal interrupt API:
 *
 * - VMs (or rather the VM abstraction that matters to the GIC)
 *   contain an irq domain where each interrupt maps to a VPE. In
 *   turn, this domain sits on top of the normal LPI allocator, and a
 *   specially crafted irq_chip implementation.
 *
 * - mask/unmask do what is expected on the doorbell interrupt.
 *
 * - irq_set_affinity is used to move a VPE from one redistributor to
 *   another.
 *
 * - irq_set_vcpu_affinity once again gets hijacked for the purpose of
 *   creating a new sub-API, namely scheduling/descheduling a VPE
 *   (which involves programming GICR_V{PROP,PEND}BASER) and
 *   performing INVALL operations.
 */

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

static int its_send_vpe_cmd(struct its_vpe *vpe, struct its_cmd_info *info)
{
	unsigned int irq;
	irq_hw_number_t hwirq;

	WARN_ON(preemptible());

	hwirq = vpe->vpe_db_lpi - vpe->its_vm->db_lpi_base;
	irq = irq_find_mapping(vpe->its_vm->domain, hwirq);

	return irq_set_vcpu_affinity(irq, info);
}

int its_schedule_vpe(struct its_vpe *vpe, bool on)
{
	struct its_cmd_info info;

	info.cmd_type = on ? SCHEDULE_VPE : DESCHEDULE_VPE;

	return its_send_vpe_cmd(vpe, &info);
}

int its_invall_vpe(struct its_vpe *vpe)
{
	struct its_cmd_info info = {
		.cmd_type = INVALL_VPE,
	};

	return its_send_vpe_cmd(vpe, &info);
}

int its_map_vlpi(int irq, struct its_vlpi_map *map)
{
	struct its_cmd_info info = {
		.cmd_type = MAP_VLPI,
		.map      = map,
	};

	return irq_set_vcpu_affinity(irq, &info);
}

int its_unmap_vlpi(int irq)
{
	struct its_cmd_info info = {
		.cmd_type = UNMAP_VLPI,
	};

	return irq_set_vcpu_affinity(irq, &info);
}

int its_prop_update_vlpi(int irq, u8 config)
{
	struct its_cmd_info info = {
		.cmd_type = PROP_UPDATE_VLPI,
		.config   = config,
	};

	return irq_set_vcpu_affinity(irq, &info);
}
