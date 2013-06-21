/*
 * Copyright (C) 2012,2013 ARM Limited, All Rights Reserved.
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
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include <linux/irqchip/arm-gic.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

static int vgic_v2_get_lr_irq(const struct kvm_vcpu *vcpu, int lr)
{
	return vcpu->arch.vgic_cpu.vgic_v2.vgic_lr[lr] & GICH_LR_VIRTUALID;
}

#define MK_LR_PEND(src, irq)	\
	(GICH_LR_PENDING_BIT | ((src) << GICH_LR_PHYSID_CPUID_SHIFT) | (irq))

static void vgic_v2_build_lr(struct kvm_vcpu *vcpu, u8 source_id,
			     int irq, int lr, bool is_edge)
{
	u32 lr_val = MK_LR_PEND(source_id, irq);

	/*
	 * If an interrupt is already active, preserve the active bit.
	 * Only an edge interrupt can be both active and pending, so
	 * skip the test in this case.
	 */
	if (vcpu->arch.vgic_cpu.vgic_v2.vgic_lr[lr] & GICH_LR_ACTIVE_BIT) {
		lr_val |= GICH_LR_ACTIVE_BIT;
	} else {
		if (!is_edge)
			lr_val |= GICH_LR_EOI;
	}

	vcpu->arch.vgic_cpu.vgic_v2.vgic_lr[lr] = lr_val;
}

static bool vgic_v2_match_lr_source_id(const struct kvm_vcpu *vcpu,
				       int lr, u8 source_id)
{
	u32 val = vcpu->arch.vgic_cpu.vgic_v2.vgic_lr[lr];
	val = (val & GICH_LR_PHYSID_CPUID) >> GICH_LR_PHYSID_CPUID_SHIFT;
	return val == source_id;
}

static void vgic_v2_clear_lr_state(struct kvm_vcpu *vcpu, int lr)
{
	u32 bits = GICH_LR_STATE | GICH_LR_EOI;
	vcpu->arch.vgic_cpu.vgic_v2.vgic_lr[lr] &= ~bits;

	/*
	 * Despite being EOIed, the LR may not have been marked as
	 * empty.
	 */
	set_bit(lr, (unsigned long *)vcpu->arch.vgic_cpu.vgic_v2.vgic_elrsr);
}

static u64 vgic_v2_get_elrsr(const struct kvm_vcpu *vcpu)
{
	const u32 *elrsr = vcpu->arch.vgic_cpu.vgic_v2.vgic_elrsr;
	return *(u64 *)elrsr;
}

static u64 vgic_v2_get_eisr(const struct kvm_vcpu *vcpu)
{
	const u32 *eisr = vcpu->arch.vgic_cpu.vgic_v2.vgic_eisr;
	return *(u64 *)eisr;
}

static u32 vgic_v2_get_interrupt_status(const struct kvm_vcpu *vcpu)
{
	u32 misr = vcpu->arch.vgic_cpu.vgic_v2.vgic_misr;
	u32 ret = 0;

	if (misr & GICH_MISR_EOI)
		ret |= INT_STATUS_EOI;
	if (misr & GICH_MISR_U)
		ret |= INT_STATUS_UNDERFLOW;

	return ret;
}

static void vgic_v2_set_underflow(struct kvm_vcpu *vcpu)
{
	vcpu->arch.vgic_cpu.vgic_v2.vgic_hcr |= GICH_HCR_UIE;
}

static void vgic_v2_clear_underflow(struct kvm_vcpu *vcpu)
{
	vcpu->arch.vgic_cpu.vgic_v2.vgic_hcr &= ~GICH_HCR_UIE;
}

static void vgic_v2_enable(struct kvm_vcpu *vcpu)
{
	/*
	 * By forcing VMCR to zero, the GIC will restore the binary
	 * points to their reset values. Anything else resets to zero
	 * anyway.
	 */
	vcpu->arch.vgic_cpu.vgic_v2.vgic_vmcr = 0;

	/* Get the show on the road... */
	vcpu->arch.vgic_cpu.vgic_v2.vgic_hcr = GICH_HCR_EN;
}

static const struct vgic_ops vgic_v2_ops = {
	.get_lr_irq		= vgic_v2_get_lr_irq,
	.build_lr		= vgic_v2_build_lr,
	.match_lr_source_id	= vgic_v2_match_lr_source_id,
	.clear_lr_state		= vgic_v2_clear_lr_state,
	.get_elrsr		= vgic_v2_get_elrsr,
	.get_eisr		= vgic_v2_get_eisr,
	.get_interrupt_status	= vgic_v2_get_interrupt_status,
	.set_underflow		= vgic_v2_set_underflow,
	.clear_underflow	= vgic_v2_clear_underflow,
	.enable			= vgic_v2_enable,
};

static struct vgic_params vgic_v2_params;

int vgic_v2_probe(const struct vgic_ops **ops,
		  const struct vgic_params **params)
{
	int ret;
	struct resource vctrl_res;
	struct resource vcpu_res;
	struct device_node *vgic_node;
	struct vgic_params *vgic = &vgic_v2_params;

	vgic_node = of_find_compatible_node(NULL, NULL, "arm,cortex-a15-gic");
	if (!vgic_node) {
		kvm_err("error: no compatible GICv2 node in DT\n");
		return -ENODEV;
	}

	vgic->maint_irq = irq_of_parse_and_map(vgic_node, 0);
	if (!vgic->maint_irq) {
		kvm_err("error getting vgic maintenance irq from DT\n");
		ret = -ENXIO;
		goto out;
	}

	ret = of_address_to_resource(vgic_node, 2, &vctrl_res);
	if (ret) {
		kvm_err("Cannot obtain GICH resource\n");
		goto out;
	}

	vgic->vctrl_base = of_iomap(vgic_node, 2);
	if (!vgic->vctrl_base) {
		kvm_err("Cannot ioremap GICH\n");
		ret = -ENOMEM;
		goto out;
	}

	vgic->nr_lr = readl_relaxed(vgic->vctrl_base + GICH_VTR);
	vgic->nr_lr = (vgic->nr_lr & 0x3f) + 1;

	ret = create_hyp_io_mappings(vgic->vctrl_base,
				     vgic->vctrl_base + resource_size(&vctrl_res),
				     vctrl_res.start);
	if (ret) {
		kvm_err("Cannot map VCTRL into hyp\n");
		goto out_unmap;
	}

	if (of_address_to_resource(vgic_node, 3, &vcpu_res)) {
		kvm_err("Cannot obtain GICV resource\n");
		ret = -ENXIO;
		goto out_unmap;
	}
	vgic->vcpu_base = vcpu_res.start;

	kvm_info("%s@%llx IRQ%d\n", vgic_node->name,
		 vctrl_res.start, vgic->maint_irq);

	vgic->type = VGIC_V2;
	*ops = &vgic_v2_ops;
	*params = vgic;
	goto out;

out_unmap:
	iounmap(vgic->vctrl_base);
out:
	of_node_put(vgic_node);
	return ret;
}
