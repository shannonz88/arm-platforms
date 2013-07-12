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
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include <linux/irqchip/arm-gic-v3.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

/* These are for GICv2 emulation only */
#define GICH_LR_VIRTUALID		(0x3ffUL << 0)
#define GICH_LR_PHYSID_CPUID_SHIFT	(10)
#define GICH_LR_PHYSID_CPUID		(7UL << GICH_LR_PHYSID_CPUID_SHIFT)

static u32 ich_vtr_el2;

static int vgic_v3_get_lr_irq(const struct kvm_vcpu *vcpu, int lr)
{
	return vcpu->arch.vgic_cpu.vgic_v3.vgic_lr[lr] & GICH_LR_VIRTUALID;
}

#define MK_LR_PEND(src, irq)	\
	(GICH_LR_PENDING_BIT | \
	 (((u32)(src)) << GICH_LR_PHYSID_CPUID_SHIFT) | (irq))

static void vgic_v3_build_lr(struct kvm_vcpu *vcpu, u8 source_id,
			     int irq, int lr, bool is_edge)
{
	u64 lr_val = MK_LR_PEND(source_id, irq);

	/*
	 * If an interrupt is already active, preserve the active bit.
	 * Only an edge interrupt can be both active and pending, so
	 * skip the test in this case.
	 */
	if (vcpu->arch.vgic_cpu.vgic_v3.vgic_lr[lr] & GICH_LR_ACTIVE_BIT) {
		lr_val |= GICH_LR_ACTIVE_BIT;
	} else {
		if (!is_edge)
			lr_val |= GICH_LR_EOI;
	}

	vcpu->arch.vgic_cpu.vgic_v3.vgic_lr[lr] = lr_val;
}

static bool vgic_v3_match_lr_source_id(const struct kvm_vcpu *vcpu,
				       int lr, u8 source_id)
{
	u64 val = vcpu->arch.vgic_cpu.vgic_v3.vgic_lr[lr];
	val = (val & GICH_LR_PHYSID_CPUID) >> GICH_LR_PHYSID_CPUID_SHIFT;
	return val == source_id;
}

static void vgic_v3_clear_lr_state(struct kvm_vcpu *vcpu, int lr)
{
	u64 bits = GICH_LR_STATE | GICH_LR_EOI;

	vcpu->arch.vgic_cpu.vgic_v3.vgic_lr[lr] &= ~bits;

	/*
	 * Despite being EOIed, the LR may not have been marked as
	 * empty.
	 */
	vcpu->arch.vgic_cpu.vgic_v3.vgic_elrsr |= (1U << lr);
}

static u64 vgic_v3_get_elrsr(const struct kvm_vcpu *vcpu)
{
	return vcpu->arch.vgic_cpu.vgic_v3.vgic_elrsr;
}

static u64 vgic_v3_get_eisr(const struct kvm_vcpu *vcpu)
{
	return vcpu->arch.vgic_cpu.vgic_v3.vgic_eisr;
}

static u32 vgic_v3_get_interrupt_status(const struct kvm_vcpu *vcpu)
{
	u32 misr = vcpu->arch.vgic_cpu.vgic_v3.vgic_misr;
	u32 ret = 0;

	if (misr & GICH_MISR_EOI)
		ret |= INT_STATUS_EOI;
	if (misr & GICH_MISR_U)
		ret |= INT_STATUS_UNDERFLOW;

	return ret;
}

static void vgic_v3_set_underflow(struct kvm_vcpu *vcpu)
{
	vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr |= GICH_HCR_UIE;
}

static void vgic_v3_clear_underflow(struct kvm_vcpu *vcpu)
{
	vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr &= ~GICH_HCR_UIE;
}

static void vgic_v3_enable(struct kvm_vcpu *vcpu)
{
	/*
	 * By forcing VMCR to zero, the GIC will restore the binary
	 * points to their reset values. Anything else resets to zero
	 * anyway.
	 */
	vcpu->arch.vgic_cpu.vgic_v3.vgic_vmcr = 0;

	/* Get the show on the road... */
	vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr = GICH_HCR_EN;
}

static const struct vgic_ops vgic_v3_ops = {
	.get_lr_irq		= vgic_v3_get_lr_irq,
	.build_lr		= vgic_v3_build_lr,
	.match_lr_source_id	= vgic_v3_match_lr_source_id,
	.clear_lr_state		= vgic_v3_clear_lr_state,
	.get_elrsr		= vgic_v3_get_elrsr,
	.get_eisr		= vgic_v3_get_eisr,
	.get_interrupt_status	= vgic_v3_get_interrupt_status,
	.set_underflow		= vgic_v3_set_underflow,
	.clear_underflow	= vgic_v3_clear_underflow,
	.enable			= vgic_v3_enable,
};

static struct vgic_params vgic_v3_params;

int vgic_v3_probe(const struct vgic_ops **ops,
		  const struct vgic_params **params)
{
	int ret = 0;
	u32 gicv_idx;
	struct resource vcpu_res;
	struct device_node *vgic_node;
	struct vgic_params *vgic = &vgic_v3_params;

	vgic_node = of_find_compatible_node(NULL, NULL, "arm,gic-v3");
	if (!vgic_node) {
		kvm_err("error: no compatible GICv3 node in DT\n");
		return -ENODEV;
	}

	vgic->maint_irq = irq_of_parse_and_map(vgic_node, 0);
	if (!vgic->maint_irq) {
		kvm_err("error getting vgic maintenance irq from DT\n");
		ret = -ENXIO;
		goto out;
	}

	ich_vtr_el2 = kvm_call_hyp(__vgic_v3_get_ich_vtr_el2);

	/*
	 * The ListRegs field is 5 bits, but there is a architectural
	 * maximum of 16 list registers. Just ignore bit 4...
	 */
	vgic->nr_lr = (ich_vtr_el2 & 0xf) + 1;

	if (of_property_read_u32(vgic_node, "redist-regions", &gicv_idx))
		gicv_idx = 1;

	gicv_idx += 3; /* Also skip GICD, GICC, GICH */
	if (of_address_to_resource(vgic_node, gicv_idx, &vcpu_res)) {
		kvm_err("Cannot obtain GICV region\n");
		ret = -ENXIO;
		goto out;
	}
	vgic->vcpu_base = vcpu_res.start;
	vgic->vctrl_base = (void *)(-1);
	vgic->type = VGIC_V3;

	kvm_info("%s@%llx IRQ%d\n", vgic_node->name,
		 vcpu_res.start, vgic->maint_irq);

	*ops = &vgic_v3_ops;
	*params = vgic;

out:
	of_node_put(vgic_node);
	return ret;
}
