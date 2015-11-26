/*
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
 * along with this program; if not, write to the Free Software
 * Foundation.
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include "vgic.h"

/*
 * Call this function to convert a u64 value to an unsigned long * bitmask
 * in a way that works on both 32-bit and 64-bit LE and BE platforms.
 *
 * Warning: Calling this function may modify *val.
 */
static unsigned long *u64_to_bitmask(u64 *val)
{
#if defined(CONFIG_CPU_BIG_ENDIAN) && BITS_PER_LONG == 32
	*val = (*val >> 32) | (*val << 32);
#endif
	return (unsigned long *)val;
}

void void vgic_v2_process_maintenance(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpuif = &vcpu->arch.vgic_cpu.vgic_v2;

	if (cpuif->misr & GICH_MISR_EOI) {
		u64 eisr = cpuif->vgic_eisr;
		unsigned long *eisr_bmap = u64_to_bitmask(&eisr);
		int lr;

		for_each_set_bit(lr, eisr_bmap, vgic_global_info.nr_lr) {
			struct vgic_irq *irq;
			u32 intid = cpuif->vgic_lr[lr] & GICH_LR_VIRTUALID;
			irq = vgic_get_irq(vcpu->kvm, vcpu, intid);

			WARN_ON(irq->config == VGIC_CONFIG_EDGE);
			WARN_ON(cpuif->vgic_lr[lr] & GICH_LR_STATE);

			/*
			 * kvm_notify_acked_irq calls kvm_set_irq()
			 * to reset the IRQ level, which grabs the dist->lock
			 * so we call this before taking the dist->lock.
			 */
			kvm_notify_acked_irq(kvm, 0,
					     intid - VGIC_NR_PRIVATE_IRQS);

			cpuif->vgic_lr[lr] &= ~GICH_LR_STATE; /* Useful?? */
			cpuif->vgic_elrsr |= 1ULL << lr;
		}
	}

	if (cpuif->misr & GICH_MISR_U)
		cpuif->vgic_hcr &= ~GICH_HCR_UIE;

	/*
	 * In the next iterations of the vcpu loop, if we sync the
	 * vgic state after flushing it, but before entering the guest
	 * (this happens for pending signals and vmid rollovers), then
	 * make sure we don't pick up any old maintenance interrupts
	 * here.
	 */
	cpuif->vgic_eisr = 0;
}

void vgic_v2_fold_lr_state(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpuif = &vcpu->arch.vgic_cpu.vgic_v2;
	int lr;

	/* Assumes ap_list_lock held */

	for (lr = 0; lr < vcpu->arch.vgic_cpu.used_lrs; lr++) {
		u32 val = cpuif->vgic_lr[lr];
		u32 intid = val & GICH_LR_VIRTUALID;
		struct vgic_irq *irq;

		irq = vgic_get_irq(vcpu->kvm, vcpu, intid);

		spin_lock(&irq->irq_lock);

		/* Always preserve the active bit */
		irq->active = !!(val & GICH_LR_ACTIVE_BIT);

		/* Edge is the only case where we preserve the pending bit */
		if (irq->config == VGIC_CONFIG_EDGE &&
		    (val & GICH_LR_PENDING_BIT)) {
				irq->pending = true;

				if (intid < VGIC_NR_SGIS) {
					u32 cpuid = val & GICH_LR_PHYSID_CPUID;
					cpuid >>= GICH_LR_PHYSID_CPUID_SHIFT;
					irq->source |= (1 << cpuid);
				}
		}

		spin_unlock(&irq->irq_lock);
	}
}

void vgic_v2_populate_lrs(struct kvm_vcpu *vcpu)
{
	struct vgic_irq *irq;
	int count = 0;

	list_for_each_entry(irq, &vcpu->arch.vgic_cpu.ap_list, ap_list) {
		u32 val;

		spin_lock(&irq->irq_lock);

		val = irq->intid;

		if (irq->pending) {
			val |= GICH_LR_PENDING_BIT;
			if (irq->config == VGIC_CONFIG_EDGE)
				irq->pending = false;
		}

		if (irq->active)
			val |= GICH_LR_ACTIVE_BIT;

		if (irq->hw) {
			val |= GICH_LR_HW;
			val |= irq->hwirq << GICH_LR_PHYSID_CPUID_SHIFT;
		} else {
			if (irq->config == VGIC_CONFIG_LEVEL)
				val |= GICH_LR_EOI;
		}

		if (irq->intid < VGIC_NR_SGIS)
			val |= irq->source << GICH_LR_PHYSID_CPUID_SHIFT;

		vcpu->arch.vgic_cpu.vgic_v2.vgic_lr[count++] = val;
		spin_unlock(&irq->irq_lock);

		if (count == vcpu->kvm->arch.vgic.nr_lr)
			break;
	}

	vcpu->arch.vgic_cpu.used_lrs = count;
}

/* Use lower byte as target bitmap for gicv2 */
void vgic_v2_irq_change_affinity(struct kvm *kvm, u32 intid, u8 new_targets)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct vgic_irq *irq;
	int target;

	BUG_ON(intid <= VGIC_MAX_PRIVATE);
	BUG_ON(dist->vgic_model != KVM_DEV_TYPE_ARM_VGIC_V2);

	irq = vgic_get_irq(kvm, NULL, intid);

	spin_lock(&irq->irq_lock);
	irq->targets = new_targets;

	target = ffs(irq->targets);
	target = target ? (target - 1) : 0;
	irq->target_vcpu = kvm_get_vcpu(kvm, target);
	spin_unlock(&irq->irq_lock);
}

