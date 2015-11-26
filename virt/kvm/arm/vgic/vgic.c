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
#include <linux/list_sort.h>

#include "vgic.h"

/*
 * Locking order is always:
 *   vgic_cpu->ap_list_lock
 *     vgic_irq->irq_lock
 *
 * (that is, always take the ap_list_lock before the struct vgic_irq lock).
 *
 * When taking more than one ap_list_lock at the same time, always take the
 * lowest numbered VCPU's ap_list_lock first, so:
 *   vcpuX->vcpu_id < vcpuY->vcpu_id:
 *     spin_lock(vcpuX->vgic_cpu.ap_list_lock);
 *     spin_lock(vcpuY->vgic_cpu.ap_list_lock);
 */

static inline struct vgic_irq *vgic_its_get_lpi(struct kvm *kvm, u32 intid)
{
	return NULL;
}

struct vgic_irq *vgic_get_irq(struct kvm *kvm, struct kvm_vcpu *vcpu,
			      u32 intid)
{
	if (intid <= VGIC_MAX_PRIVATE) {
		/* SGIs and PPIs */
		return &vcpu->arch.vgic_cpu.private_irqs[intid];
	} else if (intid <= VGIC_MAX_SPI) {
		/* SPIs */
		return &kvm->arch.vgic.spis[intid - VGIC_NR_PRIVATE_IRQS];
	} else if (intid <= VGIC_MAX_RESERVED) {
		/* Reserved */
		WARN(1, "Looking up struct vgic_irq for reserved INTID");
		return NULL;
	} else {
		/*
		 * TODO: The ITS function should return null if it doesn't
		 * find an IRQ struct or if the intid is out of bounds.
		 */
		return vgic_its_get_lpi(kvm, intid);
	}
}

/*
 * The order of items in the ap_lists defines how we'll pack things in LRs as
 * well, the first items in the list being the first things populated in the
 * LRs.
 *
 * A hard rule is that active interrupts can never be pushed out of the LRs
 * (and therefore take priority) since we cannot reliably trap on deactivation
 * if IRQs and therefore they have to be present in the LRs.
 *
 * Otherwise things should be sorted by the priority field and the GIC
 * hardware support will take care of preemption of priority groups etc.
 *
 * Return negative is a sorts before b, 0 to preserve order, and positive to
 * sort b before a.
 */
static int vgic_irq_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct vgic_irq *irqa = container_of(a, struct vgic_irq, ap_list);
	struct vgic_irq *irqb = container_of(b, struct vgic_irq, ap_list);
	int ret;

	spin_lock(&irqa->irq_lock);
	spin_lock(&irqb->irq_lock);

	if (irqa->active || irqb->active) {
		ret = (int)irqb->active - (int)irqa->active;
		goto out;
	}

	BUG_ON(!irqa->pending || !irqb->pending);

	if (!irqa->enabled || !irqb->enabled) {
		ret = (int)irqb->enabled - (int)irqa->enabled;
		goto out;
	}

	/* Both pending and enabled, sort by priority */
	ret = irqa->priority - irqb->priority;
out:
	spin_unlock(&irqb->irq_lock);
	spin_unlock(&irqa->irq_lock);
	return ret;
}

/* Must be called with the ap_list_lock held */
static void vgic_sort_ap_list(struct kvm_vcpu *vcpu)
{
	list_sort(NULL, &vcpu->arch.vgic_cpu.ap_list_head, vgic_irq_cmp);
}

/*
 * Only valid injection if changing level for level-triggered IRQs or for a
 * rising edge.
 */
static bool vgic_validate_injection(struct vgic_irq *irq, bool level)
{
	switch (irq->config) {
	case VGIC_CONFIG_LEVEL:
		return irq->line_level != level;
	case VGIC_CONFIG_EDGE:
		return level;
	default:
		BUG();
	}
}

static void vgic_update_irq_pending(struct kvm *kvm, struct kvm_vcpu *vcpu,
				    u32 intid, bool level)
{
	struct vgic_irq *irq = vgic_get_irq(kvm, vcpu, intid);

	BUG_ON(in_interrupt());

retry:
	spin_lock(&irq->irq_lock);

	if (!vgic_validate_injection(irq, level)) {
		/* Nothing to see here, move along... */
		spin_unlock(&irq->irq_lock);
		return;
	}

	if (irq->vcpu) {
		/*
		 * We do not need to take any ap_list_lock here because this
		 * irq cannot be moved or modified and the vcpu pointer will
		 * remain constant for as long as we hold the irq_lock.
		 */
		irq->pending = true;
		spin_unlock(&irq->irq_lock);
	} else {
		struct kvm_vcpu *vcpu = irq->target_vcpu;

		/*
		 * We must unlock the irq lock to take the ap_list_lock where
		 * we are going to insert this new pending interrupt.
		 */
		spin_unlock(&irq->irq_lock);

		/* someone can do stuff here, which we re-check below */

		spin_lock(&vcpu->arch.vgic_cpu.ap_list_lock);
		spin_lock(&irq->irq_lock);

		/*
		 * Did something change behind our backs?
		 *
		 * There are two cases:
		 * 1) The irq got assigned pending or active behind our backs
		 *    and set the irq->vcpu field when linking it into an
		 *    ap_list
		 * 2) Someone changed the affinity on this irq behind our
		 *    backs and we are now holding the wrong ap_list_lock.
		 *
		 * In both cases, drop locks and simply retry.
		 */
		if (irq->vcpu || irq->target_vcpu != vcpu) {
			spin_unlock(&irq->irq_lock);
			spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);
			goto retry;
		}

		list_add_tail(&irq->ap_list, &vcpu->arch.vgic_cpu.ap_list_head);
		irq->pending = true;
		irq->vcpu = vcpu;

		spin_unlock(&irq->irq_lock);
		spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);
	}
}

/**
 * kvm_vgic_inject_irq - Inject an IRQ from a device to the vgic
 * @kvm:     The VM structure pointer
 * @cpuid:   The CPU for PPIs
 * @irq_num: The INTID to inject a new state to.
 *           must not be mapped to a HW interrupt.
 * @level:   Edge-triggered:  true:  to trigger the interrupt
 *			      false: to ignore the call
 *	     Level-sensitive  true:  raise the input signal
 *			      false: lower the input signal
 *
 * The GIC is not concerned with devices being active-LOW or active-HIGH for
 * level-sensitive interrupts.  You can think of the level parameter as 1
 * being HIGH and 0 being LOW and all devices being active-HIGH.
 */
int kvm_vgic_inject_irq(struct kvm *kvm, int cpuid, unsigned int intid,
			bool level)
{
	struct kvm_vcpu *vcpu;

#if 0
	ret = vgic_lazy_init(kvm);
	if (ret)
		return ret;
#endif

	vcpu = kvm_get_vcpu(kvm, cpuid);
	vgic_update_irq_pending(kvm, vcpu, intid, level);
	return 0;
}
