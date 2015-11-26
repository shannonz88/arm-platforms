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
 *     spin_lock(vcpuX->arch.vgic_cpu.ap_list_lock);
 *     spin_lock(vcpuY->arch.vgic_cpu.ap_list_lock);
 */

static inline struct vgic_irq *vgic_its_get_lpi(struct kvm *kvm, u32 intid)
{
	return NULL;
}

static struct vgic_irq *vgic_get_irq(struct kvm *kvm, struct kvm_vcpu *vcpu,
				     u32 intid)
{
	if (intid <= VGIC_MAX_PRIVATE)
		/* SGIs and PPIs */
		return &vcpu->vgic_cpu.private_irqs[intid];
	else if (intid <= VGIC_MAX_SPI)
		/* SPIs */
		return &kvm->arch->dist.spis[intid - VGIC_NR_PRIVATE_IRQS];
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

/* Use lower byte as target bitmap for gicv2 */
static void irq_change_affinity(struct kvm *kvm, u32 intid, u32 new_affinity)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	struct vgic_irq *irq;
	
	BUG_ON(intid <= VGIC_MAX_PRIVATE);
	irq = vgic_get_irq(kvm, NULL, intid);
	spin_lock(irq->irq_lock);
	if (dist->vgic_model == KVM_DEV_TYPE_ARM_VGIC_V2)
		irq->targets = new_affinity;
	else
		irq->affinity = new_affinity;
	spin_unlock(irq->irq_lock);
}

static struct kvm_vcpu *affinity_to_vcpu(struct kvm *kvm, struct vgic_irq *irq)
{
	struct vgic_dist *dist = &kvm->arch.vgic;

	if (dist->vgic_model == KVM_DEV_TYPE_ARM_VGIC_V2) {
		int vcpu_id;
		vcpu_id = ffs(irq->targets);
		vcpu_id = vcpu_id ? (target - 1) : 0;
		return kvm_get_vcpu(kvm, vcpu_id);
	} else {
		unsigned long mpidr;
		mpidr = uncompress_mpidr(irq->affinity);
		return kvm_mpidr_to_vcpu(kvm, mpidr);
	}
}

/* Must be called with the ap_list_lock and irq_lock held */
static int vgic_insert_irq_sorted(struct vgic_irq *irq, struct kvm_vcpu *vcpu)
{
	/* TODO: Implement */
	WARN(1, "Unimplemented function\n");
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
	}
}

static void vgic_update_irq_pending(struct kvm *kvm, struct kvm_vcpu *vcpu,
				    u32 intid, bool level)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
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
		struct kvm_vcpu *vcpu = affinity_to_vcpu(kvm, irq);

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
		if (irq->vcpu || affinity_to_vcpu(kvm, irq) != vcpu) {
			spin_unlock(&irq->irq_lock);
			spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);
			goto retry;
		}

		vgic_insert_irq_sorted(irq, vcpu);
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
	struct irq_phys_map *map;
	struct kvm_vcpu *vcpu;
	int ret;

#if 0
	ret = vgic_lazy_init(kvm);
	if (ret)
		return ret;
#endif

	vcpu = kvm_get_vcpu(kvm, cpuid);
	return vgic_update_irq_pending(kvm, cpuid, irq_num, level);
}

/* Tell me where things should go */
static struct vcpu *vgic_target_oracle(struct kvm *kvm, struct vgic_irq *irq)
{
	/* Assume irq is locked */
	if (!((irq->enabled && irq->pending) || irq->active))
		return NULL;

	return affinity_to_vcpu(kvm, irq);
}

/**
 * vgic_prune_ap_list - Remove non-relevant interrupts from the list
 *
 * @vcpu: The VCPU pointer
 *
 * Go over the list of "interesting" interrupts, and prune those that we
 * won't have to consider in the near future.
 */
static void vgic_prune_ap_list(struct kvm_vcpu *vcpu)
{
	struct vgic_irq *irq, *tmp;

retry:
	spin_lock(&vcpu->arch.vgic_cpu.ap_list_lock);

	list_for_each_entry_safe(irq, tmp, &vcpu->vgic_cpu.ap_list, ap_list) {
		struct kvm_vcpu *target_vcpu, *vpcuA, *vcpuB;

		spin_lock(&irq->irq_lock);

		BUG_ON(vcpu != irq->vcpu);

		target_vcpu = vgic_target_oracle(vpcu->kvm, irq);

		if (!target_vcpu) {
			/* We don't need to process this interrupt any
			 * further, move it off the list */
			list_del_init(irq->ap_list);
			spin_unlock(&irq->irq_lock);
			continue;
		}

		if (target_vcpu == vcpu) {
			/* We're on the right CPU */
			spin_unlock(&irq->irq_lock);
			continue;
		}

		if (irq->active) {
			/* We have an active interrupt, we can't migrate yet */
			spin_unlock(&irq->irq_lock);
			continue;
		}

		/* This interrupt looks like it has to be migrated. */

		spin_unlock(&irq->irq_lock);
		spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);

		/* Ensure locking order by always locking the smallest
		 * ID first.*/
		if (vcpu->vcpu_id < target_vcpu->vcpu_id) {
			vcpuA = vcpu;
			vcpuB = target_vcpu;
		} else {
			vcpuA = target_vcpu;
			vcpuB = vcpu;
		}

		spin_lock(&vpcuA->arch.vgic_cpu.ap_list_lock);
		spin_lock(&vpcuB->arch.vgic_cpu.ap_list_lock);
		spin_lock(&irq->irq_lock);

		/*
		 * If the affinity has been preserved, move the
		 * interrupt around. Otherwise, it means things have
		 * changed while the interrupt was unlocked, and we
		 * need to replay this.
		 *
		 * In all cases, we cannot trust the list not to have
		 * changed, so we restart from the beginning.
		 */
		if (target_vcpu == vgic_target_oracle(vpcu->kvm, irq)) {
			list_del_init(irq->ap_list);
			/* Should that be in vgic_insert_irq_sorted??*/
			irq->vcpu = target_vcpu;
			vgic_insert_irq_sorted(irq, target_vcpu);
		}

		spin_unlock(&irq->irq_lock);
		spin_unlock(&vcpuB->arch.vgic_cpu.ap_list_lock);
		spin_unlock(&vcpuA->arch.vgic_cpu.ap_list_lock);
		goto retry;
	}

	spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);
}

void kvm_vgic_sync_hwstate(struct kvm_vcpu *vcpu)
{
	vgic_process_maintenance_interrupt(vcpu);
	vgic_fold_lr_state(vcpu);
	vgic_prune_ap_list(vcpu);
}

void kvm_vgic_sync_hwstate(struct kvm_vcpu *vcpu)
{
	spin_lock(&vcpu->arch.vgic_cpu.ap_list_lock);
	vgic_sort_ap_list(vcpu);
	vgic_populate_lrs(vcpu);
	spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);
}

bool kvm_vcpu_has_pending_irqs(struct kvm_vcpu *vcpu)
{
	struct vgic_irq *irq;
	bool pending = false;

	spin_lock(&vcpu->arch.vgic_cpu.ap_list_lock);

	list_for_each_entry(irq, &vcpu->vgic_cpu.ap_list, ap_list) {
		spin_lock(&irq->irq_lock);
		pending |= irq->pending;
		spin_unlock(&irq->irq_lock);
	}

	spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);

	return pending;
}
