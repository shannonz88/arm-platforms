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

static void vgic_update_irq_pending(struct kvm *kvm, struct kvm_vcpu *vcpu,
				    u32 intid, bool level)
{
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
