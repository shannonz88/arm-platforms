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
#ifndef __KVM_ARM_VGIC_NEW_H__
#define __KVM_ARM_VGIC_NEW_H__

struct vgic_irq *vgic_get_irq(struct kvm *kvm, struct kvm_vcpu *vcpu,
			      u32 intid);

void vgic_v2_process_maintenance(struct kvm_vcpu *vcpu);
void vgic_v2_fold_lr_state(struct kvm_vcpu *vcpu);
void vgic_v2_populate_lr(struct kvm_vcpu *vcpu, struct vgic_irq *irq, int lr);
void vgiv_v2_irq_change_affinity(struct kvm *kvm, u32 intid, u8 target);
void vgic_v2_set_underflow(struct kvm_vcpu *vcpu);

void vgic_v3_process_maintenance(struct kvm_vcpu *vcpu);
void vgic_v3_fold_lr_state(struct kvm_vcpu *vcpu);
void vgic_v3_populate_lr(struct kvm_vcpu *vcpu, struct vgic_irq *irq, int lr);
void vgiv_v3_irq_change_affinity(struct kvm *kvm, u32 intid, u64 mpidr);
void vgic_v3_set_underflow(struct kvm_vcpu *vcpu);

#endif
