/*
 * Copyright (C) 2015 - ARM Ltd
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

#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>

void kvm_fpsimd_load_vcpu_state(struct kvm_vcpu *vcpu)
{
	vcpu->arch.cptr_el2 = (3 << 12) | 0x1ff | CPTR_EL2_TTA;

	if (vcpu_mode_is_32bit(vcpu)) {
		unsigned long flags;

		local_irq_save(flags);

		__kvm_save_fpsimd(vcpu->arch.host_cpu_context);
		__kvm_restore_fpsimd(&vcpu->arch.ctxt);

		local_irq_restore(flags);
	} else {
	      	vcpu->arch.cptr_el2 |= CPTR_EL2_TFP;
	}
}

void kvm_fpsimd_put_vcpu_state(struct kvm_vcpu *vcpu)
{
	/* If the trapping was still active, nothing to do */
	if (!(vcpu->arch.cptr_el2 & CPTR_EL2_TFP)) {
		unsigned long flags;

		local_irq_save(flags);

		__kvm_save_fpsimd(&vcpu->arch.ctxt);
		__kvm_restore_fpsimd(vcpu->arch.host_cpu_context);

		local_irq_restore(flags);
	}
}

