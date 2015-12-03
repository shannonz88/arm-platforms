/*
 * Copyright (C) 2015 Linaro Ltd.
 * Author: Shannon Zhao <shannon.zhao@linaro.org>
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

#ifndef __ASM_ARM_KVM_PMU_H
#define __ASM_ARM_KVM_PMU_H

#include <linux/perf_event.h>
#ifdef CONFIG_KVM_ARM_PMU
#include <asm/pmu.h>
#endif

struct kvm_pmc {
	u8 idx;/* index into the pmu->pmc array */
	struct perf_event *perf_event;
	struct kvm_vcpu *vcpu;
	u64 bitmask;
};

struct kvm_pmu {
#ifdef CONFIG_KVM_ARM_PMU
	/* PMU IRQ Number per VCPU */
	int irq_num;
	struct kvm_pmc pmc[ARMV8_MAX_COUNTERS];
#endif
};

#ifdef CONFIG_KVM_ARM_PMU
void kvm_pmu_vcpu_reset(struct kvm_vcpu *vcpu);
void kvm_pmu_flush_hwstate(struct kvm_vcpu *vcpu);
unsigned long kvm_pmu_get_counter_value(struct kvm_vcpu *vcpu, u32 select_idx);
void kvm_pmu_disable_counter(struct kvm_vcpu *vcpu, u32 val);
void kvm_pmu_enable_counter(struct kvm_vcpu *vcpu, u32 val, bool all_enable);
void kvm_pmu_overflow_clear(struct kvm_vcpu *vcpu, u32 val);
void kvm_pmu_overflow_set(struct kvm_vcpu *vcpu, u32 val);
void kvm_pmu_software_increment(struct kvm_vcpu *vcpu, u32 val);
void kvm_pmu_set_counter_event_type(struct kvm_vcpu *vcpu, u32 data,
				    u32 select_idx);
void kvm_pmu_handle_pmcr(struct kvm_vcpu *vcpu, u32 val);
#else
void kvm_pmu_vcpu_reset(struct kvm_vcpu *vcpu) {}
void kvm_pmu_flush_hwstate(struct kvm_vcpu *vcpu) {}
unsigned long kvm_pmu_get_counter_value(struct kvm_vcpu *vcpu, u32 select_idx)
{
	return 0;
}
void kvm_pmu_disable_counter(struct kvm_vcpu *vcpu, u32 val) {}
void kvm_pmu_enable_counter(struct kvm_vcpu *vcpu, u32 val, bool all_enable) {}
void kvm_pmu_overflow_clear(struct kvm_vcpu *vcpu, u32 val) {}
void kvm_pmu_overflow_set(struct kvm_vcpu *vcpu, u32 val) {}
void kvm_pmu_software_increment(struct kvm_vcpu *vcpu, u32 val) {}
void kvm_pmu_set_counter_event_type(struct kvm_vcpu *vcpu, u32 data,
				    u32 select_idx) {}
void kvm_pmu_handle_pmcr(struct kvm_vcpu *vcpu, u32 val) {}
#endif

#endif
