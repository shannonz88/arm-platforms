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

#endif
