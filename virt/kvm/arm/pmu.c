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

#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/perf_event.h>
#include <asm/kvm_emulate.h>
#include <kvm/arm_pmu.h>

/**
 * kvm_pmu_get_counter_value - get PMU counter value
 * @vcpu: The vcpu pointer
 * @select_idx: The counter index
 */
unsigned long kvm_pmu_get_counter_value(struct kvm_vcpu *vcpu, u32 select_idx)
{
	u64 counter, enabled, running;
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_pmc *pmc = &pmu->pmc[select_idx];

	if (!vcpu_mode_is_32bit(vcpu))
		counter = vcpu_sys_reg(vcpu, PMEVCNTR0_EL0 + select_idx);
	else
		counter = vcpu_cp15(vcpu, c14_PMEVCNTR0 + select_idx);

	if (pmc->perf_event)
		counter += perf_event_read_value(pmc->perf_event, &enabled,
						 &running);

	return counter & pmc->bitmask;
}

static bool kvm_pmu_counter_is_enabled(struct kvm_vcpu *vcpu, u32 select_idx)
{
	if (!vcpu_mode_is_32bit(vcpu))
		return (vcpu_sys_reg(vcpu, PMCR_EL0) & ARMV8_PMCR_E) &
		       (vcpu_sys_reg(vcpu, PMCNTENSET_EL0) >> select_idx);
	else
		return (vcpu_sys_reg(vcpu, c9_PMCR) & ARMV8_PMCR_E) &
		       (vcpu_sys_reg(vcpu, c9_PMCNTENSET) >> select_idx);
}

/**
 * kvm_pmu_stop_counter - stop PMU counter
 * @pmc: The PMU counter pointer
 *
 * If this counter has been configured to monitor some event, release it here.
 */
static void kvm_pmu_stop_counter(struct kvm_pmc *pmc)
{
	struct kvm_vcpu *vcpu = pmc->vcpu;
	u64 counter;

	if (pmc->perf_event) {
		counter = kvm_pmu_get_counter_value(vcpu, pmc->idx);
		if (!vcpu_mode_is_32bit(vcpu))
			vcpu_sys_reg(vcpu, PMEVCNTR0_EL0 + pmc->idx) = counter;
		else
			vcpu_cp15(vcpu, c14_PMEVCNTR0 + pmc->idx) = counter;

		perf_event_release_kernel(pmc->perf_event);
		pmc->perf_event = NULL;
	}
}

/**
 * kvm_pmu_enable_counter - enable selected PMU counter
 * @vcpu: The vcpu pointer
 * @val: the value guest writes to PMCNTENSET register
 * @all_enable: the value of PMCR.E
 *
 * Call perf_event_enable to start counting the perf event
 */
void kvm_pmu_enable_counter(struct kvm_vcpu *vcpu, u32 val, bool all_enable)
{
	int i;
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_pmc *pmc;

	if (!all_enable)
		return;

	for_each_set_bit(i, (const unsigned long *)&val, ARMV8_MAX_COUNTERS) {
		pmc = &pmu->pmc[i];
		if (pmc->perf_event) {
			perf_event_enable(pmc->perf_event);
			if (pmc->perf_event->state != PERF_EVENT_STATE_ACTIVE)
				kvm_debug("fail to enable perf event\n");
		}
	}
}

/**
 * kvm_pmu_disable_counter - disable selected PMU counter
 * @vcpu: The vcpu pointer
 * @val: the value guest writes to PMCNTENCLR register
 *
 * Call perf_event_disable to stop counting the perf event
 */
void kvm_pmu_disable_counter(struct kvm_vcpu *vcpu, u32 val)
{
	int i;
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_pmc *pmc;

	for_each_set_bit(i, (const unsigned long *)&val, ARMV8_MAX_COUNTERS) {
		pmc = &pmu->pmc[i];
		if (pmc->perf_event)
			perf_event_disable(pmc->perf_event);
	}
}

static unsigned long kvm_pmu_valid_counter_mask(struct kvm_vcpu *vcpu)
{
	u32 val;

	if (!vcpu_mode_is_32bit(vcpu))
	val = (vcpu_sys_reg(vcpu, PMCR_EL0) >> ARMV8_PMCR_N_SHIFT)
	      & ARMV8_PMCR_N_MASK;
	else
	val = (vcpu_cp15(vcpu, c9_PMCR) >> ARMV8_PMCR_N_SHIFT)
	      & ARMV8_PMCR_N_MASK;

	return GENMASK(val - 1, 0) | BIT(ARMV8_COUNTER_MASK);
}

/**
 * kvm_pmu_overflow_clear - clear PMU overflow interrupt
 * @vcpu: The vcpu pointer
 * @val: the value guest writes to PMOVSCLR register
 * @reg: the current value of PMOVSCLR register
 */
void kvm_pmu_overflow_clear(struct kvm_vcpu *vcpu, u32 val)
{
	u32 mask = kvm_pmu_valid_counter_mask(vcpu);

	if (!vcpu_mode_is_32bit(vcpu)) {
		vcpu_sys_reg(vcpu, PMOVSCLR_EL0) &= mask;
		vcpu_sys_reg(vcpu, PMOVSCLR_EL0) &= ~val;
		vcpu_sys_reg(vcpu, PMOVSSET_EL0) &= mask;
		vcpu_sys_reg(vcpu, PMOVSSET_EL0) &= ~val;
		val = vcpu_sys_reg(vcpu, PMOVSSET_EL0);
	} else {
		vcpu_cp15(vcpu, c9_PMOVSCLR) &= mask;
		vcpu_cp15(vcpu, c9_PMOVSCLR) &= ~val;
		vcpu_cp15(vcpu, c9_PMOVSSET) &= mask;
		vcpu_cp15(vcpu, c9_PMOVSSET) &= ~val;
		val = vcpu_cp15(vcpu, c9_PMOVSSET);
	}

	/* If all overflow bits are cleared, kick the vcpu to clear interrupt
	 * pending status.
	 */
	if (val == 0)
		kvm_vcpu_kick(vcpu);
}

/**
 * kvm_pmu_overflow_set - set PMU overflow interrupt
 * @vcpu: The vcpu pointer
 * @val: the value guest writes to PMOVSSET register
 */
void kvm_pmu_overflow_set(struct kvm_vcpu *vcpu, u32 val)
{
	u32 mask = kvm_pmu_valid_counter_mask(vcpu);

	val &= mask;
	if (val == 0)
		return;

	if (!vcpu_mode_is_32bit(vcpu)) {
		vcpu_sys_reg(vcpu, PMOVSSET_EL0) &= mask;
		vcpu_sys_reg(vcpu, PMOVSSET_EL0) |= val;
		vcpu_sys_reg(vcpu, PMOVSCLR_EL0) &= mask;
		vcpu_sys_reg(vcpu, PMOVSCLR_EL0) |= val;
		val = vcpu_sys_reg(vcpu, PMCNTENSET_EL0)
		      & vcpu_sys_reg(vcpu, PMINTENSET_EL1)
		      & vcpu_sys_reg(vcpu, PMOVSSET_EL0);
	} else {
		vcpu_cp15(vcpu, c9_PMOVSSET) &= mask;
		vcpu_cp15(vcpu, c9_PMOVSSET) |= val;
		vcpu_cp15(vcpu, c9_PMOVSCLR) &= mask;
		vcpu_cp15(vcpu, c9_PMOVSCLR) |= val;
		val = vcpu_cp15(vcpu, c9_PMCNTENSET)
		      & vcpu_cp15(vcpu, c9_PMINTENSET)
		      & vcpu_cp15(vcpu, c9_PMOVSSET);
	}

	if (val != 0)
		kvm_vcpu_kick(vcpu);
}

/**
 * kvm_pmu_software_increment - do software increment
 * @vcpu: The vcpu pointer
 * @val: the value guest writes to PMSWINC register
 */
void kvm_pmu_software_increment(struct kvm_vcpu *vcpu, u32 val)
{
	int i;
	u32 type, enable, reg;

	if (val == 0)
		return;

	for (i = 0; i < ARMV8_MAX_COUNTERS; i++) {
		if (!((val >> i) & 0x1))
			continue;
		if (!vcpu_mode_is_32bit(vcpu)) {
			type = vcpu_sys_reg(vcpu, PMEVTYPER0_EL0 + i)
			       & ARMV8_EVTYPE_EVENT;
			enable = vcpu_sys_reg(vcpu, PMCNTENSET_EL0);
			if ((type == 0) && ((enable >> i) & 0x1)) {
				vcpu_sys_reg(vcpu, PMEVCNTR0_EL0 + i)++;
				reg = vcpu_sys_reg(vcpu, PMEVCNTR0_EL0 + i);
				if ((reg & 0xFFFFFFFF) == 0)
					kvm_pmu_overflow_set(vcpu, 1 >> i);
			}
		} else {
			type = vcpu_cp15(vcpu, c14_PMEVTYPER0 + i)
			       & ARMV8_EVTYPE_EVENT;
			enable = vcpu_cp15(vcpu, c9_PMCNTENSET);
			if ((type == 0) && ((enable >> i) & 0x1)) {
				vcpu_cp15(vcpu, c14_PMEVCNTR0 + i)++;
				reg = vcpu_cp15(vcpu, c14_PMEVCNTR0 + i);
				if ((reg & 0xFFFFFFFF) == 0)
					kvm_pmu_overflow_set(vcpu, 1 >> i);
			}
		}
	}
}

/**
 * kvm_pmu_set_counter_event_type - set selected counter to monitor some event
 * @vcpu: The vcpu pointer
 * @data: The data guest writes to PMXEVTYPER_EL0
 * @select_idx: The number of selected counter
 *
 * When OS accesses PMXEVTYPER_EL0, that means it wants to set a PMC to count an
 * event with given hardware event number. Here we call perf_event API to
 * emulate this action and create a kernel perf event for it.
 */
void kvm_pmu_set_counter_event_type(struct kvm_vcpu *vcpu, u32 data,
				    u32 select_idx)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_pmc *pmc = &pmu->pmc[select_idx];
	struct perf_event *event;
	struct perf_event_attr attr;
	u32 eventsel;
	u64 counter;

	kvm_pmu_stop_counter(pmc);
	eventsel = data & ARMV8_EVTYPE_EVENT;

	/* For software increment event it does't need to create perf event */
	if (eventsel == 0)
		return;

	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.type = PERF_TYPE_RAW;
	attr.size = sizeof(attr);
	attr.pinned = 1;
	attr.disabled = kvm_pmu_counter_is_enabled(vcpu, select_idx);
	attr.exclude_user = data & ARMV8_EXCLUDE_EL0 ? 1 : 0;
	attr.exclude_kernel = data & ARMV8_EXCLUDE_EL1 ? 1 : 0;
	attr.exclude_hv = 1; /* Don't count EL2 events */
	attr.exclude_host = 1; /* Don't count host events */
	attr.config = eventsel;

	counter = kvm_pmu_get_counter_value(vcpu, select_idx);
	/* The initial sample period (overflow count) of an event. */
	attr.sample_period = (-counter) & pmc->bitmask;

	event = perf_event_create_kernel_counter(&attr, -1, current, NULL, pmc);
	if (IS_ERR(event)) {
		printk_once("kvm: pmu event creation failed %ld\n",
			    PTR_ERR(event));
		return;
	}

	pmc->perf_event = event;
}
