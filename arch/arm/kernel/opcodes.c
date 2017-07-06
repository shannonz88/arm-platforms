/*
 *  linux/arch/arm/kernel/opcodes.c
 *
 *  A32 condition code lookup feature moved from nwfpe/fpopcode.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <asm/opcodes.h>

#define ARM_OPCODE_CONDITION_UNCOND 0xf

/*
 * condition code lookup table
 * index into the table is test code: EQ, NE, ... LT, GT, AL, NV
 *
 * bit position in short is condition code: NZCV
 */
static const unsigned short cc_map[16] = {
	0xF0F0,			/* EQ == Z set            */
	0x0F0F,			/* NE                     */
	0xCCCC,			/* CS == C set            */
	0x3333,			/* CC                     */
	0xFF00,			/* MI == N set            */
	0x00FF,			/* PL                     */
	0xAAAA,			/* VS == V set            */
	0x5555,			/* VC                     */
	0x0C0C,			/* HI == C set && Z clear */
	0xF3F3,			/* LS == C clear || Z set */
	0xAA55,			/* GE == (N==V)           */
	0x55AA,			/* LT == (N!=V)           */
	0x0A05,			/* GT == (!Z && (N==V))   */
	0xF5FA,			/* LE == (Z || (N!=V))    */
	0xFFFF,			/* AL always              */
	0			/* NV                     */
};

#define PSR_IT_1_0_SHIFT	25
#define PSR_IT_1_0_MASK		(0x3 << PSR_IT_1_0_SHIFT)
#define PSR_IT_7_2_SHIFT	10
#define PSR_IT_7_2_MASK		(0x3f << PSR_IT_7_2_SHIFT)

static u32 psr_get_it_state(u32 psr)
{
	u32 it;

	it  = (psr & PSR_IT_1_0_MASK) >> PSR_IT_1_0_SHIFT;
	it |= ((psr & PSR_IT_7_2_MASK) >> PSR_IT_7_2_SHIFT) << 2;

	return it;
}

static void psr_set_it_state(struct pt_regs *regs, u32 it)
{
	u32 cpsr_it;

	cpsr_it  = (it << PSR_IT_1_0_SHIFT) & PSR_IT_1_0_MASK;
	cpsr_it |= ((it >> 2) << PSR_IT_7_2_SHIFT) & PSR_IT_7_2_MASK;

	regs->ARM_cpsr &= ~PSR_IT_MASK;
	regs->ARM_cpsr |= cpsr_it;
}

void arm_advance_itstate(struct pt_regs *regs)
{
	u32 it;

	/* ARM mode or no conditional */
	if (thumb_mode(regs) || !(regs->ARM_cpsr & PSR_IT_MASK))
		return;

	it = psr_get_it_state(regs->ARM_cpsr);

	/*
	 * If this is the last instruction of the block, wipe the IT
	 * state. Otherwise advance it. See the ITAdvance() pseudocode
	 * for reference.
	 */
	if (!(it & 7))
		it = 0;
	else
		it = (it & 0xe0) | ((it << 1) & 0x1f);

	psr_set_it_state(regs, it);
}

/*
 * Returns:
 * ARM_OPCODE_CONDTEST_FAIL   - if condition fails
 * ARM_OPCODE_CONDTEST_PASS   - if condition passes (including AL)
 * ARM_OPCODE_CONDTEST_UNCOND - if NV condition, or separate unconditional
 *                              opcode space from v5 onwards
 *
 * Code that tests whether a conditional instruction would pass its condition
 * check should check that return value == ARM_OPCODE_CONDTEST_PASS.
 *
 * Code that tests if a condition means that the instruction would be executed
 * (regardless of conditional or unconditional) should instead check that the
 * return value != ARM_OPCODE_CONDTEST_FAIL.
 */
asmlinkage unsigned int arm_check_condition(u32 opcode, u32 psr)
{
	u32 cc_bits;
	u32 psr_cond = psr >> 28;
	unsigned int ret;

	/*
	 * If the CPU is in Thumb mode Thumb, extract the condition
	 * code from psr. Otherwise, extract the condition code from
	 * the instruction itself.
	 */
	if (psr & PSR_T_BIT) {
		u32 it;

		it = psr_get_it_state(psr);
		if (!it)
			return ARM_OPCODE_CONDTEST_PASS;

		cc_bits = it >> 4;
	} else {
		cc_bits  = opcode >> 28;
	}

	if (cc_bits != ARM_OPCODE_CONDITION_UNCOND) {
		if ((cc_map[cc_bits] >> (psr_cond)) & 1)
			ret = ARM_OPCODE_CONDTEST_PASS;
		else
			ret = ARM_OPCODE_CONDTEST_FAIL;
	} else {
		ret = ARM_OPCODE_CONDTEST_UNCOND;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(arm_check_condition);
