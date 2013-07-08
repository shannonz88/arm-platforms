/*
 * Hypervisor stub
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author:	Marc Zyngier <marc.zyngier@arm.com>
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

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/irqchip/arm-gic-v3.h>

#include <asm/assembler.h>
#include <asm/ptrace.h>
#include <asm/virt.h>

	.text
	.align 11

ENTRY(__hyp_stub_vectors)
	ventry	el2_sync_invalid		// Synchronous EL2t
	ventry	el2_irq_invalid			// IRQ EL2t
	ventry	el2_fiq_invalid			// FIQ EL2t
	ventry	el2_error_invalid		// Error EL2t

	ventry	el2_sync_invalid		// Synchronous EL2h
	ventry	el2_irq_invalid			// IRQ EL2h
	ventry	el2_fiq_invalid			// FIQ EL2h
	ventry	el2_error_invalid		// Error EL2h

	ventry	el1_sync			// Synchronous 64-bit EL1
	ventry	el1_irq_invalid			// IRQ 64-bit EL1
	ventry	el1_fiq_invalid			// FIQ 64-bit EL1
	ventry	el1_error_invalid		// Error 64-bit EL1

	ventry	el1_sync_invalid		// Synchronous 32-bit EL1
	ventry	el1_irq_invalid			// IRQ 32-bit EL1
	ventry	el1_fiq_invalid			// FIQ 32-bit EL1
	ventry	el1_error_invalid		// Error 32-bit EL1
ENDPROC(__hyp_stub_vectors)

	.align 11

#define sysreg_to_iss(op0, op1, crn, crm, op2)	\
	(((op0 & 3) << 20) | ((op2 & 7 ) << 17) | \
	 ((op1 & 7 ) << 14) | ((crn & 15) << 10) | \
	 ((crm & 15) << 1))

el1_sync:
	// Hack alert: we don't have a stack, and we can't use the one
	// from EL1 because our MMU is off. Thankfully, we have
	// tpidr_el2, which is under our complete control, and
	// tpidr_el0, which can be used as long as we haven't reached
	// userspace. Oh hum...
	msr	tpidr_el2, x1			// Preserve x1

	mrs	x1, esr_el2
	lsr	x1, x1, #26
	cmp	x1, #0x16
	b.ne	3f				// Not an HVC trap

	// Handle getting/setting vbar_el2
	cbz	x0, 1f
	msr	vbar_el2, x0			// Set vbar_el2
	b	2f
1:	mrs	x0, vbar_el2			// Return vbar_el2
2:	mrs	x1, tpidr_el2			// Restore x1
	eret

3:	cmp	x1, #0x18			// MSR/MRS?
	b.ne	2b

	// Handle trapped sys reg access
	msr	tpidr_el0, x0			// Preserve x0
	mrs	x1, esr_el2
	ldr	x0, =sysreg_to_iss(3, 7, 15, 15, 7)
	and	x1, x1, x0
	ldr	x0, =sysreg_to_iss(3, 0, 12, 12, 5)
	eor	x0, x0, x1			// Check for ICC_SRE_EL1
	cbnz	x0, 4f				// Something bad happened

	// Set ICC_SRE_EL1 access enable
	mrs	x1, ICC_SRE_EL2
	orr	x1, x1, #(1 << 3)
	msr	ICC_SRE_EL2, x1

4:	mrs	x0, tpidr_el0			// Restore x0
	mrs	x1, tpidr_el2			// Restore x1
	eret
ENDPROC(el1_sync)

.macro invalid_vector	label
\label:
	b \label
ENDPROC(\label)
.endm

	invalid_vector	el2_sync_invalid
	invalid_vector	el2_irq_invalid
	invalid_vector	el2_fiq_invalid
	invalid_vector	el2_error_invalid
	invalid_vector	el1_sync_invalid
	invalid_vector	el1_irq_invalid
	invalid_vector	el1_fiq_invalid
	invalid_vector	el1_error_invalid

/*
 * __hyp_set_vectors: Call this after boot to set the initial hypervisor
 * vectors as part of hypervisor installation.  On an SMP system, this should
 * be called on each CPU.
 *
 * x0 must be the physical address of the new vector table, and must be
 * 2KB aligned.
 *
 * Before calling this, you must check that the stub hypervisor is installed
 * everywhere, by waiting for any secondary CPUs to be brought up and then
 * checking that is_hyp_mode_available() is true.
 *
 * If not, there is a pre-existing hypervisor, some CPUs failed to boot, or
 * something else went wrong... in such cases, trying to install a new
 * hypervisor is unlikely to work as desired.
 *
 * When you call into your shiny new hypervisor, sp_el2 will contain junk,
 * so you will need to set that to something sensible at the new hypervisor's
 * initialisation entry point.
 */

ENTRY(__hyp_get_vectors)
	mov	x0, xzr
	// fall through
ENTRY(__hyp_set_vectors)
	hvc	#0
	ret
ENDPROC(__hyp_get_vectors)
ENDPROC(__hyp_set_vectors)
