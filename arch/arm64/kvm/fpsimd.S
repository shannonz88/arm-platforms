/*
 * Copyright (C) 2012,2013 - ARM Ltd
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

#include <linux/linkage.h>

#include <asm/asm-offsets.h>
#include <asm/fpsimdmacros.h>

#define CPU_GP_REG_OFFSET(x)	(CPU_GP_REGS + x)

ENTRY(__kvm_save_fpsimd)
	// x0: cpu context address
	// x1, x2: tmp regs
	add	x1, x0, #CPU_GP_REG_OFFSET(CPU_FP_REGS)
	fpsimd_save x1, 2
	ret
END(__kvm_save_fpsimd)

ENTRY(__kvm_restore_fpsimd)
	// x0: cpu context address
	// x1, x2: tmp regs
	add	x1, x0, #CPU_GP_REG_OFFSET(CPU_FP_REGS)
	fpsimd_restore x1, 2
	ret
END(__kvm_restore_fpsimd)
