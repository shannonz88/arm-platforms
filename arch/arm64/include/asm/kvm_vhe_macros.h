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

#ifndef __ARM64_KVM_VHE_MACROS_H__
#define __ARM64_KVM_VHE_MACROS_H__

#include <asm/alternative.h>
#include <asm/cpufeature.h>

#ifdef __ASSEMBLY__

/* Hack to allow stringification of macros... */
#define __S__(a,args...)	__stringify(a, ##args)
#define _S_(a,args...)		__S__(a, args)

.macro ifnvhe nonvhe vhe
	alternative_insn	"\nonvhe", "\vhe", ARM64_HAS_VIRT_HOST_EXTN
.endm

#endif

#endif	/*__ARM64_KVM_VHE_MACROS_H__  */
