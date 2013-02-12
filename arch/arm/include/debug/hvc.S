/*
 * Debugging macro include header
 *
 *  Copyright (C) 2013 ARM Ltd
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

		.macro	addruart, rp, rv, tmp
		.endm

		.macro	senduart,rd,rx
		mov	\rx, r0
		mov	r0, \rd
		hvc	#0x7e57
		mov	r0, \rx
		.endm

		.macro	waituart,rd,rx
		.endm

		.macro	busyuart,rd,rx
		.endm
