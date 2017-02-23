/*
 * Copyright (C) 2012 ARM Ltd.
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

#ifndef __ASM_PMUV3_H
#define __ASM_PMUV3_H

#include <asm/cp15.h>

#define pmcr		__ACCESS_CP15(c9, 0, c12, 0)
#define pmselr		__ACCESS_CP15(c9, 0, c12, 5)
#define pmccntr		__ACCESS_CP15_64(0, c9)
#define pmxevcntr	__ACCESS_CP15(c9, 0, c13, 2)
#define pmxevtyper	__ACCESS_CP15(c9, 0, c13, 1)
#define pmcntenset	__ACCESS_CP15(c9, 0, c12, 1)
#define pmcntenclr	__ACCESS_CP15(c9, 0, c12, 2)
#define pmintenset	__ACCESS_CP15(c9, 0, c12, 1)
#define pmintenclr	__ACCESS_CP15(c9, 0, c12, 2)
#define pmovsclr	__ACCESS_CP15(c9, 0, c12, 3)
#define pmceid0		__ACCESS_CP15(c9, 0, c12, 6)
#define pmceid1		__ACCESS_CP15(c9, 0, c12, 7)

static inline void write_pmcr(u32 val)
{
	write_sysreg(val, pmcr);
}

static inline u32 read_pmcr(void)
{
	return read_sysreg(pmcr);
}

static inline void write_pmselr(u32 val)
{
	write_sysreg(val, pmselr);
}

static inline void write_pmccntr(u64 val)
{
	write_sysreg(val, pmccntr);
}

static inline u64 read_pmccntr(void)
{
	return read_sysreg(pmccntr);
}

static inline void write_pmxevcntr(u32 val)
{
	write_sysreg(val, pmxevcntr);
}

static inline u32 read_pmxevcntr(void)
{
	return read_sysreg(pmxevcntr);
}

static inline void write_pmxevtyper(u32 val)
{
	write_sysreg(val, pmxevtyper);
}

static inline void write_pmcntenset(u32 val)
{
	write_sysreg(val, pmcntenset);
}

static inline void write_pmcntenclr(u32 val)
{
	write_sysreg(val, pmcntenclr);
}

static inline void write_pmintenset(u32 val)
{
	write_sysreg(val, pmintenset);
}

static inline void write_pmintenclr(u32 val)
{
	write_sysreg(val, pmintenclr);
}

static inline void write_pmovsclr(u32 val)
{
	write_sysreg(val, pmovsclr);
}

static inline u32 read_pmovsclr(void)
{
	return read_sysreg(pmovsclr);
}

static inline u32 read_pmceid0(void)
{
	return read_sysreg(pmceid0);
}

static inline u32 read_pmceid1(void)
{
	return read_sysreg(pmceid1);
}

#endif
