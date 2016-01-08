/*
 * Copyright (C) 2016 - ARM Ltd
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

#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/seq_file.h>

#include <asm/cacheflush.h>
#include <asm/traps.h>

static unsigned long bx_emul_counter;

#ifdef CONFIG_PROC_FS
static int bx_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Emulated BX:\t%lu\n", bx_emul_counter);

	return 0;
}

static int bx_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, bx_proc_show, PDE_DATA(inode));
}

static const struct file_operations bx_proc_fops = {
	.open		= bx_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

static int handle_bx_trap(struct pt_regs *regs, unsigned int instr)
{
	if (arm_check_condition(instr,
				regs->ARM_cpsr) != ARM_OPCODE_CONDTEST_FAIL) {
		int reg = instr & 0xf;

		regs->ARM_pc = regs->uregs[reg];
		bx_emul_counter++;
	}
	return 0;
}

static struct undef_hook arm_bx_hook = {
	.instr_mask	= 0x0ffffff0,
	.instr_val	= 0x012fff10,
	.cpsr_mask	= 0,
	.cpsr_val	= 0,
	.fn		= handle_bx_trap,
};

static int __init arm_bx_hook_init(void)
{
	if (elf_hwcap & HWCAP_THUMB)
		return 0;

#ifdef CONFIG_PROC_FS
	if (!proc_create("cpu/bx_emulation", S_IRUGO, NULL, &bx_proc_fops))
		return -ENOMEM;
#endif /* CONFIG_PROC_FS */

	pr_notice("Registering BX emulation handler\n");
	register_undef_hook(&arm_bx_hook);
	return 0;
}

late_initcall(arm_bx_hook_init);
