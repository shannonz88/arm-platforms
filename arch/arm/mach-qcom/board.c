/* Copyright (c) 2010-2014 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/memblock.h>
#include <asm/mach/arch.h>
#include <asm/setup.h>

static const char * const qcom_dt_match[] __initconst = {
	"qcom,apq8064",
	"qcom,apq8074-dragonboard",
	"qcom,apq8084",
	"qcom,ipq8062",
	"qcom,ipq8064",
	"qcom,msm8660-surf",
	"qcom,msm8960-cdp",
	"qcom,mdm9615",
	NULL
};


static long long qcom_dt_pv_fixup(void)
{
	struct memblock_region *reg;
	int i = 0;

	for_each_memblock(memory, reg) {
		pr_info("region %d: %08x-%08x\n", i, reg->base, reg->base+reg->size-1);
		if (reg->base == 0x80200000 || reg->base == 0x40200000) {
			pr_info("augmenting region base\n");
			reg->base -= 0x200000;
			reg->size += 0x200000;
		}
		i++;
	}
	return 0;
}

DT_MACHINE_START(QCOM_DT, "Qualcomm (Flattened Device Tree)")
	.dt_compat = qcom_dt_match,
	.pv_fixup = qcom_dt_pv_fixup,
MACHINE_END
