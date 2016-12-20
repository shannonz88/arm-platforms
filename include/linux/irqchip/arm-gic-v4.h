/*
 * Copyright (C) 2016 ARM Limited, All Rights Reserved.
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

#ifndef __LINUX_IRQCHIP_ARM_GIC_V4_H
#define __LINUX_IRQCHIP_ARM_GIC_V4_H

/* Embedded in kvm.arch */
struct its_vm {
	struct irq_domain	*domain;
	struct page		*vprop_page;
	irq_hw_number_t		db_lpi_base;
	unsigned long		*db_bitmap;
	int			nr_db_lpis;
};

/* Embedded in kvm_vcpu.arch */
struct its_vpe {
	struct page 		*vpt_page;
	struct its_vm		*its_vm;
	/* Doorbell interrupt */
	irq_hw_number_t		vpe_db_lpi;
	/*
	 * This collection ID is used to indirect the target
	 * redistributor for this VPE. The ID itself isn't involved in
	 * programming of the ITS.
	 */
	u16			col_idx;
	/* Unique (system-wide) VPE identifier */
	u16			vpe_id;
	/* Implementation Defined Area Invalid */
	bool			idai;
	/* Pending VLPIs on schedule out? */
	bool			pending_last;
};

/*
 * struct its_vlpi: structure describing a VLPI. Only to be
 * interpreted in the context of a physical interrupt it complements.
 *
 * @vintid:	Virtual LPI number
 * @db_enabled:	Is the VPE doorbell to be generated?
 * @vpe_idx:	Index (0-based) of the VPE in this VM. Not the vpe_id!
 */
struct its_vlpi {
	u32			vintid;
	bool			db_enabled;
	u16			vpe_idx;
};

/*
 * struct its_vlpi_map: structure describing the mappings of all vlpis
 * for a single device. To be used as the vcpu_info passed to
 * irq_set_vcpu_affinity().
 *
 * @vpes: Array of struct its_vpe, describing the GICv4 view of the
 * 	  vpus.
 * @vlpis: Array of struct vlpi, each one matching the corresponding LPI
 * @nr_vpes: Size of the @vpes array
 * @nr_vlpis: Size of the @vlpis array
 */
struct its_vlpi_map {
	struct its_vpe		**vpes;
	struct its_vlpi		*vlpis;
	int			nr_vpes;
	int			nr_vlpis;
};

enum its_vcpu_info_cmd_type {
	MAP_VLPI,
	UNMAP_VLPI,
	PROP_UPDATE_VLPI,
	SCHEDULE_VPE,
	DESCHEDULE_VPE,
	INVALL_VPE,
};

struct its_cmd_info {
	enum its_vcpu_info_cmd_type	cmd_type;
	union {
		struct its_vlpi_map	*map;
		u8			config;
	};
};

int its_alloc_vcpu_irqs(struct its_vm *vm, struct its_vpe **vpes, int nr_vpes);
void its_free_vcpu_irqs(struct its_vm *vm, int nr_vpes);
int its_schedule_vpe(struct its_vpe *vpe, bool on);
int its_invall_vpe(struct its_vpe *vpe);

#endif
