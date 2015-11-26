/*
 * Copyright (C) 2012 ARM Ltd.
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
 * along with this program; if not, write to the Free Software
 * Foundation.
 */
#ifndef __ASM_ARM_KVM_VGIC_VGIC_H
#define __ASM_ARM_KVM_VGIC_VGIC_H

#include <linux/kernel.h>
#include <linux/kvm.h>
#include <linux/irqreturn.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <kvm/iodev.h>

#define VGIC_NR_SGIS		16
#define VGIC_NR_PPIS		16
#define VGIC_NR_PRIVATE_IRQS	(VGIC_NR_SGIS + VGIC_NR_PPIS)
#define VGIC_MAX_PRIVATE	(VGIC_NR_PRIVATE_IRQS - 1)
#define VGIC_MAX_SPI		1019
#define VGIC_MAX_RESERVED	1023
#define VGIC_MIN_LPI		8192


struct vgic_global {
	/* virtual control interface mapping */
	void __iomem		*vctrl_base;

	/* Number of list registers on this CPU */
	int		nr_lr;
};

enum vgic_irq_config {
	VGIC_CONFIG_EDGE = 0,
	VGIC_CONFIG_LEVEL
};

struct vgic_irq {
	spinlock_t irq_lock;		/* Protects the content of the struct */
	struct list_head ap_list;

	struct vcpu *vcpu;		/* SGIs and PPIs: The VCPU
					 * SPIs and LIPs: The VCPU whose ap_list
					 * on which this is queued.
					 */

	u32 intid;			/* Guest visible INTID */
	bool pending;
	bool line_level;		/* Level only */
	bool soft_pending;		/* Level only */
	bool active;			/* not used for LPIs */
	bool enabled;
	bool hw;			/* Tied to HW IRQ */
	u32 hwintid;			/* HW INTID number */
	union {
		u8	targets;	/* GICv2  */
		u32	affinity;	/* GICv3+ 32-bit packed MPIDR */
	};
	u8 source;			/* GICv2 SGIs only */
	u8 priority;
	enum vgic_irq_config config;	/* Level or edge */
};

enum vgic_type {
	VGIC_V2,		/* Good ol' GICv2 */
	VGIC_V3,		/* New fancy GICv3 */
};

struct vgic_dist {
	spinlock_t		lock;
	bool			in_kernel;
	bool			ready;

	/* vGIC model the kernel emulates for the guest (GICv2 or GICv3) */
	u32			vgic_model;

	int			nr_spis;

	/* distributor and vcpu interface mapping in the guest */
	phys_addr_t		vgic_dist_base;

	/* gicv2 and gicv3 use different mapped register blocks */
	union {
		phys_addr_t		vgic_cpu_base;
		phys_addr_t		vgic_redist_base;
	};

	/* distributor enabled */
	u32			enabled;

	struct vgic_irq		*spis;

	/* To be moved - probably */
	int			nr_lr;
};

struct vgic_v2_cpu_if {
	u32		vgic_hcr;
	u32		vgic_vmcr;
	u32		vgic_misr;	/* Saved only */
	u64		vgic_eisr;	/* Saved only */
	u64		vgic_elrsr;	/* Saved only */
	u32		vgic_apr;
	u32		vgic_lr[VGIC_V2_MAX_LRS];
};

struct vgic_v3_cpu_if {
#ifdef CONFIG_KVM_ARM_VGIC_V3
	u32		vgic_hcr;
	u32		vgic_vmcr;
	u32		vgic_sre;	/* Restored only, change ignored */
	u32		vgic_misr;	/* Saved only */
	u32		vgic_eisr;	/* Saved only */
	u32		vgic_elrsr;	/* Saved only */
	u32		vgic_ap0r[4];
	u32		vgic_ap1r[4];
	u64		vgic_lr[VGIC_V3_MAX_LRS];
#endif
};

struct vgic_cpu {
	/* CPU vif control registers for world switch */
	union {
		struct vgic_v2_cpu_if	vgic_v2;
		struct vgic_v3_cpu_if	vgic_v3;
	};

	unsigned int used_lrs;
	struct vgic_irq private_irqs[VGIC_NR_PRIVATE_IRQS];
	spinlock_t ap_list_lock;	/* Protects the ap_list */
	struct list_head ap_list_head;	/* ap_list a.k.a. Blue list */
};

bool kvm_vcpu_has_pending_irqs(struct kvm_vcpu *vcpu);
void kvm_vgic_sync_hwstate(struct kvm_vcpu *vcpu);

void void vgic_v2_process_maintenance(struct kvm_vcpu *vcpu);
void vgic_v2_fold_lr_state(struct kvm_vcpu *vcpu);
void vgic_v2_populate_lrs(struct kvm_vcpu *vcpu);

#endif /* __ASM_ARM_KVM_VGIC_VGIC_H */
