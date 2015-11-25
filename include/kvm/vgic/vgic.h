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

/******************************************************************
 * TODO: Consider removing these, added for compilation purposes.
 */

#define VGIC_V3_MAX_CPUS	255

struct irq_phys_map {
	u32			virt_irq;
	u32			phys_irq;
	u32			irq;
};

static inline void vgic_v3_dispatch_sgi(struct kvm_vcpu *vcpu, u64 reg) { }

static inline struct irq_phys_map *kvm_vgic_map_phys_irq(struct kvm_vcpu *vcpu,
							 int virt_irq, int irq)
{
	return NULL;
}

static inline int kvm_vgic_unmap_phys_irq(struct kvm_vcpu *vcpu,
					  struct irq_phys_map *map)
{
	return 0;
}

/**
 * kvm_vgic_get_max_vcpus - Get the maximum number of VCPUs allowed by HW
 *
 * The host's GIC naturally limits the maximum amount of VCPUs a guest
 * can use.
 */
static inline int kvm_vgic_get_max_vcpus(void)
{
	return 0;
}

/*
 *****************************************************************/

#define VGIC_NR_SGIS		16
#define VGIC_NR_PPIS		16
#define VGIC_NR_PRIVATE_IRQS	(VGIC_NR_SGIS + VGIC_NR_PPIS)
#define VGIC_MAX_PRIVATE	(VGIC_NR_PRIVATE_IRQS - 1)
#define VGIC_MAX_SPI		1019
#define VGIC_MAX_RESERVED	1023
#define VGIC_MIN_LPI		8192


#define VGIC_V2_MAX_LRS		(1 << 6)
#define VGIC_V3_MAX_LRS		16

enum vgic_irq_config {
	VGIC_CONFIG_EDGE = 0,
	VGIC_CONFIG_LEVEL
};

struct vgic_irq {
	struct list_head ap_list;

	struct kvm_vcpu *vcpu;		/* SGIs and PPIs: The VCPU
					 * SPIs and LIPs: The VCPU whose ap_list
					 * on which this is queued.
					 */

	struct kvm_vcpu *target_vcpu;	/* The VCPU that this interrupt should,
					 * as a result of the targets reg (v2)
					 * or the affinity reg (v3).
					 */

	u32 intid;			/* Guest visible INTID */
	bool pending;
	bool line_level;		/* Level only */
	bool soft_pending;		/* Level only */
	bool active;			/* not used for LPIs */
	bool enabled;
	bool hw;			/* Tied to HW IRQ */
	u32 hwintid;			/* HW INTID number */
	u8 targets;			/* GICv2  */
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

	/* Virtual control interface mapping */
	void __iomem		*vctrl_base;

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

	/* TODO: Move nr_lr to a global state */
	/* Number of list registers on this CPU */
	int		nr_lr;

	struct vgic_irq private_irqs[VGIC_NR_PRIVATE_IRQS];
	struct list_head ap_list_head;	/* Blue list */
};

void kvm_vgic_early_init(struct kvm *kvm);
int kvm_vgic_create(struct kvm *kvm, u32 type);
void kvm_vgic_destroy(struct kvm *kvm);
void kvm_vgic_vcpu_early_init(struct kvm_vcpu *vcpu);
void kvm_vgic_vcpu_destroy(struct kvm_vcpu *vcpu);
int kvm_vgic_map_resources(struct kvm *kvm);
int kvm_vgic_hyp_init(void);

int kvm_vgic_get_max_vcpus(void);
int kvm_vgic_addr(struct kvm *kvm, unsigned long type, u64 *addr, bool write);

int kvm_vgic_inject_irq(struct kvm *kvm, int cpuid, unsigned int irq_num,
			bool level);

static inline void kvm_vgic_flush_hwstate(struct kvm_vcpu *vcpu) { }
static inline void kvm_vgic_sync_hwstate(struct kvm_vcpu *vcpu) { }

static inline int kvm_vgic_inject_mapped_irq(struct kvm *kvm, int cpuid,
					     struct irq_phys_map *map,
					     bool level)
{
	return 0;
}

static inline int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu)
{
	return 0;
}

static inline int kvm_vgic_vcpu_active_irq(struct kvm_vcpu *vcpu)
{
	return 0;
}

#define irqchip_in_kernel(k)	(!!((k)->arch.vgic.in_kernel))
#define vgic_initialized(k)	(false)
#define vgic_ready(k)		((k)->arch.vgic.ready)

#endif /* __ASM_ARM_KVM_VGIC_VGIC_H */
