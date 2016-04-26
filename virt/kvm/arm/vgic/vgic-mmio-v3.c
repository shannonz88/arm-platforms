/*
 * VGICv3 MMIO handling functions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/irqchip/arm-gic-v3.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <kvm/iodev.h>
#include <kvm/vgic/vgic.h>

#include <asm/kvm_emulate.h>

#include "vgic.h"
#include "vgic_mmio.h"

static unsigned long vgic_mmio_read_v3_misc(struct kvm_vcpu *vcpu,
					    gpa_t addr, unsigned int len)
{
	u32 value = 0;

	switch (addr & 0x0c) {
	case GICD_CTLR:
		if (vcpu->kvm->arch.vgic.enabled)
		       value |=	GICD_CTLR_ENABLE_SS_G1;
		value |= GICD_CTLR_ARE_NS | GICD_CTLR_DS;
		break;
	case GICD_TYPER:
		value = vcpu->kvm->arch.vgic.nr_spis + VGIC_NR_PRIVATE_IRQS;
		value = (value >> 5) - 1;
		value |= (INTERRUPT_ID_BITS_SPIS - 1) << 19;
		break;
	case GICD_IIDR:
		value = (PRODUCT_ID_KVM << 24) | (IMPLEMENTER_ARM << 0);
		break;
	default:
		return 0;
	}

	return extract_bytes(value, addr & 3, len);
}

static void vgic_mmio_write_v3_misc(struct kvm_vcpu *vcpu,
				    gpa_t addr, unsigned int len,
				    unsigned long val)
{
	switch (addr & 0x0c) {
	case GICD_CTLR:
		if (!(addr & 1)) {
			struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
			bool was_enabled = dist->enabled;

			dist->enabled = val & GICD_CTLR_ENABLE_SS_G1;

			if (!was_enabled && dist->enabled)
				vgic_kick_vcpus(vcpu->kvm);
		}
		break;
	case GICD_TYPER:
	case GICD_IIDR:
		return;
	}
}

/*
 * We use a compressed version of the MPIDR (all 32 bits in one 32-bit word)
 * when we store the target MPIDR written by the guest.
 */
static u32 compress_mpidr(unsigned long mpidr)
{
	u32 ret;

	ret = MPIDR_AFFINITY_LEVEL(mpidr, 0);
	ret |= MPIDR_AFFINITY_LEVEL(mpidr, 1) << 8;
	ret |= MPIDR_AFFINITY_LEVEL(mpidr, 2) << 16;
	ret |= MPIDR_AFFINITY_LEVEL(mpidr, 3) << 24;

	return ret;
}

static unsigned long decompress_mpidr(u32 value)
{
	unsigned long mpidr;

	mpidr  = ((value >>  0) & 0xFF) << MPIDR_LEVEL_SHIFT(0);
	mpidr |= ((value >>  8) & 0xFF) << MPIDR_LEVEL_SHIFT(1);
	mpidr |= ((value >> 16) & 0xFF) << MPIDR_LEVEL_SHIFT(2);
	mpidr |= (u64)((value >> 24) & 0xFF) << MPIDR_LEVEL_SHIFT(3);

	return mpidr;
}

static unsigned long vgic_mmio_read_irouter(struct kvm_vcpu *vcpu,
					    gpa_t addr, unsigned int len)
{
	int intid = (addr & 0x1fff) / 8;
	struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, NULL, intid);
	unsigned long mpidr;

	if (!irq)
		return 0;

	spin_lock(&irq->irq_lock);
	mpidr = irq->mpidr;
	spin_unlock(&irq->irq_lock);

	mpidr = decompress_mpidr(mpidr);
	return extract_bytes(mpidr, addr & 7, len);
}

static void vgic_mmio_write_irouter(struct kvm_vcpu *vcpu,
				    gpa_t addr, unsigned int len,
				    unsigned long val)
{
	int intid = (addr & 0x1fff) / 8;
	struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, NULL, intid);
	int offset = addr & 4;
	u64 mpidr;

	if (!irq)
		return;

	/*
	 * There are only two supported options:
	 * (1) aligned 64-bit access
	 * (2) aligned 32-bit access
	 */
	if (len != 4 && len != 8)
		return;

	spin_lock(&irq->irq_lock);

	mpidr = decompress_mpidr(irq->mpidr);
	while (len) {
		int shift = offset * 8;
		u64 mask = 0xffffffff << shift;

		mpidr &= ~mask;
		mpidr |= val & mask;
		offset -= 4;
		len -= 4;
	}
	irq->mpidr = compress_mpidr(mpidr);
	irq->target_vcpu = kvm_mpidr_to_vcpu(vcpu->kvm, mpidr);

	spin_unlock(&irq->irq_lock);
}

static unsigned long vgic_mmio_read_v3r_typer(struct kvm_vcpu *vcpu,
					      gpa_t addr, unsigned int len)
{
	unsigned long mpidr = kvm_vcpu_get_mpidr_aff(vcpu);
	int target_vcpu_id = vcpu->vcpu_id;
	u64 value;

	value = (u64)compress_mpidr(mpidr) << 32;
	value |= ((target_vcpu_id & 0xffff) << 8);
	if (target_vcpu_id == atomic_read(&vcpu->kvm->online_vcpus) - 1)
		value |= GICR_TYPER_LAST;

	return extract_bytes(value, addr & 7, len);
}

static unsigned long vgic_mmio_read_v3r_iidr(struct kvm_vcpu *vcpu,
					     gpa_t addr, unsigned int len)
{
	u32 value;

	value = (PRODUCT_ID_KVM << 24) | (IMPLEMENTER_ARM << 0);
	return extract_bytes(value, addr & 3, len);
}

static unsigned long vgic_mmio_read_v3_idregs(struct kvm_vcpu *vcpu,
					      gpa_t addr, unsigned int len)
{
	u32 regnr = (addr & 0x3f) - (GICD_IDREGS & 0x3f);
	u32 reg = 0;

	switch (regnr + GICD_IDREGS) {
	case GICD_PIDR2:
		/* report a GICv3 compliant implementation */
		reg = 0x3b;
		break;
	}

	return extract_bytes(reg, addr & 3, len);
}

/*
 * The GICv3 per-IRQ registers are split to control PPIs and SGIs in the
 * redistributors, while SPIs are covered by registers in the distributor
 * block. Trying to set private IRQs in this block gets ignored.
 * We take some special care here to fix the calculation of the register
 * offset.
 */
#define REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(off, read_ops, write_ops, bpi) \
	{								\
		.reg_offset = off,					\
		.bits_per_irq = bpi,					\
		.len = (bpi * VGIC_NR_PRIVATE_IRQS) / 8,		\
		.read = vgic_mmio_read_raz,				\
		.write = vgic_mmio_write_wi,				\
	}, {								\
		.reg_offset = off + (bpi * VGIC_NR_PRIVATE_IRQS) / 8,	\
		.bits_per_irq = bpi,					\
		.len = (bpi * (1024 - VGIC_NR_PRIVATE_IRQS)) / 8, 	\
		.read = read_ops,					\
		.write = write_ops,					\
	}

static const struct vgic_register_region vgic_v3_dist_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GICD_CTLR,
		vgic_mmio_read_v3_misc, vgic_mmio_write_v3_misc, 16),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_IGROUPR,
		vgic_mmio_read_rao, vgic_mmio_write_wi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ISENABLER,
		vgic_mmio_read_enable, vgic_mmio_write_senable, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ICENABLER,
		vgic_mmio_read_enable, vgic_mmio_write_cenable, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ISPENDR,
		vgic_mmio_read_pending, vgic_mmio_write_spending, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ICPENDR,
		vgic_mmio_read_pending, vgic_mmio_write_cpending, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ISACTIVER,
		vgic_mmio_read_active, vgic_mmio_write_sactive, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ICACTIVER,
		vgic_mmio_read_active, vgic_mmio_write_cactive, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_IPRIORITYR,
		vgic_mmio_read_priority, vgic_mmio_write_priority, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ITARGETSR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ICFGR,
		vgic_mmio_read_config, vgic_mmio_write_config, 2),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_IGRPMODR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_IROUTER,
		vgic_mmio_read_irouter, vgic_mmio_write_irouter, 64),
	REGISTER_DESC_WITH_LENGTH(GICD_IDREGS,
		vgic_mmio_read_v3_idregs, vgic_mmio_write_wi, 48),
};

static const struct vgic_register_region vgic_v3_redist_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GICR_CTLR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_IIDR,
		vgic_mmio_read_v3r_iidr, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_TYPER,
		vgic_mmio_read_v3r_typer, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_LENGTH(GICR_PROPBASER,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_LENGTH(GICR_PENDBASER,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_LENGTH(GICR_IDREGS,
		vgic_mmio_read_v3_idregs, vgic_mmio_write_wi, 48),
};

static const struct vgic_register_region vgic_v3_private_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GICR_IGROUPR0,
		vgic_mmio_read_rao, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ISENABLER0,
		vgic_mmio_read_enable, vgic_mmio_write_senable, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ICENABLER0,
		vgic_mmio_read_enable, vgic_mmio_write_cenable, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ISPENDR0,
		vgic_mmio_read_pending, vgic_mmio_write_spending, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ICPENDR0,
		vgic_mmio_read_pending, vgic_mmio_write_cpending, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ISACTIVER0,
		vgic_mmio_read_active, vgic_mmio_write_sactive, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ICACTIVER0,
		vgic_mmio_read_active, vgic_mmio_write_cactive, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_IPRIORITYR0,
		vgic_mmio_read_priority, vgic_mmio_write_priority, 32),
	REGISTER_DESC_WITH_LENGTH(GICR_ICFGR0,
		vgic_mmio_read_config, vgic_mmio_write_config, 8),
	REGISTER_DESC_WITH_LENGTH(GICR_IGRPMODR0,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_NSACR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 4),
};

unsigned int vgic_v3_init_dist_iodev(struct vgic_io_device *dev)
{
	dev->regions = vgic_v3_dist_registers;
	dev->nr_regions = ARRAY_SIZE(vgic_v3_dist_registers);

	kvm_iodevice_init(&dev->dev, &kvm_io_gic_ops);

	return SZ_64K;
}

int vgic_register_redist_iodevs(struct kvm *kvm, gpa_t redist_base_address)
{
	int nr_vcpus = atomic_read(&kvm->online_vcpus);
	struct kvm_vcpu *vcpu;
	struct vgic_io_device *devices, *device;
	int c, ret = 0;

	devices = kmalloc(sizeof(struct vgic_io_device) * nr_vcpus * 2,
			  GFP_KERNEL);
	if (!devices)
		return -ENOMEM;

	device = devices;
	kvm_for_each_vcpu(c, vcpu, kvm) {
		kvm_iodevice_init(&device->dev, &kvm_io_gic_ops);
		device->base_addr = redist_base_address;
		device->regions = vgic_v3_redist_registers;
		device->nr_regions = ARRAY_SIZE(vgic_v3_redist_registers);
		device->redist_vcpu = vcpu;

		mutex_lock(&kvm->slots_lock);
		ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
					      redist_base_address,
					      SZ_64K, &device->dev);
		mutex_unlock(&kvm->slots_lock);

		if (ret)
			break;

		device++;
		kvm_iodevice_init(&device->dev, &kvm_io_gic_ops);
		device->base_addr = redist_base_address + SZ_64K;
		device->regions = vgic_v3_private_registers;
		device->nr_regions = ARRAY_SIZE(vgic_v3_private_registers);
		device->redist_vcpu = vcpu;

		mutex_lock(&kvm->slots_lock);
		ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
					      redist_base_address + SZ_64K,
					      SZ_64K, &device->dev);
		mutex_unlock(&kvm->slots_lock);
		if (ret) {
			kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS,
						  &devices[c * 2].dev);
			break;
		}
		device++;
		redist_base_address += 2 * SZ_64K;
	}

	if (ret) {
		for (c--; c >= 0; c--) {
			kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS,
						  &devices[c * 2].dev);
			kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS,
						  &devices[c * 2 + 1].dev);
		}
		kfree(devices);
	} else {
		kvm->arch.vgic.redist_iodevs = devices;
	}

	return ret;
}

/*
 * Compare a given affinity (level 1-3 and a level 0 mask, from the SGI
 * generation register ICC_SGI1R_EL1) with a given VCPU.
 * If the VCPU's MPIDR matches, return the level0 affinity, otherwise
 * return -1.
 */
static int match_mpidr(u64 sgi_aff, u16 sgi_cpu_mask, struct kvm_vcpu *vcpu)
{
	unsigned long affinity;
	int level0;

	/*
	 * Split the current VCPU's MPIDR into affinity level 0 and the
	 * rest as this is what we have to compare against.
	 */
	affinity = kvm_vcpu_get_mpidr_aff(vcpu);
	level0 = MPIDR_AFFINITY_LEVEL(affinity, 0);
	affinity &= ~MPIDR_LEVEL_MASK;

	/* bail out if the upper three levels don't match */
	if (sgi_aff != affinity)
		return -1;

	/* Is this VCPU's bit set in the mask ? */
	if (!(sgi_cpu_mask & BIT(level0)))
		return -1;

	return level0;
}

/*
 * The ICC_SGI* registers encode the affinity differently from the MPIDR,
 * so provide a wrapper to use the existing defines to isolate a certain
 * affinity level.
 */
#define SGI_AFFINITY_LEVEL(reg, level) \
	((((reg) & ICC_SGI1R_AFFINITY_## level ##_MASK) \
	>> ICC_SGI1R_AFFINITY_## level ##_SHIFT) << MPIDR_LEVEL_SHIFT(level))

/**
 * vgic_v3_dispatch_sgi - handle SGI requests from VCPUs
 * @vcpu: The VCPU requesting a SGI
 * @reg: The value written into the ICC_SGI1R_EL1 register by that VCPU
 *
 * With GICv3 (and ARE=1) CPUs trigger SGIs by writing to a system register.
 * This will trap in sys_regs.c and call this function.
 * This ICC_SGI1R_EL1 register contains the upper three affinity levels of the
 * target processors as well as a bitmask of 16 Aff0 CPUs.
 * If the interrupt routing mode bit is not set, we iterate over all VCPUs to
 * check for matching ones. If this bit is set, we signal all, but not the
 * calling VCPU.
 */
void vgic_v3_dispatch_sgi(struct kvm_vcpu *vcpu, u64 reg)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu *c_vcpu;
	u16 target_cpus;
	u64 mpidr;
	int sgi, c;
	int vcpu_id = vcpu->vcpu_id;
	bool broadcast;

	sgi = (reg & ICC_SGI1R_SGI_ID_MASK) >> ICC_SGI1R_SGI_ID_SHIFT;
	broadcast = reg & BIT(ICC_SGI1R_IRQ_ROUTING_MODE_BIT);
	target_cpus = (reg & ICC_SGI1R_TARGET_LIST_MASK) >> ICC_SGI1R_TARGET_LIST_SHIFT;
	mpidr = SGI_AFFINITY_LEVEL(reg, 3);
	mpidr |= SGI_AFFINITY_LEVEL(reg, 2);
	mpidr |= SGI_AFFINITY_LEVEL(reg, 1);

	/*
	 * We iterate over all VCPUs to find the MPIDRs matching the request.
	 * If we have handled one CPU, we clear its bit to detect early
	 * if we are already finished. This avoids iterating through all
	 * VCPUs when most of the times we just signal a single VCPU.
	 */
	kvm_for_each_vcpu(c, c_vcpu, kvm) {
		struct vgic_irq *irq;

		/* Exit early if we have dealt with all requested CPUs */
		if (!broadcast && target_cpus == 0)
			break;

		/* Don't signal the calling VCPU */
		if (broadcast && c == vcpu_id)
			continue;

		if (!broadcast) {
			int level0;

			level0 = match_mpidr(mpidr, target_cpus, c_vcpu);
			if (level0 == -1)
				continue;

			/* remove this matching VCPU from the mask */
			target_cpus &= ~BIT(level0);
		}

		irq = vgic_get_irq(vcpu->kvm, c_vcpu, sgi);

		spin_lock(&irq->irq_lock);
		irq->pending = true;

		vgic_queue_irq_unlock(vcpu->kvm, irq);
	}
}
