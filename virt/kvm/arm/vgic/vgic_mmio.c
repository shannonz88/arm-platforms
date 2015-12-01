/*
 * VGIC MMIO handling functions
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

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <kvm/iodev.h>
#include <kvm/vgic/vgic.h>
#include <linux/bitops.h>
#include <linux/irqchip/arm-gic.h>

#include "vgic.h"
#include "vgic_mmio.h"

void write_mask32(u32 value, int offset, int len, void *val)
{
	value = cpu_to_le32(value) >> (offset * 8);
	memcpy(val, &value, len);
}

u32 mask32(u32 origvalue, int offset, int len, const void *val)
{
	origvalue &= ~((BIT_ULL(len) - 1) << (offset * 8));
	memcpy((char *)&origvalue + (offset * 8), val, len);
	return origvalue;
}

#ifdef CONFIG_KVM_ARM_VGIC_V3
void write_mask64(u64 value, int offset, int len, void *val)
{
	value = cpu_to_le64(value) >> (offset * 8);
	memcpy(val, &value, len);
}

/* FIXME: I am clearly misguided here, there must be some saner way ... */
u64 mask64(u64 origvalue, int offset, int len, const void *val)
{
	origvalue &= ~((BIT_ULL(len) - 1) << (offset * 8));
	memcpy((char *)&origvalue + (offset * 8), val, len);
	return origvalue;
}
#endif

int vgic_mmio_read_raz(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
		       gpa_t addr, int len, void *val)
{
	memset(val, 0, len);

	return 0;
}

int vgic_mmio_read_rao(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
		       gpa_t addr, int len, void *val)
{
	memset(val, 0xff, len);

	return 0;
}

int vgic_mmio_write_wi(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
		       gpa_t addr, int len, const void *val)
{
	return 0;
}

static int vgic_mmio_read_nyi(struct kvm_vcpu *vcpu,
			      struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	pr_warn("KVM: handling unimplemented VGIC MMIO read: VCPU %d, address: 0x%llx\n",
		vcpu->vcpu_id, (unsigned long long)addr);
	return 0;
}

static int vgic_mmio_write_nyi(struct kvm_vcpu *vcpu,
			       struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	pr_warn("KVM: handling unimplemented VGIC MMIO write: VCPU %d, address: 0x%llx\n",
		vcpu->vcpu_id, (unsigned long long)addr);
	return 0;
}

struct vgic_register_region vgic_v2_dist_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_CTRL,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 12),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_IGROUP,
		vgic_mmio_read_rao, vgic_mmio_write_wi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ENABLE_SET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ENABLE_CLEAR,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PENDING_SET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PENDING_CLEAR,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ACTIVE_SET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ACTIVE_CLEAR,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PRI,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_TARGET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_CONFIG,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 8),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SOFTINT,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 4),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SGI_PENDING_CLEAR,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 16),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SGI_PENDING_SET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 16),
};

/* Find the proper register handler entry given a certain address offset. */
static struct vgic_register_region *
vgic_find_mmio_region(struct vgic_register_region *region, int nr_regions,
		      int offset)
{
	int i;

	for (i = 0; i < nr_regions; i++) {
		int reg_size = region[i].len;

		if (!reg_size)
			reg_size = (region[i].bits_per_irq * 1024) / 8;

		if ((offset < region[i].reg_offset) ||
		    (offset >= region[i].reg_offset + reg_size))
			continue;

		return region + i;
	}

	return NULL;
}

static int dispatch_mmio_read(struct kvm_vcpu *vcpu,
			      struct vgic_register_region *regions,
			      int nr_regions, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	struct vgic_register_region *region;

	region = vgic_find_mmio_region(regions, nr_regions,
				       addr - iodev->base_addr);
	if (!region)
		return -EOPNOTSUPP;

	return region->ops.read(vcpu, dev, addr, len, val);
}

static int dispatch_mmio_write(struct kvm_vcpu *vcpu,
			       struct vgic_register_region *regions,
			       int nr_regions, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	struct vgic_register_region *region;

	region = vgic_find_mmio_region(regions, nr_regions,
				       addr - iodev->base_addr);
	if (!region)
		return -EOPNOTSUPP;

	return region->ops.write(vcpu, dev, addr, len, val);
}

int vgic_mmio_read_v2dist(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			  gpa_t addr, int len, void *val)
{
	return dispatch_mmio_read(vcpu, vgic_v2_dist_registers,
				  ARRAY_SIZE(vgic_v2_dist_registers), dev,
				  addr, len, val);
}

int vgic_mmio_write_v2dist(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			   gpa_t addr, int len, const void *val)
{
	return dispatch_mmio_write(vcpu, vgic_v2_dist_registers,
				   ARRAY_SIZE(vgic_v2_dist_registers), dev,
				   addr, len, val);
}

struct kvm_io_device_ops kvm_io_v2dist_ops = {
	.read = vgic_mmio_read_v2dist,
	.write = vgic_mmio_write_v2dist,
};

int vgic_register_dist_iodev(struct kvm *kvm, gpa_t dist_base_address,
			     enum vgic_type type)
{
	struct vgic_io_device *io_device = &kvm->arch.vgic.dist_iodev;
	int ret = 0;
	int len;

	switch (type) {
	case VGIC_V2:
		kvm_iodevice_init(&io_device->dev, &kvm_io_v2dist_ops);
		len = SZ_4K;
		break;
	default:
		BUG_ON(1);
	}

	io_device->base_addr = dist_base_address;

	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, dist_base_address,
				      len, &io_device->dev);
	mutex_unlock(&kvm->slots_lock);

	return ret;
}
