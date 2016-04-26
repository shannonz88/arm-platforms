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

#include <linux/bitops.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <kvm/iodev.h>
#include <kvm/vgic/vgic.h>

#include "vgic.h"
#include "vgic_mmio.h"

/* extract @num bytes at @offset bytes offset in data */
unsigned long extract_bytes(unsigned long data,
			    unsigned int offset, unsigned int num)
{
	return (data >> (offset * 8)) & GENMASK_ULL(num * 8 - 1, 0);
}

unsigned long vgic_mmio_read_raz(struct kvm_vcpu *vcpu,
				 gpa_t addr, unsigned int len)
{
	return 0;
}

unsigned long vgic_mmio_read_rao(struct kvm_vcpu *vcpu,
				 gpa_t addr, unsigned int len)
{
	return -1UL;
}

void vgic_mmio_write_wi(struct kvm_vcpu *vcpu, gpa_t addr,
			unsigned int len, unsigned long val)
{
	/* Ignore */
}

/*
 * Read accesses to both GICD_ICENABLER and GICD_ISENABLER return the value
 * of the enabled bit, so there is only one function for both here.
 */
unsigned long vgic_mmio_read_enable(struct kvm_vcpu *vcpu,
				    gpa_t addr, unsigned int len)
{
	u32 intid = (addr & 0x7f) * 8;
	u32 value = 0;
	int i;

	/* Loop over all IRQs affected by this read */
	for (i = 0; i < len * 8; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->enabled)
			value |= (1U << i);
	}

	return extract_bytes(value, addr & 3, len);
}

void vgic_mmio_write_senable(struct kvm_vcpu *vcpu,
			     gpa_t addr, unsigned int len,
			     unsigned long val)
{
	u32 intid = (addr & 0x7f) * 8;
	int i;

	for_each_set_bit(i, &val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		irq->enabled = true;
		vgic_queue_irq_unlock(vcpu->kvm, irq);
	}
}

void vgic_mmio_write_cenable(struct kvm_vcpu *vcpu,
			     gpa_t addr, unsigned int len,
			     unsigned long val)
{
	u32 intid = (addr & 0x7f) * 8;
	int i;

	for_each_set_bit(i, &val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		irq->enabled = false;

		spin_unlock(&irq->irq_lock);
	}
}

unsigned long vgic_mmio_read_pending(struct kvm_vcpu *vcpu,
				     gpa_t addr, unsigned int len)
{
	u32 intid = (addr & 0x7f) * 8;
	u32 value = 0;
	int i;

	/* Loop over all IRQs affected by this read */
	for (i = 0; i < len * 8; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->pending)
			value |= (1U << i);
	}

	return extract_bytes(value, addr & 3, len);
}

void vgic_mmio_write_spending(struct kvm_vcpu *vcpu,
			      gpa_t addr, unsigned int len,
			      unsigned long val)
{
	u32 intid = (addr & 0x7f) * 8;
	int i;

	for_each_set_bit(i, &val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		irq->pending = true;
		if (irq->config == VGIC_CONFIG_LEVEL)
			irq->soft_pending = true;

		vgic_queue_irq_unlock(vcpu->kvm, irq);
	}
}

void vgic_mmio_write_cpending(struct kvm_vcpu *vcpu,
			      gpa_t addr, unsigned int len,
			      unsigned long val)
{
	u32 intid = (addr & 0x7f) * 8;
	int i;

	for_each_set_bit(i, &val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		if (irq->config == VGIC_CONFIG_LEVEL) {
			irq->soft_pending = false;
			irq->pending = irq->line_level;
		} else {
			irq->pending = false;
		}

		spin_unlock(&irq->irq_lock);
	}
}

unsigned long vgic_mmio_read_active(struct kvm_vcpu *vcpu,
				    gpa_t addr, unsigned int len)
{
	u32 intid = (addr & 0x7f) * 8;
	u32 value = 0;
	int i;

	/* Loop over all IRQs affected by this read */
	for (i = 0; i < len * 8; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->active)
			value |= (1U << i);
	}

	return extract_bytes(value, addr & 3, len);
}

void vgic_mmio_write_cactive(struct kvm_vcpu *vcpu,
			     gpa_t addr, unsigned int len,
			     unsigned long val)
{
	u32 intid = (addr & 0x7f) * 8;
	int i;

	for_each_set_bit(i, &val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		irq->active = false;

		/*
		 * Christoffer wrote:
		 * The question is what to do if the vcpu for this irq is
		 * running and the LR there has the active bit set, then we'll
		 * overwrite this change when we fold the LR state back into
		 * the vgic_irq struct.
		 *
		 * Since I expect this to be extremely rare, one option is to
		 * force irq->vcpu to exit (if non-null) and then do you
		 * thing here after you've confirm it has exited while holding
		 * some lock preventing it from re-entering again.
		 * Slightly crazy.
		 *
		 * The alternative is to put a big fat comment nothing that
		 * this is non-supported bad race, and wait until someone
		 * submits a bug report relating to this...
		 */

		spin_unlock(&irq->irq_lock);
	}
}

void vgic_mmio_write_sactive(struct kvm_vcpu *vcpu,
			     gpa_t addr, unsigned int len,
			     unsigned long val)
{
	u32 intid = (addr & 0x7f) * 8;
	int i;

	for_each_set_bit(i, &val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		/* As this is a special case, we can't use the
		 * vgic_queue_irq_unlock() function to put this on a VCPU.
		 * So deal with this here explicitly unless the IRQs was
		 * already active, it was on a VCPU before or there is no
		 * target VCPU assigned at the moment.
		 */
		if (irq->active || irq->vcpu || !irq->target_vcpu) {
			irq->active = true;

			spin_unlock(&irq->irq_lock);
			continue;
		}

		spin_unlock(&irq->irq_lock);
retry:
		vcpu = irq->target_vcpu;

		spin_lock(&vcpu->arch.vgic_cpu.ap_list_lock);
		spin_lock(&irq->irq_lock);

		/*
		 * Recheck after dropping the IRQ lock to see if we should
		 * still care about queueing it.
		 */
		if (irq->active || irq->vcpu) {
			irq->active = true;

			spin_unlock(&irq->irq_lock);
			spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);

			continue;
		}

		/* Did the target VCPU change while we had the lock dropped? */
		if (vcpu != irq->target_vcpu) {
			spin_unlock(&irq->irq_lock);
			spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);

			goto retry;
		}

		/* Now queue the IRQ to the VCPU's ap_list. */
		list_add_tail(&irq->ap_list, &vcpu->arch.vgic_cpu.ap_list_head);
		irq->vcpu = vcpu;

		irq->active = true;

		spin_unlock(&irq->irq_lock);
		spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);

		kvm_vcpu_kick(vcpu);
	}
}

unsigned long vgic_mmio_read_priority(struct kvm_vcpu *vcpu,
				      gpa_t addr, unsigned int len)
{
	u32 intid = addr & 0x3ff;
	int i;
	u64 val = 0;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		val |= (u64)irq->priority << (i * 8);
	}

	return val;
}

void vgic_mmio_write_priority(struct kvm_vcpu *vcpu,
			      gpa_t addr, unsigned int len,
			      unsigned long val)
{
	u32 intid = addr & 0x3ff;
	int i;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		irq->priority = (val >> (i * 8)) & 0xff;
		spin_unlock(&irq->irq_lock);
	}
}

unsigned long vgic_mmio_read_config(struct kvm_vcpu *vcpu,
				    gpa_t addr, unsigned int len)
{
	u32 intid = (addr & 0xff) * 4;
	u32 value = 0;
	int i;

	for (i = 0; i < len * 4; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->config == VGIC_CONFIG_EDGE)
			value |= (2U << (i * 2));
	}

	return extract_bytes(value, addr & 3, len);
}

void vgic_mmio_write_config(struct kvm_vcpu *vcpu,
			    gpa_t addr, unsigned int len,
			    unsigned long val)
{
	u32 intid = (addr & 0xff) * 4;
	int i;

	for (i = 0; i < len * 4; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (intid + i < 16)
			continue;

		/*
		 * The spec says that interrupts must be disabled before
		 * changing the configuration to avoid UNDEFINED behaviour.
		 */

		spin_lock(&irq->irq_lock);
		if (test_bit(i * 2 + 1, &val)) {
			irq->config = VGIC_CONFIG_EDGE;
		} else {
			irq->config = VGIC_CONFIG_LEVEL;
			irq->pending = irq->line_level | irq->soft_pending;
		}
		spin_unlock(&irq->irq_lock);
	}
}

/* Find the proper register handler entry given a certain address offset. */
static const struct vgic_register_region *
vgic_find_mmio_region(const struct vgic_register_region *region, int nr_regions,
		      unsigned int offset)
{
	int i;

	for (i = 0; i < nr_regions; i++) {
		if ((offset < region[i].reg_offset) ||
		    (offset >= region[i].reg_offset + region[i].len))
			continue;

		return region + i;
	}

	return NULL;
}

/*
 * kvm_mmio_read_buf() returns a value in a format where it can be converted
 * to a byte array and be directly observed as the guest wanted it to appear
 * in memory if it had done the store itself, which is LE for the GIC, as the
 * guest knows the GIC is always LE.
 *
 * We convert this value to the CPUs native format to deal with it as a data
 * value.
 */
unsigned long vgic_data_mmio_bus_to_host(const void *val, unsigned int len)
{
	unsigned long data = kvm_mmio_read_buf(val, len);
	switch (len) {
	case 1:
		return data;
	case 2:
		return le16_to_cpu(data);
	case 4:
		return le32_to_cpu(data);
	default:
		return le64_to_cpu(data);
	}
}

/*
 * kvm_mmio_write_buf() expects a value in a format such that if converted to
 * a byte array it is observed as the guest would see it if it could perform
 * the load directly.  Since the GIC is LE, and the guest knows this, the
 * guest expects a value in little endian format.
 *
 * We convert the data value from the CPUs native format to LE so that the
 * value is returned in the proper format.
 */
void vgic_data_host_to_mmio_bus(void *buf, unsigned int len,
				unsigned long data)
{
	switch (len) {
	case 1:
		break;
	case 2:
		data = cpu_to_le16(data);
		break;
	case 4:
		data = cpu_to_le32(data);
		break;
	default:
		data = cpu_to_le64(data);
	}

	kvm_mmio_write_buf(buf, len, data);
}

static int dispatch_mmio_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = kvm_to_vgic_iodev(dev);
	const struct vgic_register_region *region;
	struct kvm_vcpu *r_vcpu;
	unsigned long data;

	region = vgic_find_mmio_region(iodev->regions, iodev->nr_regions,
				       addr - iodev->base_addr);
	if (!region)
		return -EOPNOTSUPP;

	r_vcpu = iodev->redist_vcpu ? iodev->redist_vcpu : vcpu;
	data = region->ops.read(r_vcpu, addr, len);
	vgic_data_host_to_mmio_bus(val, len, data);
	return 0;
}

static int dispatch_mmio_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = kvm_to_vgic_iodev(dev);
	const struct vgic_register_region *region;
	struct kvm_vcpu *r_vcpu;
	unsigned long data = vgic_data_mmio_bus_to_host(val, len);

	region = vgic_find_mmio_region(iodev->regions, iodev->nr_regions,
				       addr - iodev->base_addr);
	if (!region)
		return -EOPNOTSUPP;

	r_vcpu = iodev->redist_vcpu ? iodev->redist_vcpu : vcpu;
	region->ops.write(r_vcpu, addr, len, data);
	return 0;
}

struct kvm_io_device_ops kvm_io_gic_ops = {
	.read = dispatch_mmio_read,
	.write = dispatch_mmio_write,
};

int vgic_register_dist_iodev(struct kvm *kvm, gpa_t dist_base_address,
			     enum vgic_type type)
{
	struct vgic_io_device *io_device = &kvm->arch.vgic.dist_iodev;
	int ret = 0;
	unsigned int len;

	switch (type) {
	case VGIC_V2:
		len = vgic_v2_init_dist_iodev(io_device);
		break;
#ifdef CONFIG_KVM_ARM_VGIC_V3
	case VGIC_V3:
		len = vgic_v3_init_dist_iodev(io_device);
		break;
#endif
	default:
		BUG_ON(1);
	}

	io_device->base_addr = dist_base_address;
	io_device->redist_vcpu = NULL;

	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, dist_base_address,
				      len, &io_device->dev);
	mutex_unlock(&kvm->slots_lock);

	return ret;
}
