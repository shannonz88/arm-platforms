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

static int vgic_mmio_read_v2_misc(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *dev,
				  gpa_t addr, int len, void *val)
{
	u32 value;

	switch (addr & 0x0c) {
	case 0x0:
		value = vcpu->kvm->arch.vgic.enabled ? GICD_ENABLE : 0;
		break;
	case 0x4:
		value = vcpu->kvm->arch.vgic.nr_spis + VGIC_NR_PRIVATE_IRQS;
		value = (value >> 5) - 1;
		value |= (atomic_read(&vcpu->kvm->online_vcpus) - 1) << 5;
		break;
	case 0x8:
		value = (PRODUCT_ID_KVM << 24) | (IMPLEMENTER_ARM << 0);
		break;
	default:
		return 0;
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_v2_misc(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *dev,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	bool was_enabled = dist->enabled;

	/*
	 * GICD_TYPER and GICD_IIDR are read-only, the upper three bytes of
	 * GICD_CTLR are reserved.
	 */
	if ((addr & 0x0f) >= 1)
		return 0;

	vcpu->kvm->arch.vgic.enabled = (*(u32 *)val) ? true : false;

	if (!was_enabled && dist->enabled)
		vgic_kick_vcpus(vcpu->kvm);

	return 0;
}

/*
 * Read accesses to both GICD_ICENABLER and GICD_ISENABLER return the value
 * of the enabled bit, so there is only one function for both here.
 */
static int vgic_mmio_read_enable(struct kvm_vcpu *vcpu,
				 struct kvm_io_device *dev,
				 gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0x7f) * 8;
	u32 value = 0;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	/* Loop over all IRQs affected by this read */
	for (i = 0; i < len * 8; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->enabled)
			value |= (1U << i);
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_senable(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *dev,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0x7f) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		irq->enabled = true;
		vgic_queue_irq_unlock(vcpu->kvm, irq);
	}

	return 0;
}

static int vgic_mmio_write_cenable(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *dev,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0x7f) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		irq->enabled = false;

		spin_unlock(&irq->irq_lock);
	}
	return 0;
}

static int vgic_mmio_read_pending(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *dev,
				  gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0x7f) * 8;
	u32 value = 0;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	/* Loop over all IRQs affected by this read */
	for (i = 0; i < len * 8; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->pending)
			value |= (1U << i);
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_spending(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev,
				    gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0x7f) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		irq->pending = true;
		if (irq->config == VGIC_CONFIG_LEVEL)
			irq->soft_pending = true;

		vgic_queue_irq_unlock(vcpu->kvm, irq);
	}

	return 0;
}

static int vgic_mmio_write_cpending(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev,
				    gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0x7f) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
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
	return 0;
}

static int vgic_mmio_read_active(struct kvm_vcpu *vcpu,
				 struct kvm_io_device *dev,
				 gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0x7f) * 8;
	u32 value = 0;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	/* Loop over all IRQs affected by this read */
	for (i = 0; i < len * 8; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->active)
			value |= (1U << i);
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_cactive(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *dev,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0x7f) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
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
	return 0;
}

static int vgic_mmio_write_sactive(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *dev,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0x7f) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
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
	return 0;
}

static int vgic_mmio_read_priority(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *dev,
				   gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = addr & 0x3ff;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		((u8 *)val)[i] = irq->priority;
	}

	return 0;
}

static int vgic_mmio_write_priority(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev,
				    gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = addr & 0x3ff;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		irq->priority = ((u8 *)val)[i];
		spin_unlock(&irq->irq_lock);
	}

	return 0;
}

static int vgic_mmio_read_config(struct kvm_vcpu *vcpu,
				 struct kvm_io_device *dev,
				 gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0xff) * 4;
	u32 value = 0;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for (i = 0; i < len * 4; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->config == VGIC_CONFIG_EDGE)
			value |= (2U << (i * 2));
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_config(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *dev,
				  gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	u32 intid = (addr & 0xff) * 4;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for (i = 0; i < len * 4; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (intid + i < 16)
			continue;

		/*
		 * The spec says that interrupts must be disabled before
		 * changing the configuration to avoid UNDEFINED behaviour.
		 */

		spin_lock(&irq->irq_lock);
		if (test_bit(i * 2 + 1, val)) {
			irq->config = VGIC_CONFIG_EDGE;
		} else {
			irq->config = VGIC_CONFIG_LEVEL;
			irq->pending = irq->line_level | irq->soft_pending;
		}
		spin_unlock(&irq->irq_lock);
	}

	return 0;
}

static int vgic_mmio_read_target(struct kvm_vcpu *vcpu,
				 struct kvm_io_device *dev,
				 gpa_t addr, int len, void *val)
{
	u32 intid = addr & 0x3ff;
	int i;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		((u8 *)val)[i] = irq->targets;
	}

	return 0;
}

static int vgic_mmio_write_target(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *dev,
				  gpa_t addr, int len, const void *val)
{
	u32 intid = addr & 0x3ff;
	int i;

	/* GICD_ITARGETSR[0-7] are read-only */
	if (intid < VGIC_NR_PRIVATE_IRQS)
		return 0;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, NULL, intid + i);
		int target;

		spin_lock(&irq->irq_lock);

		irq->targets = ((u8 *)val)[i];
		target = irq->targets ? __ffs(irq->targets) : 0;
		irq->target_vcpu = kvm_get_vcpu(vcpu->kvm, target);

		spin_unlock(&irq->irq_lock);
	}

	return 0;
}

static int vgic_mmio_write_sgir(struct kvm_vcpu *source_vcpu,
				struct kvm_io_device *dev,
				gpa_t addr, int len, const void *val)
{
	int nr_vcpus = atomic_read(&source_vcpu->kvm->online_vcpus);
	u32 value = *(u32 *)val;
	int intid = value & 0xf;
	int targets = (value >> 16) & 0xff;
	int mode = (value >> 24) & 0x03;
	int c;
	struct kvm_vcpu *vcpu;

	switch (mode) {
	case 0x0:		/* as specified by targets */
		break;
	case 0x1:
		targets = (1U << nr_vcpus) - 1;			/* all, ... */
		targets &= ~(1U << source_vcpu->vcpu_id);	/* but self */
		break;
	case 0x2:		/* this very vCPU only */
		targets = (1U << source_vcpu->vcpu_id);
		break;
	case 0x3:		/* reserved */
		return 0;
	}

	kvm_for_each_vcpu(c, vcpu, source_vcpu->kvm) {
		struct vgic_irq *irq;

		if (!(targets & (1U << c)))
			continue;

		irq = vgic_get_irq(source_vcpu->kvm, vcpu, intid);

		spin_lock(&irq->irq_lock);
		irq->pending = true;
		irq->source |= 1U << source_vcpu->vcpu_id;

		vgic_queue_irq_unlock(source_vcpu->kvm, irq);
	}

	return 0;
}

static int vgic_mmio_read_sgipend(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *dev,
				  gpa_t addr, int len, void *val)
{
	u32 intid = addr & 0x0f;
	int i;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		((u8 *)val)[i] = irq->source;
	}
	return 0;
}

static int vgic_mmio_write_sgipendc(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev,
				    gpa_t addr, int len, const void *val)
{
	u32 intid = addr & 0x0f;
	int i;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		irq->source &= ~((u8 *)val)[i];
		if (!irq->source)
			irq->pending = false;

		spin_unlock(&irq->irq_lock);
	}
	return 0;
}

static int vgic_mmio_write_sgipends(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev,
				    gpa_t addr, int len, const void *val)
{
	u32 intid = addr & 0x0f;
	int i;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		irq->source |= ((u8 *)val)[i];

		if (irq->source) {
			irq->pending = true;
			vgic_queue_irq_unlock(vcpu->kvm, irq);
		} else {
			spin_unlock(&irq->irq_lock);
		}
	}
	return 0;
}

struct vgic_register_region vgic_v2_dist_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_CTRL,
		vgic_mmio_read_v2_misc, vgic_mmio_write_v2_misc, 12),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_IGROUP,
		vgic_mmio_read_rao, vgic_mmio_write_wi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ENABLE_SET,
		vgic_mmio_read_enable, vgic_mmio_write_senable, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ENABLE_CLEAR,
		vgic_mmio_read_enable, vgic_mmio_write_cenable, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PENDING_SET,
		vgic_mmio_read_pending, vgic_mmio_write_spending, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PENDING_CLEAR,
		vgic_mmio_read_pending, vgic_mmio_write_cpending, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ACTIVE_SET,
		vgic_mmio_read_active, vgic_mmio_write_sactive, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ACTIVE_CLEAR,
		vgic_mmio_read_active, vgic_mmio_write_cactive, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PRI,
		vgic_mmio_read_priority, vgic_mmio_write_priority, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_TARGET,
		vgic_mmio_read_target, vgic_mmio_write_target, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_CONFIG,
		vgic_mmio_read_config, vgic_mmio_write_config, 2),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SOFTINT,
		vgic_mmio_read_raz, vgic_mmio_write_sgir, 4),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SGI_PENDING_CLEAR,
		vgic_mmio_read_sgipend, vgic_mmio_write_sgipendc, 16),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SGI_PENDING_SET,
		vgic_mmio_read_sgipend, vgic_mmio_write_sgipends, 16),
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

/*
 * When userland tries to access the VGIC register handlers, we need to
 * create a usable struct vgic_io_device to be passed to the handlers.
 */
static int vgic_device_mmio_access(struct kvm_vcpu *vcpu,
				   struct vgic_register_region *regions,
				   int nr_regions, bool is_write,
				   int offset, int len, void *val)
{
	struct vgic_io_device dev = {
		.base_addr = 0,
		.redist_vcpu = vcpu,
	};

	if (is_write)
		return dispatch_mmio_write(vcpu, regions, nr_regions,
					   &dev.dev, offset, len, val);
	else
		return dispatch_mmio_read(vcpu, regions, nr_regions,
					  &dev.dev, offset, len, val);
}

int vgic_v2_dist_access(struct kvm_vcpu *vcpu, bool is_write,
			int offset, int len, void *val)
{
	return vgic_device_mmio_access(vcpu, vgic_v2_dist_registers,
				       ARRAY_SIZE(vgic_v2_dist_registers),
				       is_write, offset, len, val);
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
