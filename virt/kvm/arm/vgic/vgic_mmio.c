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
#include <linux/irqchip/arm-gic-v3.h>
#include <asm/kvm_emulate.h>

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

/*****************************/
/* GICv3 emulation functions */
/*****************************/
#ifdef CONFIG_KVM_ARM_VGIC_V3

static int vgic_mmio_read_v3_misc(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *dev,
				  gpa_t addr, int len, void *val)
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

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_v3_misc(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *dev,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	bool was_enabled = dist->enabled;

	/* Of the whole region only the first byte is actually writeable. */
	if ((addr & 0x0f) > 0)
		return 0;

	/* We only care about the enable bit, all other bits are WI. */
	dist->enabled = *(u8*)val & GICD_CTLR_ENABLE_SS_G1;

	if (!was_enabled && dist->enabled)
		vgic_kick_vcpus(vcpu->kvm);

	return 0;
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

static int vgic_mmio_read_irouter(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *dev,
				  gpa_t addr, int len, void *val)
{
	int intid = (addr & 0x1fff) / 8;
	struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, NULL, intid);

	if (!irq) {
		memset(val, 0, len);
		return 0;
	}

	write_mask64(decompress_mpidr(irq->mpidr), addr & 7, len, val);

	return 0;
}

static int vgic_mmio_write_irouter(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *dev,
				   gpa_t addr, int len, const void *val)
{
	int intid = (addr & 0x1fff) / 8;
	struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, NULL, intid);
	u64 mpidr;

	if (!irq)
		return 0;

	mpidr = decompress_mpidr(irq->mpidr);
	mpidr = mask64(mpidr, addr & 7, len, val);

	spin_lock(&irq->irq_lock);

	irq->mpidr = compress_mpidr(mpidr);
	irq->target_vcpu = kvm_mpidr_to_vcpu(vcpu->kvm, mpidr);

	spin_unlock(&irq->irq_lock);

	return 0;
}

static int vgic_mmio_read_v3r_typer(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev,
				    gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	unsigned long mpidr = kvm_vcpu_get_mpidr_aff(iodev->redist_vcpu);
	int target_vcpu_id = iodev->redist_vcpu->vcpu_id;
	u64 value;

	value = (u64)compress_mpidr(mpidr) << 32;
	value |= ((target_vcpu_id & 0xffff) << 8);
	if (target_vcpu_id == atomic_read(&vcpu->kvm->online_vcpus) - 1)
		value |= GICR_TYPER_LAST;

	write_mask64(value, addr & 7, len, val);
	return 0;
}

static int vgic_mmio_read_v3r_iidr(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *dev,
				   gpa_t addr, int len, void *val)
{
	write_mask32((PRODUCT_ID_KVM << 24) | (IMPLEMENTER_ARM << 0),
		     addr & 3, len, val);

	return 0;
}

static int vgic_mmio_read_v3_idregs(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev,
				    gpa_t addr, int len, void *val)
{
	u32 regnr = (addr & 0x3f) - (GICD_IDREGS & 0x3f);
	u32 reg = 0;

	switch (regnr + GICD_IDREGS) {
	case GICD_PIDR2:
		/* report a GICv3 compliant implementation */
		reg = 0x3b;
		break;
	}

	write_mask32(reg , addr & 3, len, val);
	return 0;
}
#endif

/*
 * The GICv3 per-IRQ registers are split to control PPIs and SGIs in the
 * redistributors, while SPIs are covered by registers in the distributor
 * block. Trying to set private IRQs in this block gets ignored.
 * We take some special care here to fix the calculation of the register
 * offset.
 */
#define REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(name, read_ops, write_ops, bpi) \
	{.reg_offset = name, .bits_per_irq = 0, \
	 .len = (bpi * VGIC_NR_PRIVATE_IRQS) / 8, \
	 .ops.read = vgic_mmio_read_raz, .ops.write = vgic_mmio_write_wi, }, \
	{.reg_offset = name, .bits_per_irq = bpi, .len = 0, \
	 .ops.read = read_ops, .ops.write = write_ops, }

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

#ifdef CONFIG_KVM_ARM_VGIC_V3
struct vgic_register_region vgic_v3_dist_registers[] = {
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

struct vgic_register_region vgic_v3_redist_registers[] = {
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

struct vgic_register_region vgic_v3_private_registers[] = {
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
#endif

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

#ifdef CONFIG_KVM_ARM_VGIC_V3
int vgic_mmio_read_v3dist(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			  gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	struct vgic_register_region *region;
	int offset = addr - iodev->base_addr;

	region = vgic_find_mmio_region(vgic_v3_dist_registers,
				       ARRAY_SIZE(vgic_v3_dist_registers),
				       offset);
	if (!region)
		return 1;

	/* Private IRQs are RAZ on the GICv3 distributor. */
	if (region->bits_per_irq) {
		offset -= region->reg_offset;
		if ((offset * 8 / region->bits_per_irq) < VGIC_NR_PRIVATE_IRQS)
			return vgic_mmio_read_raz(vcpu, dev, addr, len, val);
	}

	return region->ops.read(vcpu, dev, addr, len, val);
}

int vgic_mmio_write_v3dist(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(dev,
						    struct vgic_io_device, dev);
	struct vgic_register_region *region;
	int offset = addr - iodev->base_addr;

	region = vgic_find_mmio_region(vgic_v3_dist_registers,
				       ARRAY_SIZE(vgic_v3_dist_registers),
				       offset);
	if (!region)
		return 1;

	/* Private IRQs are WI on the GICv3 distributor. */
	if (region->bits_per_irq) {
		offset -= region->reg_offset;
		if ((offset * 8 / region->bits_per_irq) < VGIC_NR_PRIVATE_IRQS)
			return vgic_mmio_write_wi(vcpu, dev, addr, len, val);
	}

	return region->ops.write(vcpu, dev, addr, len, val);
}

struct kvm_io_device_ops kvm_io_v3dist_ops = {
	.read = vgic_mmio_read_v3dist,
	.write = vgic_mmio_write_v3dist,
};

int vgic_mmio_read_v3redist(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			    gpa_t addr, int len, void *val)
{
	return dispatch_mmio_read(vcpu, vgic_v3_redist_registers,
				  ARRAY_SIZE(vgic_v3_redist_registers), dev,
				  addr, len, val);
}

int vgic_mmio_write_v3redist(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			     gpa_t addr, int len, const void *val)
{
	return dispatch_mmio_write(vcpu, vgic_v3_redist_registers,
				   ARRAY_SIZE(vgic_v3_redist_registers), dev,
				   addr, len, val);
}

struct kvm_io_device_ops kvm_io_v3redist_ops = {
	.read = vgic_mmio_read_v3redist,
	.write = vgic_mmio_write_v3redist,
};

int vgic_mmio_read_v3redist_private(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev,
				    gpa_t addr, int len, void *val)
{
	return dispatch_mmio_read(vcpu, vgic_v3_private_registers,
				  ARRAY_SIZE(vgic_v3_private_registers), dev,
				  addr, len, val);
}

int vgic_mmio_write_v3redist_private(struct kvm_vcpu *vcpu,
				     struct kvm_io_device *dev,
				     gpa_t addr, int len, const void *val)
{
	return dispatch_mmio_write(vcpu, vgic_v3_private_registers,
				   ARRAY_SIZE(vgic_v3_private_registers), dev,
				   addr, len, val);
}

struct kvm_io_device_ops kvm_io_v3redist_private_ops = {
	.read = vgic_mmio_read_v3redist_private,
	.write = vgic_mmio_write_v3redist_private,
};

int vgic_v3_dist_access(struct kvm_vcpu *vcpu, bool is_write,
			int offset, int len, void *val)
{
	return vgic_device_mmio_access(vcpu, vgic_v3_dist_registers,
				       ARRAY_SIZE(vgic_v3_dist_registers),
				       is_write, offset, len, val);
}

int vgic_v3_redist_access(struct kvm_vcpu *vcpu, bool is_write,
			  int offset, int len, void *val)
{
	return vgic_device_mmio_access(vcpu, vgic_v3_redist_registers,
				       ARRAY_SIZE(vgic_v3_redist_registers),
				       is_write, offset, len, val);
}
#endif

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
#ifdef CONFIG_KVM_ARM_VGIC_V3
	case VGIC_V3:
		kvm_iodevice_init(&io_device->dev, &kvm_io_v3dist_ops);
		len = SZ_64K;
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

#ifdef CONFIG_KVM_ARM_VGIC_V3
int vgic_register_redist_iodevs(struct kvm *kvm, gpa_t redist_base_address)
{
	int nr_vcpus = atomic_read(&kvm->online_vcpus);
	struct kvm_vcpu *vcpu;
	struct vgic_io_device *regions, *region;
	int c, ret = 0;

	regions = kmalloc(sizeof(struct vgic_io_device) * nr_vcpus * 2,
			  GFP_KERNEL);
	if (!regions)
		return -ENOMEM;

	region = regions;
	kvm_for_each_vcpu(c, vcpu, kvm) {
		kvm_iodevice_init(&region->dev, &kvm_io_v3redist_ops);
		region->base_addr = redist_base_address;
		region->redist_vcpu = vcpu;

		mutex_lock(&kvm->slots_lock);
		ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
					      redist_base_address,
					      SZ_64K, &region->dev);
		mutex_unlock(&kvm->slots_lock);

		if (ret)
			break;

		region++;
		kvm_iodevice_init(&region->dev, &kvm_io_v3redist_private_ops);
		region->base_addr = redist_base_address + SZ_64K;
		region->redist_vcpu = vcpu;

		mutex_lock(&kvm->slots_lock);
		ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
					      redist_base_address + SZ_64K,
					      SZ_64K, &region->dev);
		mutex_unlock(&kvm->slots_lock);
		if (ret) {
			kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS,
						  &regions[c * 2].dev);
			break;
		}
		region++;
		redist_base_address += 2 * SZ_64K;
	}

	if (ret) {
		for (c--; c >= 0; c--) {
			kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS,
						  &regions[c * 2].dev);
			kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS,
						  &regions[c * 2 + 1].dev);
		}
	} else {
		kvm->arch.vgic.redist_iodevs = regions;
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
#endif

int vgic_v2_has_attr_regs(struct kvm_device *dev, struct kvm_device_attr *attr)
{
	int nr_irqs = dev->kvm->arch.vgic.nr_spis + VGIC_NR_PRIVATE_IRQS;
	struct vgic_register_region *regions;
	gpa_t addr;
	int nr_regions, i, len;

	addr = attr->attr & KVM_DEV_ARM_VGIC_OFFSET_MASK;

	switch (attr->group) {
	case KVM_DEV_ARM_VGIC_GRP_DIST_REGS:
		regions = vgic_v2_dist_registers;
		nr_regions = ARRAY_SIZE(vgic_v2_dist_registers);
		break;
	case KVM_DEV_ARM_VGIC_GRP_CPU_REGS:
		return -ENXIO;		/* TODO: describe CPU i/f regs also */
	default:
		return -ENXIO;
	}

	for (i = 0; i < nr_regions; i++) {
		if (regions[i].bits_per_irq)
			len = (regions[i].bits_per_irq * nr_irqs) / 8;
		else
			len = regions[i].len;

		if (regions[i].reg_offset <= addr &&
		    regions[i].reg_offset + len > addr)
			return 0;
	}

	return -ENXIO;
}
