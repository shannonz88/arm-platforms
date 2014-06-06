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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/uaccess.h>

#include <linux/irqchip/arm-gic.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

/*
 * How the whole thing works (courtesy of Christoffer Dall):
 *
 * - At any time, the dist->irq_pending_on_cpu is the oracle that knows if
 *   something is pending
 * - VGIC pending interrupts are stored on the vgic.irq_state vgic
 *   bitmap (this bitmap is updated by both user land ioctls and guest
 *   mmio ops, and other in-kernel peripherals such as the
 *   arch. timers) and indicate the 'wire' state.
 * - Every time the bitmap changes, the irq_pending_on_cpu oracle is
 *   recalculated
 * - To calculate the oracle, we need info for each cpu from
 *   compute_pending_for_cpu, which considers:
 *   - PPI: dist->irq_state & dist->irq_enable
 *   - SPI: dist->irq_state & dist->irq_enable & dist->irq_spi_target
 *   - irq_spi_target is a 'formatted' version of the GICD_ICFGR
 *     registers, stored on each vcpu. We only keep one bit of
 *     information per interrupt, making sure that only one vcpu can
 *     accept the interrupt.
 * - The same is true when injecting an interrupt, except that we only
 *   consider a single interrupt at a time. The irq_spi_cpu array
 *   contains the target CPU for each SPI.
 *
 * The handling of level interrupts adds some extra complexity. We
 * need to track when the interrupt has been EOIed, so we can sample
 * the 'line' again. This is achieved as such:
 *
 * - When a level interrupt is moved onto a vcpu, the corresponding
 *   bit in irq_active is set. As long as this bit is set, the line
 *   will be ignored for further interrupts. The interrupt is injected
 *   into the vcpu with the GICH_LR_EOI bit set (generate a
 *   maintenance interrupt on EOI).
 * - When the interrupt is EOIed, the maintenance interrupt fires,
 *   and clears the corresponding bit in irq_active. This allow the
 *   interrupt line to be sampled again.
 */

#include "vgic.h"

#define GICC_ARCH_VERSION_V2	0x2

static void vgic_retire_disabled_irqs(struct kvm_vcpu *vcpu);
static void vgic_retire_lr(int lr_nr, int irq, struct kvm_vcpu *vcpu);
static struct vgic_lr vgic_get_lr(const struct kvm_vcpu *vcpu, int lr);
static void vgic_set_lr(struct kvm_vcpu *vcpu, int lr, struct vgic_lr lr_desc);

static const struct vgic_ops *vgic_ops;
static const struct vgic_params *vgic;

#define vgic_vm_op(kvm, fn) ((kvm)->arch.vgic.vm_ops.fn)

static int vgic_init_bitmap(struct vgic_bitmap *b, int nr_cpus, int nr_irqs)
{
	int nr_longs;

	nr_longs = nr_cpus + BITS_TO_LONGS(nr_irqs - VGIC_NR_PRIVATE_IRQS);

	b->private = kzalloc(sizeof(unsigned long) * nr_longs, GFP_KERNEL);
	if (!b->private)
		return -ENOMEM;

	b->shared = b->private + nr_cpus;

	b->nr_cpus = nr_cpus;
	return 0;
}

static void vgic_free_bitmap(struct vgic_bitmap *b)
{
	kfree(b->private);
	b->private = NULL;
}

u32 *vgic_bitmap_get_reg(struct vgic_bitmap *x, int cpuid, u32 offset)
{
	offset >>= 2;
	if (!offset)
		return (u32 *)(x->private + cpuid);
	else
		return (u32 *)(x->shared) + offset - 1;
}

static int vgic_bitmap_get_irq_val(struct vgic_bitmap *x,
				   int cpuid, int irq)
{
	if (irq < VGIC_NR_PRIVATE_IRQS)
		return test_bit(irq, x->private + cpuid);

	return test_bit(irq - VGIC_NR_PRIVATE_IRQS, x->shared);
}

void vgic_bitmap_set_irq_val(struct vgic_bitmap *x, int cpuid,
			     int irq, int val)
{
	unsigned long *reg;

	if (irq < VGIC_NR_PRIVATE_IRQS) {
		reg = x->private + cpuid;
	} else {
		reg = x->shared;
		irq -= VGIC_NR_PRIVATE_IRQS;
	}

	if (val)
		set_bit(irq, reg);
	else
		clear_bit(irq, reg);
}

static unsigned long *vgic_bitmap_get_cpu_map(struct vgic_bitmap *x, int cpuid)
{
	return x->private + cpuid;
}

unsigned long *vgic_bitmap_get_shared_map(struct vgic_bitmap *x)
{
	return x->shared;
}

static int vgic_init_bytemap(struct vgic_bytemap *x, int nr_cpus, int nr_irqs)
{
	int size;

	size  = nr_cpus * VGIC_NR_PRIVATE_IRQS;
	size += nr_irqs - VGIC_NR_PRIVATE_IRQS;

	x->private = kzalloc(size, GFP_KERNEL);
	if (!x->private)
		return -ENOMEM;

	x->shared = x->private + nr_cpus * VGIC_NR_PRIVATE_IRQS / sizeof(u32);
	x->nr_cpus = nr_cpus;
	return 0;
}

static void vgic_free_bytemap(struct vgic_bytemap *b)
{
	kfree(b->private);
	b->private = NULL;
}

u32 *vgic_bytemap_get_reg(struct vgic_bytemap *x, int cpuid, u32 offset)
{
	u32 *reg;

	if (offset < 32) {
		reg = x->private;
		offset += cpuid * VGIC_NR_PRIVATE_IRQS;
	} else {
		reg = x->shared;
		offset -= VGIC_NR_PRIVATE_IRQS;
	}

	return reg + (offset / sizeof(u32));
}

#define VGIC_CFG_LEVEL	0
#define VGIC_CFG_EDGE	1

static bool vgic_irq_is_edge(struct kvm_vcpu *vcpu, int irq)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	int irq_val;

	irq_val = vgic_bitmap_get_irq_val(&dist->irq_cfg, vcpu->vcpu_id, irq);
	return irq_val == VGIC_CFG_EDGE;
}

static int vgic_irq_is_enabled(struct kvm_vcpu *vcpu, int irq)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	return vgic_bitmap_get_irq_val(&dist->irq_enabled, vcpu->vcpu_id, irq);
}

static int vgic_irq_is_active(struct kvm_vcpu *vcpu, int irq)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	return vgic_bitmap_get_irq_val(&dist->irq_active, vcpu->vcpu_id, irq);
}

static void vgic_irq_set_active(struct kvm_vcpu *vcpu, int irq)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	vgic_bitmap_set_irq_val(&dist->irq_active, vcpu->vcpu_id, irq, 1);
}

static void vgic_irq_clear_active(struct kvm_vcpu *vcpu, int irq)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	vgic_bitmap_set_irq_val(&dist->irq_active, vcpu->vcpu_id, irq, 0);
}

static int vgic_dist_irq_is_pending(struct kvm_vcpu *vcpu, int irq)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	return vgic_bitmap_get_irq_val(&dist->irq_state, vcpu->vcpu_id, irq);
}

void vgic_dist_irq_set(struct kvm_vcpu *vcpu, int irq)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	vgic_bitmap_set_irq_val(&dist->irq_state, vcpu->vcpu_id, irq, 1);
}

void vgic_dist_irq_clear(struct kvm_vcpu *vcpu, int irq)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	vgic_bitmap_set_irq_val(&dist->irq_state, vcpu->vcpu_id, irq, 0);
}

static void vgic_cpu_irq_set(struct kvm_vcpu *vcpu, int irq)
{
	if (irq < VGIC_NR_PRIVATE_IRQS)
		set_bit(irq, vcpu->arch.vgic_cpu.pending_percpu);
	else
		set_bit(irq - VGIC_NR_PRIVATE_IRQS,
			vcpu->arch.vgic_cpu.pending_shared);
}

void vgic_cpu_irq_clear(struct kvm_vcpu *vcpu, int irq)
{
	if (irq < VGIC_NR_PRIVATE_IRQS)
		clear_bit(irq, vcpu->arch.vgic_cpu.pending_percpu);
	else
		clear_bit(irq - VGIC_NR_PRIVATE_IRQS,
			  vcpu->arch.vgic_cpu.pending_shared);
}

/**
 * vgic_reg_access - access vgic register
 * @mmio:   pointer to the data describing the mmio access
 * @reg:    pointer to the virtual backing of vgic distributor data
 * @offset: least significant 2 bits used for word offset
 * @mode:   ACCESS_ mode (see defines above)
 *
 * Helper to make vgic register access easier using one of the access
 * modes defined for vgic register access
 * (read,raz,write-ignored,setbit,clearbit,write)
 */
void vgic_reg_access(struct kvm_exit_mmio *mmio, u32 *reg,
			    phys_addr_t offset, int mode)
{
	int word_offset = (offset & 3) * 8;
	u32 mask = (1UL << (mmio->len * 8)) - 1;
	u32 regval;

	/*
	 * Any alignment fault should have been delivered to the guest
	 * directly (ARM ARM B3.12.7 "Prioritization of aborts").
	 */

	if (reg) {
		regval = *reg;
	} else {
		BUG_ON(mode != (ACCESS_READ_RAZ | ACCESS_WRITE_IGNORED));
		regval = 0;
	}

	if (mmio->is_write) {
		u32 data = mmio_data_read(mmio, mask) << word_offset;
		switch (ACCESS_WRITE_MASK(mode)) {
		case ACCESS_WRITE_IGNORED:
			return;

		case ACCESS_WRITE_SETBIT:
			regval |= data;
			break;

		case ACCESS_WRITE_CLEARBIT:
			regval &= ~data;
			break;

		case ACCESS_WRITE_VALUE:
			regval = (regval & ~(mask << word_offset)) | data;
			break;
		}
		*reg = regval;
	} else {
		switch (ACCESS_READ_MASK(mode)) {
		case ACCESS_READ_RAZ:
			regval = 0;
			/* fall through */

		case ACCESS_READ_VALUE:
			mmio_data_write(mmio, mask, regval >> word_offset);
		}
	}
}

bool handle_mmio_raz_wi(struct kvm_vcpu *vcpu,
			       struct kvm_exit_mmio *mmio, phys_addr_t offset,
			       void *private)
{
	vgic_reg_access(mmio, NULL, offset,
			ACCESS_READ_RAZ | ACCESS_WRITE_IGNORED);
	return false;
}

bool vgic_handle_enable_reg(struct kvm *kvm, struct kvm_exit_mmio *mmio,
			    phys_addr_t offset, int vcpu_id, int access)
{
	u32 *reg;
	int mode = ACCESS_READ_VALUE | access;
	struct kvm_vcpu *target_vcpu = kvm_get_vcpu(kvm, vcpu_id);

	reg = vgic_bitmap_get_reg(&kvm->arch.vgic.irq_enabled, vcpu_id, offset);
	vgic_reg_access(mmio, reg, offset, mode);
	if (mmio->is_write) {
		if (access & ACCESS_WRITE_CLEARBIT) {
			if (offset < 4) /* Force SGI enabled */
				*reg |= 0xffff;
			vgic_retire_disabled_irqs(target_vcpu);
		}
		vgic_update_state(kvm);
		return true;
	}

	return false;
}

bool vgic_handle_pending_reg(struct kvm *kvm, struct kvm_exit_mmio *mmio,
			     phys_addr_t offset, int vcpu_id, int access)
{
	u32 *reg;
	int mode = ACCESS_READ_VALUE | access;

	reg = vgic_bitmap_get_reg(&kvm->arch.vgic.irq_state, vcpu_id, offset);
	vgic_reg_access(mmio, reg, offset, mode);
	if (mmio->is_write) {
		vgic_update_state(kvm);
		return true;
	}

	return false;
}

static u32 vgic_cfg_expand(u16 val)
{
	u32 res = 0;
	int i;

	/*
	 * Turn a 16bit value like abcd...mnop into a 32bit word
	 * a0b0c0d0...m0n0o0p0, which is what the HW cfg register is.
	 */
	for (i = 0; i < 16; i++)
		res |= ((val >> i) & VGIC_CFG_EDGE) << (2 * i + 1);

	return res;
}

static u16 vgic_cfg_compress(u32 val)
{
	u16 res = 0;
	int i;

	/*
	 * Turn a 32bit word a0b0c0d0...m0n0o0p0 into 16bit value like
	 * abcd...mnop which is what we really care about.
	 */
	for (i = 0; i < 16; i++)
		res |= ((val >> (i * 2 + 1)) & VGIC_CFG_EDGE) << i;

	return res;
}

/*
 * The distributor uses 2 bits per IRQ for the CFG register, but the
 * LSB is always 0. As such, we only keep the upper bit, and use the
 * two above functions to compress/expand the bits
 */
bool vgic_handle_cfg_reg(u32 *reg, struct kvm_exit_mmio *mmio,
			 phys_addr_t offset)
{
	u32 val;

	if (offset & 4)
		val = *reg >> 16;
	else
		val = *reg & 0xffff;

	val = vgic_cfg_expand(val);
	vgic_reg_access(mmio, &val, offset,
			ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
	if (mmio->is_write) {
		if (offset < 8) {
			*reg = ~0U; /* Force PPIs/SGIs to 1 */
			return false;
		}

		val = vgic_cfg_compress(val);
		if (offset & 4) {
			*reg &= 0xffff;
			*reg |= val << 16;
		} else {
			*reg &= 0xffff << 16;
			*reg |= val;
		}
	}

	return false;
}

/**
 * vgic_unqueue_irqs - move pending IRQs from LRs to the distributor
 * @vgic_cpu: Pointer to the vgic_cpu struct holding the LRs
 *
 * Move any pending IRQs that have already been assigned to LRs back to the
 * emulated distributor state so that the complete emulated state can be read
 * from the main emulation structures without investigating the LRs.
 *
 * Note that IRQs in the active state in the LRs get their pending state moved
 * to the distributor but the active state stays in the LRs, because we don't
 * track the active state on the distributor side.
 */
void vgic_unqueue_irqs(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	int i;

	for_each_set_bit(i, vgic_cpu->lr_used, vgic_cpu->nr_lr) {
		struct vgic_lr lr = vgic_get_lr(vcpu, i);

		/*
		 * There are three options for the state bits:
		 *
		 * 01: pending
		 * 10: active
		 * 11: pending and active
		 *
		 * If the LR holds only an active interrupt (not pending) then
		 * just leave it alone.
		 */
		if ((lr.state & LR_STATE_MASK) == LR_STATE_ACTIVE)
			continue;

		/*
		 * Reestablish the pending state on the distributor and the
		 * CPU interface.  It may have already been pending, but that
		 * is fine, then we are only setting a few bits that were
		 * already set.
		 */
		vgic_dist_irq_set(vcpu, lr.irq);
		if (lr.irq < VGIC_NR_SGIS)
			vgic_vm_op(vcpu->kvm, unqueue_sgi)(vcpu, lr.irq,
							   lr.source);
		lr.state &= ~LR_STATE_PENDING;
		vgic_set_lr(vcpu, i, lr);

		/*
		 * If there's no state left on the LR (it could still be
		 * active), then the LR does not hold any useful info and can
		 * be marked as free for other use.
		 */
		if (!(lr.state & LR_STATE_MASK))
			vgic_retire_lr(i, lr.irq, vcpu);

		/* Finally update the VGIC state. */
		vgic_update_state(vcpu->kvm);
	}
}

const
struct mmio_range *vgic_find_matching_range(const struct mmio_range *ranges,
					    struct kvm_exit_mmio *mmio,
					    phys_addr_t offset)
{
	const struct mmio_range *r = ranges;
	while (r->len) {
		if (offset >= r->base &&
		    (offset + mmio->len) <= (r->base + r->len))
			return r;
		r++;
	}
	return NULL;
}

static bool vgic_validate_access(const struct vgic_dist *dist,
				 const struct mmio_range *range,
				 unsigned long offset)
{
	int irq;

	if (!range->bits_per_irq)
		return true;	/* Not an irq-based access */

	irq = offset * 8 / range->bits_per_irq;
	if (irq >= dist->nr_irqs)
		return false;

	return true;
}

/*
 * Call the respective handler function for the given range.
 * We split up any 64 bit accesses into two consecutive 32 bit
 * handler calls and merge the result afterwards.
 */
static bool call_range_handler(struct kvm_vcpu *vcpu,
			       struct kvm_exit_mmio *mmio,
			       unsigned long offset, void *private,
			       const struct mmio_range *range)
{
	u32 *data32 = (void *)mmio->data;
	struct kvm_exit_mmio mmio32;
	bool ret;

	if (likely(mmio->len <= 4))
		return range->handle_mmio(vcpu, mmio, offset, private);

	/*
	 * We assume that any access greater than 4 bytes is actually
	 * 8 bytes long, caused by a 64-bit access
	 */

	mmio32.len = 4;
	mmio32.is_write = mmio->is_write;

	mmio32.phys_addr = mmio->phys_addr + 4;
	if (mmio->is_write)
		*(u32 *)mmio32.data = data32[1];
	ret = range->handle_mmio(vcpu, &mmio32, offset + 4, private);
	if (!mmio->is_write)
		data32[1] = *(u32 *)mmio32.data;

	mmio32.phys_addr = mmio->phys_addr;
	if (mmio->is_write)
		*(u32 *)mmio32.data = data32[0];
	ret |= range->handle_mmio(vcpu, &mmio32, offset, private);
	if (!mmio->is_write)
		data32[0] = *(u32 *)mmio32.data;

	return ret;
}

/*
 * vgic_handle_mmio_range - handle an in-kernel MMIO access
 * @vcpu:	pointer to the vcpu performing the access
 * @run:	pointer to the kvm_run structure
 * @mmio:	pointer to the data describing the access
 * @ranges:	pointer to the register defining structure
 * @mmio_base:	base address for this mapping
 *
 * returns true if the MMIO access could be performed
 */
bool vgic_handle_mmio_range(struct kvm_vcpu *vcpu, struct kvm_run *run,
			    struct kvm_exit_mmio *mmio,
			    const struct mmio_range *ranges,
			    unsigned long mmio_base, void *private)
{
	const struct mmio_range *range;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	bool updated_state;
	unsigned long offset;

	offset = mmio->phys_addr - mmio_base;
	range = vgic_find_matching_range(ranges, mmio, offset);
	if (unlikely(!range || !range->handle_mmio)) {
		pr_warn("Unhandled access %d %08llx %d\n",
			mmio->is_write, mmio->phys_addr, mmio->len);
		return false;
	}

	spin_lock(&vcpu->kvm->arch.vgic.lock);
	offset -= range->base;
	if (vgic_validate_access(dist, range, offset)) {
		updated_state = call_range_handler(vcpu, mmio, offset, private,
						   range);
	} else {
		if (!mmio->is_write)
			memset(mmio->data, 0, mmio->len);
		updated_state = false;
	}
	spin_unlock(&vcpu->kvm->arch.vgic.lock);
	kvm_prepare_mmio(run, mmio);
	kvm_handle_mmio_return(vcpu, run);

	if (updated_state)
		vgic_kick_vcpus(vcpu->kvm);

	return true;
}

/**
 * vgic_handle_mmio - handle an in-kernel MMIO access for the GIC emulation
 * @vcpu:      pointer to the vcpu performing the access
 * @run:       pointer to the kvm_run structure
 * @mmio:      pointer to the data describing the access
 *
 * returns true if the MMIO access has been performed in kernel space,
 * and false if it needs to be emulated in user space.
 */
bool vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run,
		      struct kvm_exit_mmio *mmio)
{
	if (!irqchip_in_kernel(vcpu->kvm))
		return false;

	return vgic_vm_op(vcpu->kvm, handle_mmio)(vcpu, run, mmio);
}

static int vgic_nr_shared_irqs(struct vgic_dist *dist)
{
	return dist->nr_irqs - VGIC_NR_PRIVATE_IRQS;
}

static int compute_pending_for_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	unsigned long *pending, *enabled, *pend_percpu, *pend_shared;
	unsigned long pending_private, pending_shared;
	int shared = vgic_nr_shared_irqs(dist);
	int vcpu_id;

	vcpu_id = vcpu->vcpu_id;
	pend_percpu = vcpu->arch.vgic_cpu.pending_percpu;
	pend_shared = vcpu->arch.vgic_cpu.pending_shared;

	pending = vgic_bitmap_get_cpu_map(&dist->irq_state, vcpu_id);
	enabled = vgic_bitmap_get_cpu_map(&dist->irq_enabled, vcpu_id);
	bitmap_and(pend_percpu, pending, enabled, VGIC_NR_PRIVATE_IRQS);

	pending = vgic_bitmap_get_shared_map(&dist->irq_state);
	enabled = vgic_bitmap_get_shared_map(&dist->irq_enabled);
	bitmap_and(pend_shared, pending, enabled, shared);
	bitmap_and(pend_shared, pend_shared,
		   vgic_bitmap_get_shared_map(&dist->irq_spi_target[vcpu_id]),
		   shared);

	pending_private = find_first_bit(pend_percpu, VGIC_NR_PRIVATE_IRQS);
	pending_shared = find_first_bit(pend_shared, shared);
	return (pending_private < VGIC_NR_PRIVATE_IRQS ||
		pending_shared < vgic_nr_shared_irqs(dist));
}

/*
 * Update the interrupt state and determine which CPUs have pending
 * interrupts. Must be called with distributor lock held.
 */
void vgic_update_state(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct kvm_vcpu *vcpu;
	int c;

	if (!dist->enabled) {
		set_bit(0, &dist->irq_pending_on_cpu);
		return;
	}

	kvm_for_each_vcpu(c, vcpu, kvm) {
		if (compute_pending_for_cpu(vcpu)) {
			pr_debug("CPU%d has pending interrupts\n", c);
			set_bit(c, &dist->irq_pending_on_cpu);
		}
	}
}

static struct vgic_lr vgic_get_lr(const struct kvm_vcpu *vcpu, int lr)
{
	return vgic_vm_op(vcpu->kvm, get_lr)(vcpu, lr);
}

static void vgic_set_lr(struct kvm_vcpu *vcpu, int lr,
			       struct vgic_lr vlr)
{
	return vgic_vm_op(vcpu->kvm, set_lr)(vcpu, lr, vlr);
}

static void vgic_sync_lr_elrsr(struct kvm_vcpu *vcpu, int lr,
			       struct vgic_lr vlr)
{
	vgic_ops->sync_lr_elrsr(vcpu, lr, vlr);
}

static inline u64 vgic_get_elrsr(struct kvm_vcpu *vcpu)
{
	return vgic_ops->get_elrsr(vcpu);
}

static inline u64 vgic_get_eisr(struct kvm_vcpu *vcpu)
{
	return vgic_ops->get_eisr(vcpu);
}

static inline u32 vgic_get_interrupt_status(struct kvm_vcpu *vcpu)
{
	return vgic_ops->get_interrupt_status(vcpu);
}

static inline void vgic_enable_underflow(struct kvm_vcpu *vcpu)
{
	vgic_ops->enable_underflow(vcpu);
}

static inline void vgic_disable_underflow(struct kvm_vcpu *vcpu)
{
	vgic_ops->disable_underflow(vcpu);
}

void vgic_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr)
{
	vgic_ops->get_vmcr(vcpu, vmcr);
}

void vgic_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr)
{
	vgic_ops->set_vmcr(vcpu, vmcr);
}

static inline void vgic_enable(struct kvm_vcpu *vcpu)
{
	vgic_ops->enable(vcpu);
}

static void vgic_retire_lr(int lr_nr, int irq, struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_lr vlr = vgic_get_lr(vcpu, lr_nr);

	vlr.state = 0;
	vgic_set_lr(vcpu, lr_nr, vlr);
	clear_bit(lr_nr, vgic_cpu->lr_used);
	vgic_cpu->vgic_irq_lr_map[irq] = LR_EMPTY;
}

/*
 * An interrupt may have been disabled after being made pending on the
 * CPU interface (the classic case is a timer running while we're
 * rebooting the guest - the interrupt would kick as soon as the CPU
 * interface gets enabled, with deadly consequences).
 *
 * The solution is to examine already active LRs, and check the
 * interrupt is still enabled. If not, just retire it.
 */
static void vgic_retire_disabled_irqs(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	int lr;

	for_each_set_bit(lr, vgic_cpu->lr_used, vgic->nr_lr) {
		struct vgic_lr vlr = vgic_get_lr(vcpu, lr);

		if (!vgic_irq_is_enabled(vcpu, vlr.irq)) {
			vgic_retire_lr(lr, vlr.irq, vcpu);
			if (vgic_irq_is_active(vcpu, vlr.irq))
				vgic_irq_clear_active(vcpu, vlr.irq);
		}
	}
}

/*
 * Queue an interrupt to a CPU virtual interface. Return true on success,
 * or false if it wasn't possible to queue it.
 * sgi_source must be zero for any non-SGI interrupts.
 */
bool vgic_queue_irq(struct kvm_vcpu *vcpu, u8 sgi_source_id, int irq)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	struct vgic_lr vlr;
	int lr;

	/* Sanitize the input... */
	BUG_ON(sgi_source_id & ~7);
	BUG_ON(sgi_source_id && irq >= VGIC_NR_SGIS);
	BUG_ON(irq >= dist->nr_irqs);

	kvm_debug("Queue IRQ%d\n", irq);

	lr = vgic_cpu->vgic_irq_lr_map[irq];

	/* Do we have an active interrupt for the same CPUID? */
	if (lr != LR_EMPTY) {
		vlr = vgic_get_lr(vcpu, lr);
		if (vlr.source == sgi_source_id) {
			kvm_debug("LR%d piggyback for IRQ%d\n", lr, vlr.irq);
			BUG_ON(!test_bit(lr, vgic_cpu->lr_used));
			vlr.state |= LR_STATE_PENDING;
			vgic_set_lr(vcpu, lr, vlr);
			return true;
		}
	}

	/* Try to use another LR for this interrupt */
	lr = find_first_zero_bit((unsigned long *)vgic_cpu->lr_used,
			       vgic->nr_lr);
	if (lr >= vgic->nr_lr)
		return false;

	kvm_debug("LR%d allocated for IRQ%d %x\n", lr, irq, sgi_source_id);
	vgic_cpu->vgic_irq_lr_map[irq] = lr;
	set_bit(lr, vgic_cpu->lr_used);

	vlr.irq = irq;
	vlr.source = sgi_source_id;
	vlr.state = LR_STATE_PENDING;
	if (!vgic_irq_is_edge(vcpu, irq))
		vlr.state |= LR_EOI_INT;

	vgic_set_lr(vcpu, lr, vlr);

	return true;
}

static bool vgic_queue_hwirq(struct kvm_vcpu *vcpu, int irq)
{
	if (vgic_irq_is_active(vcpu, irq))
		return true; /* level interrupt, already queued */

	if (vgic_queue_irq(vcpu, 0, irq)) {
		if (vgic_irq_is_edge(vcpu, irq)) {
			vgic_dist_irq_clear(vcpu, irq);
			vgic_cpu_irq_clear(vcpu, irq);
		} else {
			vgic_irq_set_active(vcpu, irq);
		}

		return true;
	}

	return false;
}

/*
 * Fill the list registers with pending interrupts before running the
 * guest.
 */
static void __kvm_vgic_flush_hwstate(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	int i, vcpu_id;
	int overflow = 0;

	vcpu_id = vcpu->vcpu_id;

	/*
	 * We may not have any pending interrupt, or the interrupts
	 * may have been serviced from another vcpu. In all cases,
	 * move along.
	 */
	if (!kvm_vgic_vcpu_pending_irq(vcpu)) {
		pr_debug("CPU%d has no pending interrupt\n", vcpu_id);
		goto epilog;
	}

	/* SGIs */
	for_each_set_bit(i, vgic_cpu->pending_percpu, VGIC_NR_SGIS) {
		if (!vgic_vm_op(vcpu->kvm, queue_sgi)(vcpu, i))
			overflow = 1;
	}

	/* PPIs */
	for_each_set_bit_from(i, vgic_cpu->pending_percpu, VGIC_NR_PRIVATE_IRQS) {
		if (!vgic_queue_hwirq(vcpu, i))
			overflow = 1;
	}

	/* SPIs */
	for_each_set_bit(i, vgic_cpu->pending_shared, vgic_nr_shared_irqs(dist)) {
		if (!vgic_queue_hwirq(vcpu, i + VGIC_NR_PRIVATE_IRQS))
			overflow = 1;
	}

epilog:
	if (overflow) {
		vgic_enable_underflow(vcpu);
	} else {
		vgic_disable_underflow(vcpu);
		/*
		 * We're about to run this VCPU, and we've consumed
		 * everything the distributor had in store for
		 * us. Claim we don't have anything pending. We'll
		 * adjust that if needed while exiting.
		 */
		clear_bit(vcpu_id, &dist->irq_pending_on_cpu);
	}
}

static bool vgic_process_maintenance(struct kvm_vcpu *vcpu)
{
	u32 status = vgic_get_interrupt_status(vcpu);
	bool level_pending = false;

	kvm_debug("STATUS = %08x\n", status);

	if (status & INT_STATUS_EOI) {
		/*
		 * Some level interrupts have been EOIed. Clear their
		 * active bit.
		 */
		u64 eisr = vgic_get_eisr(vcpu);
		unsigned long *eisr_ptr = (unsigned long *)&eisr;
		int lr;

		for_each_set_bit(lr, eisr_ptr, vgic->nr_lr) {
			struct vgic_lr vlr = vgic_get_lr(vcpu, lr);

			vgic_irq_clear_active(vcpu, vlr.irq);
			WARN_ON(vlr.state & LR_STATE_MASK);
			vlr.state = 0;
			vgic_set_lr(vcpu, lr, vlr);

			/* Any additional pending interrupt? */
			if (vgic_dist_irq_is_pending(vcpu, vlr.irq)) {
				vgic_cpu_irq_set(vcpu, vlr.irq);
				level_pending = true;
			} else {
				vgic_cpu_irq_clear(vcpu, vlr.irq);
			}

			/*
			 * Despite being EOIed, the LR may not have
			 * been marked as empty.
			 */
			vgic_sync_lr_elrsr(vcpu, lr, vlr);
		}
	}

	if (status & INT_STATUS_UNDERFLOW)
		vgic_disable_underflow(vcpu);

	return level_pending;
}

/*
 * Sync back the VGIC state after a guest run. The distributor lock is
 * needed so we don't get preempted in the middle of the state processing.
 */
static void __kvm_vgic_sync_hwstate(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	u64 elrsr;
	unsigned long *elrsr_ptr;
	int lr, pending;
	bool level_pending;

	level_pending = vgic_process_maintenance(vcpu);
	elrsr = vgic_get_elrsr(vcpu);
	elrsr_ptr = (unsigned long *)&elrsr;

	/* Clear mappings for empty LRs */
	for_each_set_bit(lr, elrsr_ptr, vgic->nr_lr) {
		struct vgic_lr vlr;

		if (!test_and_clear_bit(lr, vgic_cpu->lr_used))
			continue;

		vlr = vgic_get_lr(vcpu, lr);

		BUG_ON(vlr.irq >= dist->nr_irqs);
		vgic_cpu->vgic_irq_lr_map[vlr.irq] = LR_EMPTY;
	}

	/* Check if we still have something up our sleeve... */
	pending = find_first_zero_bit(elrsr_ptr, vgic->nr_lr);
	if (level_pending || pending < vgic->nr_lr)
		set_bit(vcpu->vcpu_id, &dist->irq_pending_on_cpu);
}

void kvm_vgic_flush_hwstate(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	spin_lock(&dist->lock);
	__kvm_vgic_flush_hwstate(vcpu);
	spin_unlock(&dist->lock);
}

void kvm_vgic_sync_hwstate(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	spin_lock(&dist->lock);
	__kvm_vgic_sync_hwstate(vcpu);
	spin_unlock(&dist->lock);
}

int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	if (!irqchip_in_kernel(vcpu->kvm))
		return 0;

	return test_bit(vcpu->vcpu_id, &dist->irq_pending_on_cpu);
}

void vgic_kick_vcpus(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int c;

	/*
	 * We've injected an interrupt, time to find out who deserves
	 * a good kick...
	 */
	kvm_for_each_vcpu(c, vcpu, kvm) {
		if (kvm_vgic_vcpu_pending_irq(vcpu))
			kvm_vcpu_kick(vcpu);
	}
}

static int vgic_validate_injection(struct kvm_vcpu *vcpu, int irq, int level)
{
	int is_edge = vgic_irq_is_edge(vcpu, irq);
	int state = vgic_dist_irq_is_pending(vcpu, irq);

	/*
	 * Only inject an interrupt if:
	 * - edge triggered and we have a rising edge
	 * - level triggered and we change level
	 */
	if (is_edge)
		return level > state;
	else
		return level != state;
}

static bool vgic_update_irq_state(struct kvm *kvm, int cpuid,
				  unsigned int irq_num, bool level)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct kvm_vcpu *vcpu;
	int is_edge, is_level;
	int enabled;
	bool ret = true, can_inject = true;

	spin_lock(&dist->lock);

	vcpu = kvm_get_vcpu(kvm, cpuid);
	is_edge = vgic_irq_is_edge(vcpu, irq_num);
	is_level = !is_edge;

	if (!vgic_validate_injection(vcpu, irq_num, level)) {
		ret = false;
		goto out;
	}

	if (irq_num >= VGIC_NR_PRIVATE_IRQS) {
		cpuid = dist->irq_spi_cpu[irq_num - VGIC_NR_PRIVATE_IRQS];
		if (cpuid == VCPU_NOT_ALLOCATED) {
			/* Pretend we use CPU0, and prevent injection */
			cpuid = 0;
			can_inject = false;
		}
		vcpu = kvm_get_vcpu(kvm, cpuid);
	}

	kvm_debug("Inject IRQ%d level %d CPU%d\n", irq_num, level, cpuid);

	if (level)
		vgic_dist_irq_set(vcpu, irq_num);
	else
		vgic_dist_irq_clear(vcpu, irq_num);

	enabled = vgic_irq_is_enabled(vcpu, irq_num);

	if (!enabled || !can_inject) {
		ret = false;
		goto out;
	}

	if (is_level && vgic_irq_is_active(vcpu, irq_num)) {
		/*
		 * Level interrupt in progress, will be picked up
		 * when EOId.
		 */
		ret = false;
		goto out;
	}

	if (level) {
		vgic_cpu_irq_set(vcpu, irq_num);
		set_bit(cpuid, &dist->irq_pending_on_cpu);
	}

out:
	spin_unlock(&dist->lock);

	return ret;
}

/**
 * kvm_vgic_inject_irq - Inject an IRQ from a device to the vgic
 * @kvm:     The VM structure pointer
 * @cpuid:   The CPU for PPIs
 * @irq_num: The IRQ number that is assigned to the device
 * @level:   Edge-triggered:  true:  to trigger the interrupt
 *			      false: to ignore the call
 *	     Level-sensitive  true:  activates an interrupt
 *			      false: deactivates an interrupt
 *
 * The GIC is not concerned with devices being active-LOW or active-HIGH for
 * level-sensitive interrupts.  You can think of the level parameter as 1
 * being HIGH and 0 being LOW and all devices being active-HIGH.
 */
int kvm_vgic_inject_irq(struct kvm *kvm, int cpuid, unsigned int irq_num,
			bool level)
{
	if (likely(vgic_initialized(kvm)) &&
	    vgic_update_irq_state(kvm, cpuid, irq_num, level))
		vgic_kick_vcpus(kvm);

	return 0;
}

static irqreturn_t vgic_maintenance_handler(int irq, void *data)
{
	/*
	 * We cannot rely on the vgic maintenance interrupt to be
	 * delivered synchronously. This means we can only use it to
	 * exit the VM, and we perform the handling of EOIed
	 * interrupts on the exit path (see vgic_process_maintenance).
	 */
	return IRQ_HANDLED;
}

void kvm_vgic_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	kfree(vgic_cpu->pending_shared);
	kfree(vgic_cpu->vgic_irq_lr_map);
	vgic_cpu->pending_shared = NULL;
	vgic_cpu->vgic_irq_lr_map = NULL;
}

static int vgic_vcpu_init_maps(struct kvm_vcpu *vcpu, int nr_irqs)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	int sz = (nr_irqs - VGIC_NR_PRIVATE_IRQS) / 8;
	vgic_cpu->pending_shared = kzalloc(sz, GFP_KERNEL);
	vgic_cpu->vgic_irq_lr_map = kzalloc(nr_irqs, GFP_KERNEL);

	if (!vgic_cpu->pending_shared || !vgic_cpu->vgic_irq_lr_map) {
		kvm_vgic_vcpu_destroy(vcpu);
		return -ENOMEM;
	}

	return 0;
}

/**
 * kvm_vgic_vcpu_init - Initialize per-vcpu VGIC state
 * @vcpu: pointer to the vcpu struct
 *
 * Initialize the vgic_cpu struct and vgic_dist struct fields pertaining to
 * this vcpu and enable the VGIC for this VCPU
 */
static void kvm_vgic_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	int i;

	for (i = 0; i < dist->nr_irqs; i++) {
		if (i < VGIC_NR_PPIS)
			vgic_bitmap_set_irq_val(&dist->irq_enabled,
						vcpu->vcpu_id, i, 1);
		if (i < VGIC_NR_PRIVATE_IRQS)
			vgic_bitmap_set_irq_val(&dist->irq_cfg,
						vcpu->vcpu_id, i, VGIC_CFG_EDGE);

		vgic_cpu->vgic_irq_lr_map[i] = LR_EMPTY;
	}

	/*
	 * Store the number of LRs per vcpu, so we don't have to go
	 * all the way to the distributor structure to find out. Only
	 * assembly code should use this one.
	 */
	vgic_cpu->nr_lr = vgic->nr_lr;

	vgic_enable(vcpu);
}

static void vgic_init_maintenance_interrupt(void *info)
{
	enable_percpu_irq(vgic->maint_irq, 0);
}

static int vgic_cpu_notify(struct notifier_block *self,
			   unsigned long action, void *cpu)
{
	switch (action) {
	case CPU_STARTING:
	case CPU_STARTING_FROZEN:
		vgic_init_maintenance_interrupt(NULL);
		break;
	case CPU_DYING:
	case CPU_DYING_FROZEN:
		disable_percpu_irq(vgic->maint_irq);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block vgic_cpu_nb = {
	.notifier_call = vgic_cpu_notify,
};

static const struct of_device_id vgic_ids[] = {
	{ .compatible = "arm,cortex-a15-gic", .data = vgic_v2_probe, },
	{ .compatible = "arm,gic-v3", .data = vgic_v3_probe, },
	{},
};

int kvm_vgic_hyp_init(void)
{
	const struct of_device_id *matched_id;
	int (*vgic_probe)(struct device_node *,const struct vgic_ops **,
			  const struct vgic_params **);
	struct device_node *vgic_node;
	int ret;

	vgic_node = of_find_matching_node_and_match(NULL,
						    vgic_ids, &matched_id);
	if (!vgic_node) {
		kvm_err("error: no compatible GIC node found\n");
		return -ENODEV;
	}

	vgic_probe = matched_id->data;
	ret = vgic_probe(vgic_node, &vgic_ops, &vgic);
	if (ret)
		return ret;

	ret = request_percpu_irq(vgic->maint_irq, vgic_maintenance_handler,
				 "vgic", kvm_get_running_vcpus());
	if (ret) {
		kvm_err("Cannot register interrupt %d\n", vgic->maint_irq);
		return ret;
	}

	ret = __register_cpu_notifier(&vgic_cpu_nb);
	if (ret) {
		kvm_err("Cannot register vgic CPU notifier\n");
		goto out_free_irq;
	}

	on_each_cpu(vgic_init_maintenance_interrupt, NULL, 1);

	/* Callback into for arch code for setup */
	vgic_arch_setup(vgic);

	return 0;

out_free_irq:
	free_percpu_irq(vgic->maint_irq, kvm_get_running_vcpus());
	return ret;
}

void kvm_vgic_destroy(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct kvm_vcpu *vcpu;
	int i;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvm_vgic_vcpu_destroy(vcpu);

	vgic_free_bitmap(&dist->irq_enabled);
	vgic_free_bitmap(&dist->irq_state);
	vgic_free_bitmap(&dist->irq_active);
	vgic_free_bitmap(&dist->irq_cfg);
	vgic_free_bytemap(&dist->irq_priority);
	if (dist->irq_spi_target)
		for (i = 0; i < dist->nr_cpus; i++)
			vgic_free_bitmap(&dist->irq_spi_target[i]);
	kfree(dist->irq_sgi_sources);
	kfree(dist->irq_spi_cpu);
	kfree(dist->irq_spi_mpidr);
	kfree(dist->irq_spi_target);
	dist->irq_sgi_sources = NULL;
	dist->irq_spi_cpu = NULL;
	dist->irq_spi_target = NULL;
}

/*
 * Allocate and initialize the various data structures. Must be called
 * with kvm->lock held!
 */
int vgic_init_maps(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct kvm_vcpu *vcpu;
	int nr_cpus, nr_irqs;
	int ret, i;

	if (dist->nr_cpus)	/* Already allocated */
		return 0;

	nr_cpus = dist->nr_cpus = atomic_read(&kvm->online_vcpus);
	if (!nr_cpus)		/* No vcpus? Can't be good... */
		return -EINVAL;

	/*
	 * If nobody configured the number of interrupts, use the
	 * legacy one.
	 */
	if (!dist->nr_irqs)
		dist->nr_irqs = VGIC_NR_IRQS_LEGACY;

	nr_irqs = dist->nr_irqs;

	ret  = vgic_init_bitmap(&dist->irq_enabled, nr_cpus, nr_irqs);
	ret |= vgic_init_bitmap(&dist->irq_state, nr_cpus, nr_irqs);
	ret |= vgic_init_bitmap(&dist->irq_active, nr_cpus, nr_irqs);
	ret |= vgic_init_bitmap(&dist->irq_cfg, nr_cpus, nr_irqs);
	ret |= vgic_init_bytemap(&dist->irq_priority, nr_cpus, nr_irqs);

	if (ret)
		goto out;

	dist->irq_sgi_sources = kzalloc(nr_cpus * VGIC_NR_SGIS,	GFP_KERNEL);
	dist->irq_spi_cpu = kzalloc(nr_irqs - VGIC_NR_PRIVATE_IRQS, GFP_KERNEL);
	dist->irq_spi_target = kcalloc(nr_cpus, sizeof(*dist->irq_spi_target),
				       GFP_KERNEL);
	if (!dist->irq_sgi_sources ||
	    !dist->irq_spi_cpu ||
	    !dist->irq_spi_target) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < nr_cpus; i++)
		ret |= vgic_init_bitmap(&dist->irq_spi_target[i],
					nr_cpus, nr_irqs);

	if (ret)
		goto out;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = vgic_vcpu_init_maps(vcpu, nr_irqs);
		if (ret) {
			kvm_err("Failed to allocate vcpu memory\n");
			break;
		}
	}

out:
	if (ret)
		kvm_vgic_destroy(kvm);

	return ret;
}

/**
 * kvm_vgic_init - Initialize global VGIC state before running any VCPUs
 * @kvm: pointer to the kvm struct
 *
 * Map the virtual CPU interface into the VM before running any VCPUs.  We
 * can't do this at creation time, because user space must first set the
 * virtual CPU interface address in the guest physical address space.  Also
 * initialize the ITARGETSRn regs to 0 on the emulated distributor.
 */
int kvm_vgic_init(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int ret = 0, i;

	if (!irqchip_in_kernel(kvm))
		return 0;

	mutex_lock(&kvm->lock);

	if (vgic_initialized(kvm))
		goto out;

	ret = vgic_init_maps(kvm);
	if (ret) {
		kvm_err("Unable to allocate maps\n");
		goto out;
	}

	ret = vgic_vm_op(kvm, vgic_init)(kvm, vgic);
	if (ret)
		goto out;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvm_vgic_vcpu_init(vcpu);

	kvm->arch.vgic.ready = true;
out:
	if (ret)
		kvm_vgic_destroy(kvm);
	mutex_unlock(&kvm->lock);
	return ret;
}

static bool init_emulation_ops(struct kvm *kvm, int type)
{
	switch (type) {
	case KVM_DEV_TYPE_ARM_VGIC_V2:
		return vgic_v2_init_emulation_ops(kvm, type);
	}
	return false;
}

int kvm_vgic_create(struct kvm *kvm, u32 type)
{
	int i, vcpu_lock_idx = -1, ret = 0;
	struct kvm_vcpu *vcpu;

	mutex_lock(&kvm->lock);

	if (kvm->arch.vgic.in_kernel) {
		ret = -EEXIST;
		goto out;
	}

	/*
	 * Any time a vcpu is run, vcpu_load is called which tries to grab the
	 * vcpu->mutex.  By grabbing the vcpu->mutex of all VCPUs we ensure
	 * that no other VCPUs are run while we create the vgic.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!mutex_trylock(&vcpu->mutex))
			goto out_unlock;
		vcpu_lock_idx = i;
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->arch.has_run_once) {
			ret = -EBUSY;
			goto out_unlock;
		}
	}

	if (!vgic->init_emul(kvm, type)) {
		ret = -ENODEV;
		goto out;
	}

	spin_lock_init(&kvm->arch.vgic.lock);
	kvm->arch.vgic.in_kernel = true;
	kvm->arch.vgic.vgic_model = type;
	kvm->arch.vgic.vctrl_base = vgic->vctrl_base;
	kvm->arch.vgic.vgic_dist_base = VGIC_ADDR_UNDEF;
	kvm->arch.vgic.vgic_cpu_base = VGIC_ADDR_UNDEF;
	kvm->arch.vgic.vgic_redist_base = VGIC_ADDR_UNDEF;

	init_emulation_ops(kvm, type);

out_unlock:
	for (; vcpu_lock_idx >= 0; vcpu_lock_idx--) {
		vcpu = kvm_get_vcpu(kvm, vcpu_lock_idx);
		mutex_unlock(&vcpu->mutex);
	}

out:
	mutex_unlock(&kvm->lock);
	return ret;
}

static bool vgic_ioaddr_overlap(struct kvm *kvm)
{
	phys_addr_t dist = kvm->arch.vgic.vgic_dist_base;
	phys_addr_t cpu = kvm->arch.vgic.vgic_cpu_base;

	if (IS_VGIC_ADDR_UNDEF(dist) || IS_VGIC_ADDR_UNDEF(cpu))
		return 0;
	if ((dist <= cpu && dist + KVM_VGIC_V2_DIST_SIZE > cpu) ||
	    (cpu <= dist && cpu + KVM_VGIC_V2_CPU_SIZE > dist))
		return -EBUSY;
	return 0;
}

static int vgic_ioaddr_assign(struct kvm *kvm, phys_addr_t *ioaddr,
			      phys_addr_t addr, phys_addr_t size)
{
	int ret;

	if (addr & ~KVM_PHYS_MASK)
		return -E2BIG;

	if (addr & (SZ_4K - 1))
		return -EINVAL;

	if (!IS_VGIC_ADDR_UNDEF(*ioaddr))
		return -EEXIST;
	if (addr + size < addr)
		return -EINVAL;

	*ioaddr = addr;
	ret = vgic_ioaddr_overlap(kvm);
	if (ret)
		*ioaddr = VGIC_ADDR_UNDEF;

	return ret;
}

/**
 * kvm_vgic_addr - set or get vgic VM base addresses
 * @kvm:   pointer to the vm struct
 * @type:  the VGIC addr type, one of KVM_VGIC_V2_ADDR_TYPE_XXX
 * @addr:  pointer to address value
 * @write: if true set the address in the VM address space, if false read the
 *          address
 *
 * Set or get the vgic base addresses for the distributor and the virtual CPU
 * interface in the VM physical address space.  These addresses are properties
 * of the emulated core/SoC and therefore user space initially knows this
 * information.
 */
int kvm_vgic_addr(struct kvm *kvm, unsigned long type, u64 *addr, bool write)
{
	int r = 0;
	struct vgic_dist *vgic = &kvm->arch.vgic;

	mutex_lock(&kvm->lock);
	switch (type) {
	case KVM_VGIC_V2_ADDR_TYPE_DIST:
		if (write) {
			r = vgic_ioaddr_assign(kvm, &vgic->vgic_dist_base,
					       *addr, KVM_VGIC_V2_DIST_SIZE);
		} else {
			*addr = vgic->vgic_dist_base;
		}
		break;
	case KVM_VGIC_V2_ADDR_TYPE_CPU:
		if (write) {
			r = vgic_ioaddr_assign(kvm, &vgic->vgic_cpu_base,
					       *addr, KVM_VGIC_V2_CPU_SIZE);
		} else {
			*addr = vgic->vgic_cpu_base;
		}
		break;
	default:
		r = -ENODEV;
	}

	mutex_unlock(&kvm->lock);
	return r;
}

int vgic_has_attr_regs(const struct mmio_range *ranges,
		       phys_addr_t offset)
{
	struct kvm_exit_mmio dev_attr_mmio;

	dev_attr_mmio.len = 4;
	if (vgic_find_matching_range(ranges, &dev_attr_mmio, offset))
		return 0;
	else
		return -ENXIO;
}

int vgic_set_common_attr(struct kvm_device *dev, struct kvm_device_attr *attr)
{
	int r;

	switch (attr->group) {
	case KVM_DEV_ARM_VGIC_GRP_ADDR: {
		u64 __user *uaddr = (u64 __user *)(long)attr->addr;
		u64 addr;
		unsigned long type = (unsigned long)attr->attr;

		if (copy_from_user(&addr, uaddr, sizeof(addr)))
			return -EFAULT;

		r = kvm_vgic_addr(dev->kvm, type, &addr, true);
		return (r == -ENODEV) ? -ENXIO : r;
	}

	case KVM_DEV_ARM_VGIC_GRP_NR_IRQS: {
		u32 __user *uaddr = (u32 __user *)(long)attr->addr;
		u32 val;
		int ret = 0;

		if (get_user(val, uaddr))
			return -EFAULT;

		if (val > 1024 || (val & 31))
			return -EINVAL;

		mutex_lock(&dev->kvm->lock);

		if (vgic_initialized(dev->kvm) || dev->kvm->arch.vgic.nr_irqs)
			ret = -EBUSY;
		else
			dev->kvm->arch.vgic.nr_irqs = val;

		mutex_unlock(&dev->kvm->lock);

		return ret;
	}

	}

	return -ENXIO;
}

int vgic_get_common_attr(struct kvm_device *dev, struct kvm_device_attr *attr)
{
	int r = -ENXIO;

	switch (attr->group) {
	case KVM_DEV_ARM_VGIC_GRP_ADDR: {
		u64 __user *uaddr = (u64 __user *)(long)attr->addr;
		u64 addr;
		unsigned long type = (unsigned long)attr->attr;

		r = kvm_vgic_addr(dev->kvm, type, &addr, false);
		if (r)
			return (r == -ENODEV) ? -ENXIO : r;

		if (copy_to_user(uaddr, &addr, sizeof(addr)))
			return -EFAULT;
		break;
	}
	case KVM_DEV_ARM_VGIC_GRP_NR_IRQS: {
		u32 __user *uaddr = (u32 __user *)(long)attr->addr;
		r = put_user(dev->kvm->arch.vgic.nr_irqs, uaddr);
		break;
	}
	case KVM_DEV_ARM_VGIC_GRP_ADDR_OFFSET: {
		u32 __user *uaddr = (u32 __user *)(long)attr->addr;
		u32 val = vgic->vcpu_base & ~PAGE_MASK;
		r = put_user(val, uaddr);
		break;
	}

	}

	return r;
}

void vgic_destroy(struct kvm_device *dev)
{
	kfree(dev);
}

int vgic_create(struct kvm_device *dev, u32 type)
{
	return kvm_vgic_create(dev->kvm, type);
}
