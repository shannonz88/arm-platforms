/*
 * Copyright (C) 2012-2014 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Derived from virt/kvm/arm/vgic.c
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

#define VGIC_ADDR_UNDEF		(-1)
#define IS_VGIC_ADDR_UNDEF(_x)  ((_x) == VGIC_ADDR_UNDEF)

#define PRODUCT_ID_KVM      0x4b    /* ASCII code K */
#define IMPLEMENTER_ARM     0x43b

#define ACCESS_READ_VALUE	(1 << 0)
#define ACCESS_READ_RAZ		(0 << 0)
#define ACCESS_READ_MASK(x)	((x) & (1 << 0))
#define ACCESS_WRITE_IGNORED	(0 << 1)
#define ACCESS_WRITE_SETBIT	(1 << 1)
#define ACCESS_WRITE_CLEARBIT	(2 << 1)
#define ACCESS_WRITE_VALUE	(3 << 1)
#define ACCESS_WRITE_MASK(x)	((x) & (3 << 1))

#define VCPU_NOT_ALLOCATED ((u8)-1)

unsigned long *vgic_bitmap_get_shared_map(struct vgic_bitmap *x);

void vgic_update_state(struct kvm *kvm);
int vgic_init_maps(struct kvm *kvm);

u32 *vgic_bitmap_get_reg(struct vgic_bitmap *x, int cpuid, u32 offset);
u32 *vgic_bytemap_get_reg(struct vgic_bytemap *x, int cpuid, u32 offset);

void vgic_dist_irq_set(struct kvm_vcpu *vcpu, int irq);
void vgic_dist_irq_clear(struct kvm_vcpu *vcpu, int irq);
void vgic_cpu_irq_clear(struct kvm_vcpu *vcpu, int irq);
void vgic_bitmap_set_irq_val(struct vgic_bitmap *x, int cpuid,
			     int irq, int val);

void vgic_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr);
void vgic_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr);

bool vgic_queue_irq(struct kvm_vcpu *vcpu, u8 sgi_source_id, int irq);
void vgic_unqueue_irqs(struct kvm_vcpu *vcpu);

void vgic_reg_access(struct kvm_exit_mmio *mmio, u32 *reg,
		     phys_addr_t offset, int mode);
bool handle_mmio_raz_wi(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			phys_addr_t offset, void *private);

static inline
u32 mmio_data_read(struct kvm_exit_mmio *mmio, u32 mask)
{
	return *((u32 *)mmio->data) & mask;
}

static inline
void mmio_data_write(struct kvm_exit_mmio *mmio, u32 mask, u32 value)
{
	*((u32 *)mmio->data) = value & mask;
}

struct mmio_range {
	phys_addr_t base;
	unsigned long len;
	int bits_per_irq;
	bool (*handle_mmio)(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			    phys_addr_t offset, void *private);
};

#define IS_IN_RANGE(addr, alen, base, len) \
	(((addr) >= (base)) && (((addr) + (alen)) < ((base) + (len))))

const
struct mmio_range *vgic_find_matching_range(const struct mmio_range *ranges,
					    struct kvm_exit_mmio *mmio,
					    phys_addr_t offset);

bool vgic_handle_mmio_range(struct kvm_vcpu *vcpu, struct kvm_run *run,
			    struct kvm_exit_mmio *mmio,
			    const struct mmio_range *ranges,
			    unsigned long mmio_base,
			    void *private);

bool vgic_handle_enable_reg(struct kvm *kvm, struct kvm_exit_mmio *mmio,
			    phys_addr_t offset, int vcpu_id, int access);

bool vgic_handle_pending_reg(struct kvm *kvm, struct kvm_exit_mmio *mmio,
			     phys_addr_t offset, int vcpu_id, int access);

bool vgic_handle_cfg_reg(u32 *reg, struct kvm_exit_mmio *mmio,
			 phys_addr_t offset);

void vgic_kick_vcpus(struct kvm *kvm);

int vgic_create(struct kvm_device *dev, u32 type);
void vgic_destroy(struct kvm_device *dev);

int vgic_has_attr_regs(const struct mmio_range *ranges, phys_addr_t offset);
int vgic_set_common_attr(struct kvm_device *dev, struct kvm_device_attr *attr);
int vgic_get_common_attr(struct kvm_device *dev, struct kvm_device_attr *attr);

bool vgic_v2_init_emulation_ops(struct kvm *kvm, int type);
