/*
 * Copyright (C) 2015, 2016 ARM Ltd.
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
#ifndef __KVM_ARM_VGIC_MMIO_H__
#define __KVM_ARM_VGIC_MMIO_H__

struct vgic_register_ops {
	unsigned long (*read)(struct kvm_vcpu *vcpu,
			      gpa_t addr,
			      int len);
	void (*write)(struct kvm_vcpu *vcpu,
		     gpa_t addr,
		     int len,
		     unsigned long val);
};

struct vgic_register_region {
	int reg_offset;
	int len;
	int bits_per_irq;
	struct vgic_register_ops ops;
};

/*
 * Some VGIC registers store per-IRQ information, with a different number
 * of bits per IRQ. For those registers this macro is used.
 * The _WITH_LENGTH version instantiates registers with a fixed length
 * and is mutually exclusive with the _PER_IRQ version.
 */
#define REGISTER_DESC_WITH_BITS_PER_IRQ(name, read_ops, write_ops, bpi) \
	{.reg_offset = name, .bits_per_irq = bpi, .len = 0, \
	 .ops.read = read_ops, .ops.write = write_ops}
#define REGISTER_DESC_WITH_LENGTH(name, read_ops, write_ops, length) \
	{.reg_offset = name, .bits_per_irq = 0, .len = length, \
	 .ops.read = read_ops, .ops.write = write_ops}

int kvm_vgic_register_mmio_region(struct kvm *kvm, struct kvm_vcpu *vcpu,
				  struct vgic_register_region *reg_desc,
				  struct vgic_io_device *region,
				  int nr_irqs, bool offset_private);

#endif
