#include "kvm/fdt.h"
#include "kvm/irq.h"
#include "kvm/kvm.h"
#include "kvm/virtio.h"

#include "arm-common/gic.h"

#include <linux/byteorder.h>
#include <linux/kernel.h>
#include <linux/kvm.h>

static int gic_fd = -1;

static int gic__create_device(struct kvm *kvm)
{
	int err;
	u64 cpu_if_addr = ARM_GIC_CPUI_BASE;
	u64 dist_addr = ARM_GIC_DIST_BASE;
	struct kvm_create_device gic_device = {
		.type	= KVM_DEV_TYPE_ARM_VGIC_V2,
	};
	struct kvm_device_attr cpu_if_attr = {
		.group	= KVM_DEV_ARM_VGIC_GRP_ADDR,
		.attr	= KVM_VGIC_V2_ADDR_TYPE_CPU,
		.addr	= (u64)(unsigned long)&cpu_if_addr,
	};
	struct kvm_device_attr dist_attr = {
		.group	= KVM_DEV_ARM_VGIC_GRP_ADDR,
		.attr	= KVM_VGIC_V2_ADDR_TYPE_DIST,
		.addr	= (u64)(unsigned long)&dist_addr,
	};

	err = ioctl(kvm->vm_fd, KVM_CREATE_DEVICE, &gic_device);
	if (err)
		return err;

	gic_fd = gic_device.fd;

	err = ioctl(gic_fd, KVM_SET_DEVICE_ATTR, &cpu_if_attr);
	if (err)
		return err;

	return ioctl(gic_fd, KVM_SET_DEVICE_ATTR, &dist_attr);
}

static int gic__create_irqchip(struct kvm *kvm)
{
	int err;
	struct kvm_arm_device_addr gic_addr[] = {
		[0] = {
			.id = KVM_VGIC_V2_ADDR_TYPE_DIST |
			(KVM_ARM_DEVICE_VGIC_V2 << KVM_ARM_DEVICE_ID_SHIFT),
			.addr = ARM_GIC_DIST_BASE,
		},
		[1] = {
			.id = KVM_VGIC_V2_ADDR_TYPE_CPU |
			(KVM_ARM_DEVICE_VGIC_V2 << KVM_ARM_DEVICE_ID_SHIFT),
			.addr = ARM_GIC_CPUI_BASE,
		}
	};

	err = ioctl(kvm->vm_fd, KVM_CREATE_IRQCHIP);
	if (err)
		return err;

	err = ioctl(kvm->vm_fd, KVM_ARM_SET_DEVICE_ADDR, &gic_addr[0]);
	if (err)
		return err;

	err = ioctl(kvm->vm_fd, KVM_ARM_SET_DEVICE_ADDR, &gic_addr[1]);
	return err;
}

int gic__init_irqchip(struct kvm *kvm)
{
	int err;

	if (kvm->nrcpus > GIC_MAX_CPUS) {
		pr_warning("%d CPUS greater than maximum of %d -- truncating\n",
				kvm->nrcpus, GIC_MAX_CPUS);
		kvm->nrcpus = GIC_MAX_CPUS;
	}

	/* Try the new way first, and fallback on legacy method otherwise */
	err = gic__create_device(kvm);
	if (err)
		err = gic__create_irqchip(kvm);

	return err;
}

static int gic__init_max_irq(struct kvm *kvm)
{
	int lines = irq__get_nr_allocated_lines();
	u32 nr_irqs = ALIGN(lines, 32) + GIC_SPI_IRQ_BASE;
	struct kvm_device_attr nr_irqs_attr = {
		.group	= KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
		.addr	= (u64)(unsigned long)&nr_irqs,
	};

	/*
	 * If we didn't use the KVM_CREATE_DEVICE method, KVM will
	 * give us some default number of interrupts.
	 */
	if (gic_fd < 0)
		return 0;

	if (!ioctl(gic_fd, KVM_HAS_DEVICE_ATTR, &nr_irqs_attr))
		return ioctl(gic_fd, KVM_SET_DEVICE_ATTR, &nr_irqs_attr);

	return 0;
}
late_init(gic__init_max_irq)

void gic__generate_fdt_nodes(void *fdt, u32 phandle)
{
	u64 reg_prop[] = {
		cpu_to_fdt64(ARM_GIC_DIST_BASE), cpu_to_fdt64(ARM_GIC_DIST_SIZE),
		cpu_to_fdt64(ARM_GIC_CPUI_BASE), cpu_to_fdt64(ARM_GIC_CPUI_SIZE),
	};

	_FDT(fdt_begin_node(fdt, "intc"));
	_FDT(fdt_property_string(fdt, "compatible", "arm,cortex-a15-gic"));
	_FDT(fdt_property_cell(fdt, "#interrupt-cells", GIC_FDT_IRQ_NUM_CELLS));
	_FDT(fdt_property(fdt, "interrupt-controller", NULL, 0));
	_FDT(fdt_property(fdt, "reg", reg_prop, sizeof(reg_prop)));
	_FDT(fdt_property_cell(fdt, "phandle", phandle));
	_FDT(fdt_end_node(fdt));
}

#define KVM_IRQCHIP_IRQ(x) (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) |\
			   ((x) & KVM_ARM_IRQ_NUM_MASK)

void kvm__irq_line(struct kvm *kvm, int irq, int level)
{
	struct kvm_irq_level irq_level = {
		.irq	= KVM_IRQCHIP_IRQ(irq),
		.level	= !!level,
	};

	if (irq < GIC_SPI_IRQ_BASE || irq > GIC_MAX_IRQ)
		pr_warning("Ignoring invalid GIC IRQ %d", irq);
	else if (ioctl(kvm->vm_fd, KVM_IRQ_LINE, &irq_level) < 0)
		pr_warning("Could not KVM_IRQ_LINE for irq %d", irq);
}

void kvm__irq_trigger(struct kvm *kvm, int irq)
{
	kvm__irq_line(kvm, irq, VIRTIO_IRQ_HIGH);
	kvm__irq_line(kvm, irq, VIRTIO_IRQ_LOW);
}
