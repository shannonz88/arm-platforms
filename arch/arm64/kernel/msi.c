/*
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

#include <linux/irq.h>
#include <linux/msi.h>

#include <asm/msi.h>

static struct irq_domain *msi_default_domain;
static irq_flow_handler_t msi_flow_handler;

irq_hw_number_t arch_msi_irq_domain_get_hwirq(void *arg)
{
	struct arm64_msi_info *info = arg;

	return info->msi_hwirq;
}

void arch_msi_irq_domain_set_hwirq(void *arg, irq_hw_number_t msi_hwirq)
{
	struct arm64_msi_info *info = arg;

	info->msi_hwirq = msi_hwirq;
}

void arch_msi_irq_set_handler(unsigned int virq)
{
	__irq_set_handler(virq, msi_flow_handler, 0, NULL);
}

static void arm64_mask_msi_irq(struct irq_data *d)
{
	mask_msi_irq(d);
	irq_chip_mask_parent(d);
}

static void arm64_unmask_msi_irq(struct irq_data *d)
{
	unmask_msi_irq(d);
	irq_chip_unmask_parent(d);
}

static struct irq_chip msi_irq_chip = {
	.name			= "PCI-MSI",
	.irq_unmask		= arm64_unmask_msi_irq,
	.irq_mask		= arm64_mask_msi_irq,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
};

int arch_setup_msi_irqs(struct pci_dev *pdev, int nvec, int type)
{
	struct arm64_msi_info info;

	info.pdev = pdev;
	info.nvec = nvec;

	return msi_irq_domain_alloc_irqs(msi_default_domain, type, pdev, &info);
}

void arm64_init_msi_domain(struct irq_domain *parent, irq_flow_handler_t handle)
{
	WARN_ON(msi_default_domain);
	WARN_ON(msi_flow_handler);
	msi_flow_handler = handle;
	msi_default_domain = msi_create_irq_domain(NULL, &msi_irq_chip, parent);
	if (!msi_default_domain)
		pr_warn("failed to initialize irqdomain for MSI/MSI-x.\n");
}
