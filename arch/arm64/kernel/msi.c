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
	__irq_set_handler(virq, handle_fasteoi_irq, 0, "eoi");
}

static void arm64_mask_msi_irq(struct irq_data *d)
{
	mask_msi_irq(d);
	d = d->parent_data;	/* mask_parent */
	if (d && d->chip && d->chip->irq_mask)
		d->chip->irq_mask(d);
}

static void arm64_unmask_msi_irq(struct irq_data *d)
{
	unmask_msi_irq(d);
	d = d->parent_data;	/* unmask_parent */
	if (d && d->chip && d->chip->irq_unmask)
		d->chip->irq_unmask(d);
}

static void arm64_eoi_msi_irq(struct irq_data *d)
{
	d = d->parent_data;	/* eoi_parent */
	if (d && d->chip && d->chip->irq_eoi)
		d->chip->irq_eoi(d);
}

static int arm64_set_affinity_msi_irq(struct irq_data *d,
				      const struct cpumask *mask_val,
				      bool force)
{
	d = d->parent_data;	/* set_affinity_parent */
	if (d && d->chip && d->chip->irq_set_affinity)
		return d->chip->irq_set_affinity(d, mask_val, force);

	return -EINVAL;
}

static struct irq_chip msi_irq_chip = {
	.name			= "PCI-MSI",
	.irq_unmask		= arm64_unmask_msi_irq,
	.irq_mask		= arm64_mask_msi_irq,
	.irq_eoi		= arm64_eoi_msi_irq,
	.irq_set_affinity	= arm64_set_affinity_msi_irq,
};

int arch_setup_msi_irqs(struct pci_dev *pdev, int nvec, int type)
{
	struct arm64_msi_info info;

	info.pdev = pdev;
	info.nvec = nvec;
	info.type = type;

	return msi_irq_domain_alloc_irqs(msi_default_domain, type, pdev, &info);
}

void arm64_init_msi_domain(struct irq_domain *parent)
{
	msi_default_domain = msi_create_irq_domain(NULL, &msi_irq_chip, parent);
	if (!msi_default_domain)
		pr_warn("failed to initialize irqdomain for MSI/MSI-x.\n");
}
