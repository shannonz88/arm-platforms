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

#ifndef __ARM64_MSI_H__
#define __ARM64_MSI_H__

struct arm64_msi_info {
	struct pci_dev		*pdev;
	irq_hw_number_t		msi_hwirq;
	int			nvec;
	int			type;
};

void arm64_init_msi_domain(struct irq_domain *parent);

#endif /* __ARM64_MSI_H__ */
