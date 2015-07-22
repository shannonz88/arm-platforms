/*
 * ACPI GSI IRQ layer
 *
 * Copyright (C) 2015 ARM Ltd.
 * Author: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/acpi.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>

enum acpi_irq_model_id acpi_irq_model;

static void *acpi_gsi_domain_token;

static int (*acpi_gsi_descriptor_populate)(struct acpi_gsi_descriptor *data,
					   u32 gsi, unsigned int irq_type);

static unsigned int acpi_gsi_get_irq_type(int trigger, int polarity)
{
	switch (polarity) {
	case ACPI_ACTIVE_LOW:
		return trigger == ACPI_EDGE_SENSITIVE ?
		       IRQ_TYPE_EDGE_FALLING :
		       IRQ_TYPE_LEVEL_LOW;
	case ACPI_ACTIVE_HIGH:
		return trigger == ACPI_EDGE_SENSITIVE ?
		       IRQ_TYPE_EDGE_RISING :
		       IRQ_TYPE_LEVEL_HIGH;
	case ACPI_ACTIVE_BOTH:
		if (trigger == ACPI_EDGE_SENSITIVE)
			return IRQ_TYPE_EDGE_BOTH;
	default:
		return IRQ_TYPE_NONE;
	}
}

/**
 * acpi_gsi_to_irq() - Retrieve the linux irq number for a given GSI
 * @gsi: GSI IRQ number to map
 * @irq: pointer where linux IRQ number is stored
 *
 * irq location updated with irq value [>0 on success, 0 on failure]
 *
 * Returns: linux IRQ number on success (>0)
 *          -EINVAL on failure
 */
int acpi_gsi_to_irq(u32 gsi, unsigned int *irq)
{
	struct irq_domain *d = irq_find_host(acpi_gsi_domain_token);

	*irq = irq_find_mapping(d, gsi);
	/*
	 * *irq == 0 means no mapping, that should
	 * be reported as a failure
	 */
	return (*irq > 0) ? *irq : -EINVAL;
}
EXPORT_SYMBOL_GPL(acpi_gsi_to_irq);

/**
 * acpi_register_gsi() - Map a GSI to a linux IRQ number
 * @dev: device for which IRQ has to be mapped
 * @gsi: GSI IRQ number
 * @trigger: trigger type of the GSI number to be mapped
 * @polarity: polarity of the GSI to be mapped
 *
 * Returns: a valid linux IRQ number on success
 *          -EINVAL on failure
 */
int acpi_register_gsi(struct device *dev, u32 gsi, int trigger,
		      int polarity)
{
	int err;
	struct acpi_gsi_descriptor data;
	unsigned int irq_type = acpi_gsi_get_irq_type(trigger, polarity);
	struct irq_domain *d = irq_find_host(acpi_gsi_domain_token);

	if (WARN_ON(!acpi_gsi_descriptor_populate)) {
		pr_warn("GSI: No registered irqchip, giving up\n");
		return -EINVAL;
	}

	err = acpi_gsi_descriptor_populate(&data, gsi, irq_type);
	if (err)
		return err;

	return irq_create_acpi_mapping(d, &data);
}
EXPORT_SYMBOL_GPL(acpi_register_gsi);

/**
 * acpi_unregister_gsi() - Free a GSI<->linux IRQ number mapping
 * @gsi: GSI IRQ number
 */
void acpi_unregister_gsi(u32 gsi)
{
	struct irq_domain *d = irq_find_host(acpi_gsi_domain_token);
	int irq = irq_find_mapping(d, gsi);

	irq_dispose_mapping(irq);
}
EXPORT_SYMBOL_GPL(acpi_unregister_gsi);

/**
 * acpi_set_irq_model - Setup the GSI irqdomain information
 * @model: the value assigned to acpi_irq_model
 * @domain_token: the irq_domain identifier for mapping and looking up
 *                GSI interrupts
 * @populate: provided by the interrupt controller, populating a
 *            struct acpi_gsi_descriptor based on a GSI and
 *            the interrupt trigger information
 */
void acpi_set_irq_model(enum acpi_irq_model_id model,
			unsigned long domain_token,
			int (*populate)(struct acpi_gsi_descriptor *,
					u32, unsigned int))
{
	acpi_irq_model = model;
	acpi_gsi_domain_token = (void *)domain_token;
	acpi_gsi_descriptor_populate = populate;
}
