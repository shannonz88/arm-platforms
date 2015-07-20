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

static struct irq_domain *irq_find_acpi_domain(enum acpi_irq_model_id id,
					       enum irq_domain_bus_token bus_token)
{
	return irq_find_matching_host((void *)id, bus_token);
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
	struct irq_domain *d = irq_find_acpi_domain(acpi_irq_model,
						    DOMAIN_BUS_ANY);

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
	struct acpi_gsi_descriptor data;
	unsigned int irq_type = acpi_gsi_get_irq_type(trigger, polarity);
	struct irq_domain *d = irq_find_acpi_domain(acpi_irq_model,
						    DOMAIN_BUS_ANY);

	/*
	 * Populate the GSI descriptor in a way that matches the way
	 * the driver expects its of_phandle_args.
	 */
	switch (acpi_irq_model) {
	case ACPI_IRQ_MODEL_GIC:
		if (gsi >= 32) {
			data.param[0] = 0;
			data.param[1] = gsi - 32;
			data.param[2] = irq_type;
		} else {
			data.param[0] = 1;
			data.param[1] = gsi - 16;
			data.param[2] = 0xff << 4 | irq_type;
		}

		data.param_count = 3;
		break;
	default:
		pr_warn("Unknown acpi_irq_model = %d\n", acpi_irq_model);
		return -EINVAL;
	}

	return irq_create_acpi_mapping(d, &data);
}
EXPORT_SYMBOL_GPL(acpi_register_gsi);

/**
 * acpi_unregister_gsi() - Free a GSI<->linux IRQ number mapping
 * @gsi: GSI IRQ number
 */
void acpi_unregister_gsi(u32 gsi)
{
	struct irq_domain *d = irq_find_acpi_domain(acpi_irq_model,
						    DOMAIN_BUS_ANY);
	int irq = irq_find_mapping(d, gsi);

	irq_dispose_mapping(irq);
}
EXPORT_SYMBOL_GPL(acpi_unregister_gsi);
