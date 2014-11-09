#ifndef _IRQ_GIC_V2M_H_
#define _IRQ_GIC_V2M_H_

int gicv2m_of_init(struct device_node *node, struct irq_domain *parent) __init;

#endif /* _IRQ_GIC_V2M_H_ */
