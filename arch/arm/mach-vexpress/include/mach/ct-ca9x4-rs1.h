#ifndef __MACH_CT_CA9X4_RS1_H
#define __MACH_CT_CA9X4_RS1_H

/*
 * Physical base addresses
 */
#define CT_CA9X4_RS1_MPIC	(0x2c000000)
#define CT_CA9X4_RS1_L2CC	(0x2c100000)

#define A9_RS1_MPCORE_SCU	(CT_CA9X4_RS1_MPIC + 0x0000)
#define A9_RS1_MPCORE_GIC_CPU	(CT_CA9X4_RS1_MPIC + 0x0100)
#define A9_RS1_MPCORE_TWD	(CT_CA9X4_RS1_MPIC + 0x0600)
#define A9_RS1_MPCORE_GIC_DIST	(CT_CA9X4_RS1_MPIC + 0x1000)

extern struct ct_desc ct_ca9x4_rs1_desc;

#endif
