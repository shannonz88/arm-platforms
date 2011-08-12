/*
 * Versatile Express V2M Motherboard Support
 */
#include <linux/device.h>
#include <linux/amba/bus.h>
#include <linux/amba/mmci.h>
#include <linux/amba/clcd.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/ata_platform.h>
#include <linux/smsc911x.h>
#include <linux/spinlock.h>
#include <linux/sysdev.h>
#include <linux/usb/isp1760.h>
#include <linux/clkdev.h>
#include <linux/interrupt.h>
#include <linux/clockchips.h>

#include <asm/mach-types.h>
#include <asm/sizes.h>
#include <asm/localtimer.h>
#include <asm/arch_timer.h>
#include <asm/mach/arch.h>
#include <asm/mach/flash.h>
#include <asm/mach/map.h>
#include <asm/mach/time.h>
#include <asm/hardware/arm_timer.h>
#include <asm/hardware/timer-sp.h>
#include <asm/hardware/sp810.h>
#include <asm/hardware/gic.h>

#include <mach/ct-ca9x4.h>
#include <mach/ct-ca9x4-rs1.h>
#include <mach/ct-ca15x4.h>
#include <mach/ct-ca5s.h>
#include <mach/motherboard.h>

#include <plat/sched_clock.h>
#include <plat/localtimer.h>
#include <plat/clcd.h>

#include "core.h"

void __iomem *vexpress_twd_base = NULL;

static struct map_desc v2m_io_desc[] __initdata = {
	{
		.virtual	= __MMIO_P2V(V2M_PA_CS7),
		.pfn		= __phys_to_pfn(V2M_PA_CS7),
		.length		= V2M_SIZE_CS7,
		.type		= MT_DEVICE,
	},
};

static int __cpuinit v2m_arch_timer_setup(struct clock_event_device *evt)
{
	int err;

	evt->irq = gic_ppi_to_vppi(IRQ_LOCALTIMER);

	err = request_irq(gic_ppi_to_vppi(30), percpu_timer_handler,
			  IRQF_PERCPU | IRQF_NOBALANCING | IRQF_TIMER,
			  "arch-timer-ns", evt);
	if (err) {
		pr_err("timer: can't register interrupt %d on cpu %d (%d)\n",
		       gic_ppi_to_vppi(30), smp_processor_id(), err);
		return err;
	}

	return 0;
}

static void v2m_arch_timer_teardown(struct clock_event_device *evt)
{
	free_irq(gic_ppi_to_vppi(30), evt);
}

static void __init v2m_timer_init(void)
{
	u32 scctrl;

	/*
	 * Try architected timers first. If they are not available,
	 * fallback to TWD and versatile sched_clock.
	 */
	if (!arch_timer_register_setup(v2m_arch_timer_setup,
				       v2m_arch_timer_teardown))
		return;

	/* vexpress_twd_base is assigned in the tile code */
	versatile_local_timer_init(vexpress_twd_base);

	versatile_sched_clock_init(MMIO_P2V(V2M_SYS_24MHZ), 24000000);

	/* Select 1MHz TIMCLK as the reference clock for SP804 timers */
	scctrl = readl(MMIO_P2V(V2M_SYSCTL + SCCTRL));
	scctrl |= SCCTRL_TIMEREN0SEL_TIMCLK;
	scctrl |= SCCTRL_TIMEREN1SEL_TIMCLK;
	writel(scctrl, MMIO_P2V(V2M_SYSCTL + SCCTRL));

	writel(0, MMIO_P2V(V2M_TIMER0) + TIMER_CTRL);
	writel(0, MMIO_P2V(V2M_TIMER1) + TIMER_CTRL);

	sp804_clocksource_init(MMIO_P2V(V2M_TIMER1));
	sp804_clockevents_init(MMIO_P2V(V2M_TIMER0), IRQ_V2M_TIMER0);
}

static struct sys_timer v2m_timer = {
	.init	= v2m_timer_init,
};


static DEFINE_SPINLOCK(v2m_cfg_lock);

int v2m_cfg_write(u32 devfn, u32 data)
{
	/* Configuration interface broken? */
	u32 val;

	printk("%s: writing %08x to %08x\n", __func__, data, devfn);

	devfn |= SYS_CFG_START | SYS_CFG_WRITE;

	spin_lock(&v2m_cfg_lock);
	val = readl(MMIO_P2V(V2M_SYS_CFGSTAT));
	writel(val & ~SYS_CFG_COMPLETE, MMIO_P2V(V2M_SYS_CFGSTAT));

	writel(data, MMIO_P2V(V2M_SYS_CFGDATA));
	writel(devfn, MMIO_P2V(V2M_SYS_CFGCTRL));

	do {
		val = readl(MMIO_P2V(V2M_SYS_CFGSTAT));
	} while (val == 0);
	spin_unlock(&v2m_cfg_lock);

	return !!(val & SYS_CFG_ERR);
}

int v2m_cfg_read(u32 devfn, u32 *data)
{
	u32 val;

	devfn |= SYS_CFG_START;

	spin_lock(&v2m_cfg_lock);
	writel(0, MMIO_P2V(V2M_SYS_CFGSTAT));
	writel(devfn, MMIO_P2V(V2M_SYS_CFGCTRL));

	mb();

	do {
		cpu_relax();
		val = readl(MMIO_P2V(V2M_SYS_CFGSTAT));
	} while (val == 0);

	*data = readl(MMIO_P2V(V2M_SYS_CFGDATA));
	spin_unlock(&v2m_cfg_lock);

	return !!(val & SYS_CFG_ERR);
}


static struct resource v2m_pcie_i2c_resource = {
	.start	= V2M_SERIAL_BUS_PCI,
	.end	= V2M_SERIAL_BUS_PCI + SZ_4K - 1,
	.flags	= IORESOURCE_MEM,
};

static struct platform_device v2m_pcie_i2c_device = {
	.name		= "versatile-i2c",
	.id		= 0,
	.num_resources	= 1,
	.resource	= &v2m_pcie_i2c_resource,
};

static struct resource v2m_ddc_i2c_resource = {
	.start	= V2M_SERIAL_BUS_DVI,
	.end	= V2M_SERIAL_BUS_DVI + SZ_4K - 1,
	.flags	= IORESOURCE_MEM,
};

static struct platform_device v2m_ddc_i2c_device = {
	.name		= "versatile-i2c",
	.id		= 1,
	.num_resources	= 1,
	.resource	= &v2m_ddc_i2c_resource,
};

static struct resource v2m_eth_resources[] = {
	{
		.start	= V2M_LAN9118,
		.end	= V2M_LAN9118 + SZ_64K - 1,
		.flags	= IORESOURCE_MEM,
	}, {
		.start	= IRQ_V2M_LAN9118,
		.end	= IRQ_V2M_LAN9118,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct smsc911x_platform_config v2m_eth_config = {
	.flags		= SMSC911X_USE_32BIT,
	.irq_polarity	= SMSC911X_IRQ_POLARITY_ACTIVE_HIGH,
	.irq_type	= SMSC911X_IRQ_TYPE_PUSH_PULL,
	.phy_interface	= PHY_INTERFACE_MODE_MII,
};

static struct platform_device v2m_eth_device = {
	.name		= "smsc911x",
	.id		= -1,
	.resource	= v2m_eth_resources,
	.num_resources	= ARRAY_SIZE(v2m_eth_resources),
	.dev.platform_data = &v2m_eth_config,
};

static struct platform_device v2m_eth_deprecated_device = {
	.name		= "smc91x",
	.id		= -1,
	.resource	= v2m_eth_resources,
	.num_resources	= ARRAY_SIZE(v2m_eth_resources),
};

static struct platform_device *v2m_eth_device_probe(void)
{
	u32 idrev;
	void __iomem *eth_addr = ioremap(V2M_LAN9118, SZ_4K);
	struct platform_device *eth_dev = NULL;

	if (eth_addr) {
		idrev = readl(eth_addr + 0x50);
		if ((idrev & 0xffff0000) == 0x01180000)
			eth_dev = &v2m_eth_device;
		else
			eth_dev = &v2m_eth_deprecated_device;
		iounmap(eth_addr);
	}

	return eth_dev;
}

static struct resource v2m_usb_resources[] = {
	{
		.start	= V2M_ISP1761,
		.end	= V2M_ISP1761 + SZ_128K - 1,
		.flags	= IORESOURCE_MEM,
	}, {
		.start	= IRQ_V2M_ISP1761,
		.end	= IRQ_V2M_ISP1761,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct isp1760_platform_data v2m_usb_config = {
	.is_isp1761		= true,
	.bus_width_16		= false,
	.port1_otg		= true,
	.analog_oc		= false,
	.dack_polarity_high	= false,
	.dreq_polarity_high	= false,
};

static struct platform_device v2m_usb_device = {
	.name		= "isp1760",
	.id		= -1,
	.resource	= v2m_usb_resources,
	.num_resources	= ARRAY_SIZE(v2m_usb_resources),
	.dev.platform_data = &v2m_usb_config,
};

static int v2m_flash_init(void)
{
	writel(0, MMIO_P2V(V2M_SYS_FLASH));
	return 0;
}

static void v2m_flash_exit(void)
{
	writel(0, MMIO_P2V(V2M_SYS_FLASH));
}

static void v2m_flash_set_vpp(int on)
{
	writel(on != 0, MMIO_P2V(V2M_SYS_FLASH));
}

static struct flash_platform_data v2m_flash_data = {
	.map_name	= "cfi_probe",
	.width		= 4,
	.init		= v2m_flash_init,
	.exit		= v2m_flash_exit,
	.set_vpp	= v2m_flash_set_vpp,
};

static struct resource v2m_flash_resources[] = {
	{
		.start	= V2M_NOR0,
		.end	= V2M_NOR0 + SZ_64M - 1,
		.flags	= IORESOURCE_MEM,
	}, {
		.start	= V2M_NOR1,
		.end	= V2M_NOR1 + SZ_64M - 1,
		.flags	= IORESOURCE_MEM,
	},
};

static struct platform_device v2m_flash_device = {
	.name		= "armflash",
	.id		= -1,
	.resource	= v2m_flash_resources,
	.num_resources	= ARRAY_SIZE(v2m_flash_resources),
	.dev.platform_data = &v2m_flash_data,
};

static struct pata_platform_info v2m_pata_data = {
	.ioport_shift	= 2,
};

static struct resource v2m_pata_resources[] = {
	{
		.start	= V2M_CF,
		.end	= V2M_CF + 0xff,
		.flags	= IORESOURCE_MEM,
	}, {
		.start	= V2M_CF + 0x100,
		.end	= V2M_CF + SZ_4K - 1,
		.flags	= IORESOURCE_MEM,
	},
};

static struct platform_device v2m_cf_device = {
	.name		= "pata_platform",
	.id		= -1,
	.resource	= v2m_pata_resources,
	.num_resources	= ARRAY_SIZE(v2m_pata_resources),
	.dev.platform_data = &v2m_pata_data,
};

static unsigned int v2m_mmci_status(struct device *dev)
{
	return readl(MMIO_P2V(V2M_SYS_MCI)) & (1 << 0);
}

static struct mmci_platform_data v2m_mmci_data = {
	.ocr_mask	= MMC_VDD_32_33|MMC_VDD_33_34,
	.status		= v2m_mmci_status,
};

/*
 * Motherboard CLCD controller.
 */
static void v2m_clcd_enable(struct clcd_fb *fb)
{
	v2m_cfg_write(SYS_CFG_MUXFPGA | SYS_CFG_SITE_MB, 0);
#ifdef CONFIG_ARCH_VEXPRESS_CA15X4
	/* work around model bug */
	if (ct_desc == &ct_ca15x4_desc ||
	    ct_desc == &ct_ca9x4_rs1_desc)
		return;
#endif
	v2m_cfg_write(SYS_CFG_DVIMODE | SYS_CFG_SITE_MB, 2);
}

static int v2m_clcd_setup(struct clcd_fb *fb)
{
	unsigned long framesize = 640 * 480 * 2;

	fb->panel = versatile_clcd_get_panel("VGA");
	if (!fb->panel)
		return -EINVAL;

	fb->fb.screen_base = ioremap_wc(V2M_VIDEO_SRAM, framesize);

	if (!fb->fb.screen_base) {
		pr_err("CLCD: unable to map frame buffer\n");
		return -ENOMEM;
	}

	fb->fb.fix.smem_start = V2M_VIDEO_SRAM;
	fb->fb.fix.smem_len = framesize;

	return 0;
}

static int v2m_clcd_mmap(struct clcd_fb *fb, struct vm_area_struct *vma)
{
	unsigned long off, user_size, kern_size;

	off = vma->vm_pgoff << PAGE_SHIFT;
	user_size = vma->vm_end - vma->vm_start;
	kern_size = fb->fb.fix.smem_len;

	if (off >= kern_size || user_size > (kern_size - off))
		return -ENXIO;

	return remap_pfn_range(vma, vma->vm_start,
			__phys_to_pfn(fb->fb.fix.smem_start) + vma->vm_pgoff,
			user_size,
			pgprot_writecombine(vma->vm_page_prot));
}

static void v2m_clcd_remove(struct clcd_fb *fb)
{
	iounmap(fb->fb.screen_base);
}

static struct clcd_board v2m_clcd_data = {
	.name		= "V2M",
	.caps		= CLCD_CAP_5551 | CLCD_CAP_565,
	.check		= clcdfb_check,
	.decode		= clcdfb_decode,
	.enable		= v2m_clcd_enable,
	.setup		= v2m_clcd_setup,
	.mmap		= v2m_clcd_mmap,
	.remove		= v2m_clcd_remove,
};

static AMBA_DEVICE(aaci,  "mb:aaci",  V2M_AACI, NULL);
static AMBA_DEVICE(mmci,  "mb:mmci",  V2M_MMCI, &v2m_mmci_data);
static AMBA_DEVICE(kmi0,  "mb:kmi0",  V2M_KMI0, NULL);
static AMBA_DEVICE(kmi1,  "mb:kmi1",  V2M_KMI1, NULL);
static AMBA_DEVICE(uart0, "mb:uart0", V2M_UART0, NULL);
static AMBA_DEVICE(uart1, "mb:uart1", V2M_UART1, NULL);
static AMBA_DEVICE(uart2, "mb:uart2", V2M_UART2, NULL);
static AMBA_DEVICE(uart3, "mb:uart3", V2M_UART3, NULL);
static AMBA_DEVICE(wdt,   "mb:wdt",   V2M_WDT, NULL);
static AMBA_DEVICE(rtc,   "mb:rtc",   V2M_RTC, NULL);
static AMBA_DEVICE(clcd,  "mb:clcd",  V2M_CLCD, &v2m_clcd_data);

static struct amba_device *v2m_amba_devs[] __initdata = {
	&aaci_device,
	&mmci_device,
	&kmi0_device,
	&kmi1_device,
	&uart0_device,
	&uart1_device,
	&uart2_device,
	&uart3_device,
	&wdt_device,
	&rtc_device,
};


static long v2m_osc_round(struct clk *clk, unsigned long rate)
{
	return rate;
}

static int v2m_osc1_set(struct clk *clk, unsigned long rate)
{
	return v2m_cfg_write(SYS_CFG_OSC | SYS_CFG_SITE_MB | 1, rate);
}

static const struct clk_ops osc1_clk_ops = {
	.round	= v2m_osc_round,
	.set	= v2m_osc1_set,
};

static struct clk osc1_clk = {
	.ops	= &osc1_clk_ops,
	.rate	= 24000000,
};

static struct clk osc2_clk = {
	.rate	= 24000000,
};

static struct clk dummy_apb_pclk;

static struct clk_lookup v2m_lookups[] = {
	{	/* AMBA bus clock */
		.con_id		= "apb_pclk",
		.clk		= &dummy_apb_pclk,
	}, {	/* UART0 */
		.dev_id		= "mb:uart0",
		.clk		= &osc2_clk,
	}, {	/* UART1 */
		.dev_id		= "mb:uart1",
		.clk		= &osc2_clk,
	}, {	/* UART2 */
		.dev_id		= "mb:uart2",
		.clk		= &osc2_clk,
	}, {	/* UART3 */
		.dev_id		= "mb:uart3",
		.clk		= &osc2_clk,
	}, {	/* KMI0 */
		.dev_id		= "mb:kmi0",
		.clk		= &osc2_clk,
	}, {	/* KMI1 */
		.dev_id		= "mb:kmi1",
		.clk		= &osc2_clk,
	}, {	/* MMC0 */
		.dev_id		= "mb:mmci",
		.clk		= &osc2_clk,
	}, {	/* CLCD */
		.dev_id		= "mb:clcd",
		.clk		= &osc1_clk,
	},
};

static void __init v2m_init_early(void)
{
	ct_desc->init_early();
	clkdev_add_table(v2m_lookups, ARRAY_SIZE(v2m_lookups));
	versatile_sched_clock_init(MMIO_P2V(V2M_SYS_24MHZ), 24000000);
}

static void v2m_power_off(void)
{
	if (v2m_cfg_write(SYS_CFG_SHUTDOWN | SYS_CFG_SITE_MB, 0))
		printk(KERN_EMERG "Unable to shutdown\n");
}

static void v2m_restart(char str, const char *cmd)
{
	if (v2m_cfg_write(SYS_CFG_REBOOT | SYS_CFG_SITE_MB, 0))
		printk(KERN_EMERG "Unable to reboot\n");
}

struct ct_desc *ct_desc;

static struct ct_desc *ct_descs[] __initdata = {
#ifdef CONFIG_ARCH_VEXPRESS_CA5S
	&ct_ca5s_desc,
#endif
#ifdef CONFIG_ARCH_VEXPRESS_CA9X4
	&ct_ca9x4_desc,
#endif
#ifdef CONFIG_ARCH_VEXPRESS_CA9X4_RS1
	&ct_ca9x4_rs1_desc,
#endif
#ifdef CONFIG_ARCH_VEXPRESS_CA15X4
	&ct_ca15x4_desc,
#endif
};

static void __init v2m_populate_ct_desc(void)
{
	int i;
	u32 procid_reg, current_tile_id;

	ct_desc = NULL;
	procid_reg = readl(MMIO_P2V(V2M_SYS_MISC)) & SYS_MISC_MASTERSITE ?
			V2M_SYS_PROCID1 : V2M_SYS_PROCID0;
	current_tile_id = readl(MMIO_P2V(procid_reg));

	for (i = 0; i < ARRAY_SIZE(ct_descs) && !ct_desc; ++i) {
		const struct ct_id *ct_id = ct_descs[i]->id_table;

		while (ct_id->id) {
			if ((current_tile_id & ct_id->mask) == ct_id->id) {
				ct_desc = ct_descs[i];
				break;
			}
			ct_id++;
		}
	}

	if (!ct_desc)
		panic("vexpress: failed to populate core tile description "
		      "for tile ID 0x%8x\n", current_tile_id);
}

static void __init v2m_map_io(void)
{
	iotable_init(v2m_io_desc, ARRAY_SIZE(v2m_io_desc));
	v2m_populate_ct_desc();
	ct_desc->map_io();
}

static void __init v2m_init_irq(void)
{
	ct_desc->init_irq();
}

static void __init v2m_init(void)
{
	int i;
	struct platform_device *eth_dev;

	platform_device_register(&v2m_pcie_i2c_device);
	platform_device_register(&v2m_ddc_i2c_device);
	platform_device_register(&v2m_flash_device);
	platform_device_register(&v2m_cf_device);
	platform_device_register(&v2m_usb_device);

	eth_dev = v2m_eth_device_probe();
	if (eth_dev)
		platform_device_register(eth_dev);

	for (i = 0; i < ARRAY_SIZE(v2m_amba_devs); i++)
		amba_device_register(v2m_amba_devs[i], &iomem_resource);

	pm_power_off = v2m_power_off;
	arm_pm_restart = v2m_restart;

	ct_desc->init_tile();

	/* Register the onboard CLCD as a fallback display controller */
	amba_device_register(&clcd_device, &iomem_resource);
}

static const char *vexpress_dt_match[] __initdata = {
	"arm,vexpress",
	NULL,
};

MACHINE_START(VEXPRESS, "ARM-Versatile Express")
	.boot_params	= PLAT_PHYS_OFFSET + 0x00000100,
	.map_io		= v2m_map_io,
	.init_early	= v2m_init_early,
	.init_irq	= v2m_init_irq,
	.timer		= &v2m_timer,
	.init_machine	= v2m_init,
	.dt_compat	= vexpress_dt_match,
MACHINE_END
