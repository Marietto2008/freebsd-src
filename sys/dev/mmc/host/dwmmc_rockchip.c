/*
 * Copyright 2017 Emmanuel Vadot <manu@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>

#include <dev/mmc/bridge.h>
#include <dev/mmc/mmc_fdt_helpers.h>

#include <dev/ofw/ofw_bus_subr.h>

#include <dev/clk/clk.h>

#include <dev/mmc/host/dwmmc_var.h>
#include <dev/mmc/host/dwmmc_reg.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include "opt_mmccam.h"

/* RK3568 CRU base and SDMMC1 phase registers */
#define RK3568_CRU_BASE		0xFDD20000
#define RK3568_CRU_SIZE		0x1000
#define RK3568_SDMMC1_CON0	0x588	/* drive phase */
#define RK3568_SDMMC1_CON1	0x58C	/* sample phase */

enum RKTYPE {
	RK2928 = 1,
	RK3288,
};

static struct ofw_compat_data compat_data[] = {
	{"rockchip,rk2928-dw-mshc",	RK2928},
	{"rockchip,rk3288-dw-mshc",	RK3288},
	{NULL,				0},
};

static int dwmmc_rockchip_update_ios(struct dwmmc_softc *sc, struct mmc_ios *ios);

/* CRU mapped address (set during attach of sdmmc1) */
static volatile uint32_t *cru_base;
static int sdmmc1_sdr104_applied;

static void
rockchip_dwmmc_set_phase(device_t dev, uint32_t reg_off,
    int coarse, int fine, int invert)
{
	uint32_t val;

	if (cru_base == NULL)
		return;

	/*
	 * HIWORD_UPDATE: bits[31:16] = write mask, bits[15:0] = value
	 * Phase register layout:
	 *   bit 0:    invert
	 *   bits 5:1: coarse (0-3 = 0/90/180/270 degrees)
	 *   bits 11:6: fine delay taps
	 */
	val = (invert & 1) | ((coarse & 0x1F) << 1) | ((fine & 0x3F) << 6);
	/* Mask covers bits 11:0 */
	val |= (0xFFF << 16);

	*(volatile uint32_t *)((char *)cru_base + reg_off) = val;

	device_printf(dev, "CRU phase reg 0x%x = 0x%08x "
	    "(coarse=%d fine=%d inv=%d)\n",
	    reg_off, val, coarse, fine, invert);
}

static int
rockchip_dwmmc_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Synopsys DesignWare Mobile "
	    "Storage Host Controller (RockChip)");

	return (BUS_PROBE_VENDOR);
}

static int
rockchip_dwmmc_attach(device_t dev)
{
	struct dwmmc_softc *sc;
	int type;
	int rc;
	uint64_t freq;

	sc = device_get_softc(dev);
	sc->hwtype = HWTYPE_ROCKCHIP;
	type = ofw_bus_search_compatible(dev, compat_data)->ocd_data;

	switch (type) {
	case RK2928:
		sc->use_pio = 1;
		break;
	}

	sc->update_ios = &dwmmc_rockchip_update_ios;
	rc = dwmmc_attach(dev);

	/*
	 * Reparent CIU clock for SDMMC1 (WiFi SDIO).
	 * The default 24MHz oscillator only gives 750kHz CIU.
	 * Reparent to a PLL to get ~300MHz, allowing up to 150MHz card clock.
	 */
	if (sc->ciu && sc->bus_hz < 10000000) {
		clk_t parent;

		device_printf(dev, "CIU clock is only %u Hz, "
		    "attempting reparent\n", sc->bus_hz);

		if (clk_get_by_name(dev, "clk_sdmmc1", &parent) == 0 ||
		    clk_get_by_name(dev, "cclk_sdmmc1", &parent) == 0) {
			/* Try to set the parent clock to ~300 MHz */
			clk_set_freq(parent, 300000000, CLK_SET_ROUND_DOWN);
			clk_get_freq(parent, &freq);
			if (freq >= 100000000) {
				sc->bus_hz = (uint32_t)freq;
				device_printf(dev, "CIU clock reparented to "
				    "~300 MHz (now %u Hz), bus_hz updated\n",
				    sc->bus_hz);
			}
			clk_release(parent);
		} else {
			/* Try reparenting ciu directly */
			clk_set_freq(sc->ciu, 300000000 * 2,
			    CLK_SET_ROUND_DOWN);
			clk_get_freq(sc->ciu, &freq);
			if (freq >= 100000000) {
				sc->bus_hz = (uint32_t)freq;
				device_printf(dev, "CIU clock set to %u Hz\n",
				    sc->bus_hz);
			}
		}

		/* Map CRU registers for phase control */
		if (cru_base == NULL) {
			cru_base = (volatile uint32_t *)pmap_mapdev(
			    RK3568_CRU_BASE, RK3568_CRU_SIZE);
			if (cru_base != NULL)
				device_printf(dev, "CRU mapped at %p\n",
				    cru_base);
		}

		/* Set default phase (0°/0°) for enumeration */
		rockchip_dwmmc_set_phase(dev, RK3568_SDMMC1_CON0,
		    0, 0, 0);  /* drive: 0° */
		rockchip_dwmmc_set_phase(dev, RK3568_SDMMC1_CON1,
		    0, 0, 0);  /* sample: 0° */
		sdmmc1_sdr104_applied = 0;
	}

	return (rc);
}

static int
dwmmc_rockchip_update_ios(struct dwmmc_softc *sc, struct mmc_ios *ios)
{
	unsigned int clock;
	int error;

	/*
	 * For reparented SDMMC1 (CIU at 300MHz), do NOT touch the CIU
	 * clock or bus_hz.  The CLKDIV divider in dwmmc_setup_bus()
	 * will divide 300MHz down to the desired card clock.
	 *
	 * For non-reparented controllers (SDMMC0), use the original
	 * behavior: set CIU = 2 * desired_clock, CLKDIV = 0.
	 */
	if (sc->bus_hz >= 100000000) {
		/*
		 * Reparented SDMMC1 (CIU ~300MHz): let CLKDIV handle it.
		 * dwmmc_setup_bus() will compute the correct divider.
		 */
		return (0);
	}

	if (ios->clock && ios->clock != sc->bus_hz) {
		sc->bus_hz = clock = ios->clock;
		/* Set the MMC clock. */
		if (sc->ciu) {
			/*
			 * Apparently you need to set the ciu clock to
			 * the double of bus_hz
			 */
			error = clk_set_freq(sc->ciu, clock * 2,
			    CLK_SET_ROUND_DOWN);
			if (error != 0) {
				device_printf(sc->dev,
				    "failed to set frequency to %u Hz: %d\n",
				    clock, error);
				return (error);
			}
		}
	}

	return (0);
}

static device_method_t rockchip_dwmmc_methods[] = {
	/* bus interface */
	DEVMETHOD(device_probe, rockchip_dwmmc_probe),
	DEVMETHOD(device_attach, rockchip_dwmmc_attach),
	DEVMETHOD(device_detach, dwmmc_detach),

	DEVMETHOD_END
};

DEFINE_CLASS_1(rockchip_dwmmc, rockchip_dwmmc_driver, rockchip_dwmmc_methods,
    sizeof(struct dwmmc_softc), dwmmc_driver);

DRIVER_MODULE(rockchip_dwmmc, simplebus, rockchip_dwmmc_driver, 0, 0);
DRIVER_MODULE(rockchip_dwmmc, ofwbus, rockchip_dwmmc_driver, NULL, NULL);
#ifndef MMCCAM
MMC_DECLARE_BRIDGE(rockchip_dwmmc);
#endif
