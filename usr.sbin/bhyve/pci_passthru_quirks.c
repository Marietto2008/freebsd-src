/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 *
 * Adapted for FreeBSD 16.0 passthru_read_handler / passthru_write_handler API.
 */

#include <dev/pci/pcireg.h>

#include <err.h>
#include <errno.h>

#include "pci_passthru.h"

#define PCI_VENDOR_NVIDIA 0x10DE

/*
 * NVIDIA GPUs mirror their PCI config space at BAR0+0x88000.
 * Intercept reads from that region and forward them to the host PCI config.
 * Writes are silently ignored (read-only mirror).
 */
static uint64_t
pci_config_mirror_read(struct pci_devinst *const pi, int baridx __unused,
    uint64_t off, int size)
{
	struct passthru_softc *sc = pi->pi_arg;
	uint32_t rv;

	/*
	 * Return the virtual PCI config view (emulated overrides + hardware
	 * fallback) so that NVIDIA RM, reading via BAR0+0x88000, sees the
	 * same capability chain the guest OS sees (including the patched
	 * PCIe-cap NEXTPTR that links the orphan MSI-X cap into the chain).
	 */
	if (off <= PCI_REGMAX) {
		(void)passthru_cfgread_virt(sc, pi, (int)off, size, &rv);
		return (rv);
	}
	return (pci_host_read_config(passthru_get_sel(sc), (long)off, size));
}

static void
pci_config_mirror_write(struct pci_devinst *const pi __unused,
    int baridx __unused, uint64_t off __unused, int size __unused,
    uint64_t val __unused)
{
	/* read-only mirror — silently ignore writes */
}

static int
nvidia_gpu_probe(struct pci_devinst *const pi)
{
	struct passthru_softc *sc;
	uint16_t vendor;
	uint8_t class;

	sc = pi->pi_arg;

	vendor = pci_host_read_config(passthru_get_sel(sc), PCIR_VENDOR, 0x02);
	if (vendor != PCI_VENDOR_NVIDIA)
		return (ENXIO);

	class = pci_host_read_config(passthru_get_sel(sc), PCIR_CLASS, 0x01);
	if (class != PCIC_DISPLAY)
		return (ENXIO);

	return (0);
}

static int
nvidia_gpu_init(struct pci_devinst *const pi, nvlist_t *const nvl __unused)
{
	struct passthru_softc *sc;
	int error;

	sc = pi->pi_arg;

	error = passthru_set_bar_handler(sc, 0, 0x88000, PCIE_REGMAX,
	    pci_config_mirror_read, pci_config_mirror_write);
	if (error) {
		warnx("%s: failed to setup handler for PCI config space mirror!",
		    __func__);
		return (error);
	}

	return (0);
}

static struct passthru_dev nvidia_gpu = {
	.probe = nvidia_gpu_probe,
	.init = nvidia_gpu_init,
};
PASSTHRU_DEV_SET(nvidia_gpu);
