#include "os/pci.h"

#include <sys/io.h>

#include "os/fail.h"


// Physical addresses at which we can talk to PCI via geographical addressing
#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC


// Access PCI configuration space using port-mapped I/O: https://sysplay.github.io/books/LinuxDrivers/book/Content/Part08.html
// Note that Linux requires programs to call `ioperm` before accessing ports.
static void ensure_ioport_access(void)
{
	// Make sure we can talk to the devices
	// We access port 0x80 to wait after an outl, since it's the POST port so safe to do anything with (it's what glibc uses in the _p versions of outl/inl)
	// Also note that since reading an int32 is 4 bytes, we need to access 4 consecutive ports for PCI config/data.
	if (ioperm(0x80, 1, 1) < 0 || ioperm(PCI_CONFIG_ADDR, 4, 1) < 0 || ioperm(PCI_CONFIG_DATA, 4, 1) < 0) {
		os_fail("PCI ioperms failed");
	}
}

static uint32_t get_pci_reg_addr(const struct tn_pci_address address, const uint8_t reg)
{
	return 0x80000000u | ((uint32_t) address.bus << 16) | ((uint32_t) address.device << 11) | ((uint32_t) address.function << 8) | reg;
}

static void pci_target(const struct tn_pci_address address, const uint8_t reg)
{
	const uint32_t reg_addr = get_pci_reg_addr(address, reg);
	outl(reg_addr, PCI_CONFIG_ADDR);
	// Wait til the outl is done
	outb(0, 0x80);
}

size_t os_pci_enumerate(struct os_pci_address** out_devices)
{
	// TODO
	return 0;
}

uint32_t tn_pci_read(const struct tn_pci_address address, const uint8_t reg)
{
	ensure_ioport_access();
	pci_target(address, reg);
	return inl(PCI_CONFIG_DATA);
}

void tn_pci_write(const struct tn_pci_address address, const uint8_t reg, const uint32_t value)
{
	ensure_ioport_access();
	pci_target(address, reg);
	outl(value, PCI_CONFIG_DATA);
}
