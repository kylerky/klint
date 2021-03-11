# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
from ... import bitsizes
from ... import cast
from ... import utils
from ...exceptions import SymbexException

PciDevices = namedtuple('PciDevices', ['ptr', 'count'])

# size_t os_pci_enumerate(struct os_pci_address** out_devices);
class os_pci_enumerate(angr.SimProcedure):
    def run(self, out_devices):
        out_devices = cast.ptr(out_devices)

        meta = self.state.metadata.get_all(PciDevices)
        if len(meta) == 0:
            count = claripy.BVS("pci_devices_count", bitsizes.size_t)
            self.state.add_constraints(count.ULT(256 * 32 * 8)) # 256 buses, 32 devices, 8 functions
            meta = PciDevices(
                self.state.memory.allocate(count, 8, name="pci_devices"), # 8 == sizeof(os_pci_address)
                count
            )
            self.state.metadata.set(None, meta)
        else:
            meta = meta.values()[0]

        self.state.memory.store(out_devices, meta.ptr, endness=self.state.arch.memory_endness)
        return meta.count


def get_pci_index(state, address):
    meta = state.metadata.get_all(PciDevices)
    if len(meta) == 0:
        raise SymbexException("os_pci_read/write cannot be called before os_pci_enumerate")
    meta = meta.values()[0]
    index = (address - meta.ptr) // 8 # 8 == sizeof(os_pci_address)
    index = state.solver.simplify(index.zero_extend(bitsizes.size_t - index.size()))
    if utils.definitely_true(state.solver, index == index.args[1].args[2]):
        return index.args[1].args[2]
    raise SymbexException("Sorry, this shouldn't happen, unexpected PCI addr? expected something like base_ptr + (index[60:0] .. 0)")


# uint32_t os_pci_read(const struct os_pci_address* address, uint8_t reg);
class os_pci_read(angr.SimProcedure):
    def run(self, address, reg):
        address = cast.ptr(address)
        reg = cast.uint8_t(reg)

        index = get_pci_index(self.state, address)
        ...

# void os_pci_write(const struct os_pci_address* address, uint8_t reg, uint32_t value);
class os_pci_write(angr.SimProcedure):
    def run(self, address, reg, value):
        address = cast.ptr(address)
        reg = cast.uint8_t(reg)
        value = cast.uint32_t(value)

        index = get_pci_index(self.state, address)
        ...