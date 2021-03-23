# Standard/External libraries
import angr
import claripy

# Us
import binary.bitsizes as bitsizes
import binary.cast as cast
import binary.utils as utils
from binary.exceptions import SymbexException
import nf.device as nf_device

# TODO add alignment part of contract
# void* os_memory_alloc(size_t count, size_t size);
# requires count == 1 || count * size <= SIZE_MAX;
# ensures chars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX;
class os_memory_alloc(angr.SimProcedure):
    def run(self, count, size):
        # Casts
        count = cast.size_t(count)
        size = cast.size_t(size)

        # Symbolism assumptions
        if size.symbolic:
            raise SymbexException("size cannot be symbolic")

        # Preconditions
        if utils.can_be_false(self.state.solver, (count == 1) | (count * size <= (2 ** bitsizes.size_t - 1))):
            raise SymbexException("Precondition does not hold: count == 1 || count * size <= SIZE_MAX")

        # Postconditions
        result = self.state.memory.allocate(count, size, name="allocated", default=claripy.BVV(0, self.state.solver.eval_one(size, cast_to=int) * 8))
        print("!!! os_memory_alloc", count, size, "->", result)
        return result

# void* os_memory_phys_to_virt(uintptr_t addr, size_t size);
class os_memory_phys_to_virt(angr.SimProcedure):
    def run(self, addr, size):
        addr = cast.ptr(addr)
        size = cast.size_t(size)

        original_addr = addr.args[0].args[2].args[0]
        if utils.can_be_false(self.state.solver, addr == original_addr):
            raise SymbexException("Sorry, expected an addr as a BAR0 high/low pair")

        devices = self.state.metadata.get_all(nf_device.SpecDevice)
        for dev in devices.values():
            if utils.definitely_true(self.state.solver, original_addr == dev.phys_addr):
                if utils.can_be_true(self.state.solver, size.UGT(dev.bar_size)):
                    raise SymbexException("Requested size is too big")
                return dev.virt_addr

        raise SymbexException("IDK what phys addr that is, sorry")

# uintptr_t os_memory_virt_to_phys(const void* addr);
class os_memory_virt_to_phys(angr.SimProcedure):
    def run(self, addr):
        addr = cast.ptr(addr)
        return addr # TODO proper handling


# No contract, not exposed publicly, only for symbex harnesses
class os_memory_havoc(angr.SimProcedure):
    def run(self, ptr):
        ptr = cast.ptr(ptr)
        print("!!! os_memory_havoc", ptr)
        self.state.memory.havoc(ptr)
