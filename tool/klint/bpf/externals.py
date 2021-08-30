import angr
import claripy
from collections import namedtuple

from kalm import utils
from klint.bpf import detection

BpfMapDef = namedtuple('BpfMapDef', ['type', 'key_size', 'value_size', 'max_entries', 'flags'])
BpfMap = namedtuple('BpfMap', ['map_def', 'values', 'items'])


# Not an external, called to mimic the kernel initializing a map
def map_init(state, addr, map_def):
    print("Map init", addr, map_def)
    assert utils.definitely_true(state.solver, map_def.flags == 0) # no flags handled yet

    type = utils.get_if_constant(state.solver, map_def.type)
    if type == 1:
        # Hash map
        values = state.heap.allocate(map_def.max_entries, map_def.value_size, default_fraction=0)
        items = state.maps.new(map_def.key_size * 8, state.sizes.ptr, "bpf_map")
        state.metadata.append(addr, BpfMap(map_def, values, items))
    elif type == 14:
        # Dev map, only for redirect calls, we don't fully model those yet
        return
    else:
        raise Exception("Unsupported map type: " + str(type))

def align(n, val):
    if not isinstance(val, int):
        if val.symbolic: raise Exception("nope")
        val = val.args[0]
    if val % n == 0:
        return val
    return val + (n - (val % n))


# void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
class bpf_map_lookup_elem(angr.SimProcedure):
    def run(self, map, key):
        print("lookup", map, key)
        print("map", self.state.metadata.get(BpfMap, map))
        raise "TODO"

# long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)
class bpf_map_update_elem(angr.SimProcedure):
    def run(self, map, key, value, flags):
        print("update", map, key, value, flags)
        print("map", self.state.metadata.get(BpfMap, map))
        raise "TODO"

# long bpf_map_delete_elem(struct bpf_map *map, const void *key)
class bpf_map_delete_elem(angr.SimProcedure):
    def run(self, map, key):
        print("delete", map, key)
        print("map", self.state.metadata.get(BpfMap, map))
        raise "TODO"

# void *__htab_map_lookup_elem(struct bpf_map *map, void *key)
# The specialized hash version of bpf_map_lookup_elem.
# Returns NULL iff lookup failed, else a pointer to the actual value in the map (i.e., not a copy, can be mutated by users)
# Equivalent pseudo-VeriFast contract:
#  requires bpfmap(map, ?def, ?values, ?items) &*&
#           key != NULL &*&
#           [?f]chars(key, def.key_size, ?key_data);
#  ensures bpfmap(map, def, values, items) &*&
#          switch(ghostmap_get(items, key_data)) {
#              case none: result == NULL;
#              case some(i): result == values + i * def.value_size &*& [100]chars(result, def.value_size, _);
#          };
# HOWEVER: if the result is non-NULL, it's negatively shifted by some amount
#          because what it really returns is a pointer to the hash table entry, and the BPF code compensates to find the pointer to the value
class __htab_map_lookup_elem(angr.SimProcedure):
    def run(self, map, key):
        # Casts
        map = self.state.casts.ptr(map)
        key = self.state.casts.ptr(key)

        # Preconditions
        bpfmap = self.state.metadata.get(BpfMap, map)
        assert utils.definitely_true(self.state.solver, key != 0)
        key_data = self.state.memory.load(key, bpfmap.map_def.key_size, endness=self.state.arch.memory_endness)

        # Postconditions
        def case_has(state, index):
            result = bpfmap.values + index * bpfmap.map_def.value_size
            linux_ver = detection.get_linux_version()
            # Figure this out by looking at a BPF dump that includes a call to __htab_map_lookup_elem :-/
            # Alternatively, try with the existing offset and see if it works or if it obviously needs a correction (e.g. the code is trying to access an item 1 off the target)
            if linux_ver == '5.4.0-81-generic' and detection.is_64bit():
                offset = 48 + align(8, bpfmap.map_def.key_size)
            else:
                raise("Sorry, you need to do some work here as well: " + __file__)
            return result - offset
        def case_not(state):
            return claripy.BVV(0, state.sizes.ptr)
        return utils.fork_guarded_has(self, self.state, bpfmap.items, key_data, case_has, case_not)

# int htab_map_update_elem(struct bpf_map *map, void *key, void *value, u64 map_flags)
# Copies both the key and the value into the map
# Equivalent pseudo-VeriFast contract (very "pseudo" here):
#  requires bpfmap(map, ?def, ?values, ?items) &*&
#           key != NULL &*&
#           value != NULL &*&
#           [?fk]chars(key, def.key_size, ?key_data) &*&
#           [?fv]chars(value, def.value_size, ?value_data) &*&
#           flags == BPF_ANY; // TODO remove this one
#  ensures [fk]chars(key, def.key_size, ?key_data) &*&
#          [fv]chars(value, def.value_size, ?value_data) &*&
#          switch(ghostmap_get(items, key_data)) {
#              case some: result == 0 &*& bpfmap(map, def, values, items) &*& [0]chars(values + i * def.value_size, def.value_size, value_data); // unsound overwite by design!
#              case none: length(items) == def.max_entries ? result == -1 &*& bpfmap(map, def, values, items)
#                                                          : result == 0 &*& bpfmap(map, def, values, ghostmap_set(items, key_data, ?i)) &*&
#                                                            0 <= i &*& i < bpfmap.def.max_entries &*&
#                                                            [100]chars(values + i * def.value_size, def.value_size, value_data) &*&
#                                                            <the previous fraction of 'i' in 'values' was 0, now it's 100>;
#          };
class htab_map_update_elem(angr.SimProcedure):
    def run(self, map, key, value, flags):
        # Casts
        map = self.state.casts.ptr(map)
        key = self.state.casts.ptr(key)
        value = self.state.casts.ptr(value)
        flags = self.state.casts.uint64_t(flags)

        # Preconditions
        bpfmap = self.state.metadata.get(BpfMap, map)
        assert utils.definitely_true(self.state.solver, (key != 0) & (value != 0))
        key_data = self.state.memory.load(key, bpfmap.map_def.key_size, endness=self.state.arch.memory_endness)
        value_data = self.state.memory.load(value, bpfmap.map_def.value_size, endness=self.state.arch.memory_endness)
        assert utils.definitely_true(self.state.solver, flags == 0)

        def case_has(state, i):
            state.heap.UNCHECKED_store(bpfmap.values + i * bpfmap.map_def.value_size, value_data, endness=state.arch.memory_endness)
            return claripy.BVV(0, 32)
        def case_not(state):
            def case_true(state):
                return claripy.BVV(-1, 32)
            def case_false(state):
                i = claripy.BVS("i", state.sizes.ptr)
                state.solver.add(i.UGE(0) & i.ULT(bpfmap.map_def.max_entries))
                state.solver.add(state.heap.get_fraction(bpfmap.values + i * bpfmap.map_def.value_size) == 0) # needs to be a separate call, otherwise 'i' might be out of bounds
                state.heap.give(100, bpfmap.values + i * bpfmap.map_def.value_size)
                state.memory.store(bpfmap.values + i * bpfmap.map_def.value_size, value_data, endness=state.arch.memory_endness)
                state.maps.set(bpfmap.items, key_data, i)
                return claripy.BVV(0, 32)
            return utils.fork_guarded(self, state, state.maps.length(bpfmap.items) == bpfmap.map_def.max_entries, case_true, case_false)
        return utils.fork_guarded_has(self, self.state, bpfmap.items, key_data, case_has, case_not)

# long bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)
# "XDP_REDIRECT on success, or the value of the two lower bits of the flags argument on error."
# The description makes it sound like the flags are not used for anything else, which a look at the source code confirms
# For now let's just make it always succeed
class bpf_redirect_map(angr.SimProcedure):
    def run(self, map, key, flags):
        return claripy.BVV(3, self.state.sizes.ptr) # XDP_TX

# long bpf_xdp_redirect_map(struct bpf_map *map, u32 key, u64 flags)
# In practice, an alias for bpf_redirect_map
class bpf_xdp_redirect_map(angr.SimProcedure):
    def run(self, map, key, flags):
        return self.inline_call(bpf_redirect_map, map, key, flags).ret_expr

# u64 bpf_ktime_get_ns(void)
class bpf_ktime_get_ns(angr.SimProcedure):
    def run(self):
        print("ktime")
        raise "TODO"
