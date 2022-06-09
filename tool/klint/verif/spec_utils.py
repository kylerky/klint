# This file is prefixed to all specifications.
# It contains helpers that are not key to specifications but may be useful for some of them.

# TODO: Ideally, the tool would be able to infer that A->B and B->C maps can be treated as an A->C map,
# and then this class could disappear for the firewall and just have the the methods inlined into the specs...
class ExpiringSet:
    def __init__(self, elem_type, expiration_time, capacity, time, _elems_to_indices=None, _indices_to_elems=None, _indices_to_times=None):
        self.elem_type = elem_type
        self.expiration_time = expiration_time
        self.capacity = capacity
        self.time = time
        self._elems_to_indices = _elems_to_indices or Map(elem_type, "size_t")
        self._indices_to_elems = _indices_to_elems or Map("size_t", elem_type)
        self._indices_to_times = _indices_to_times or Map("size_t", Time)

    @property
    def old(self):
        return ExpiringSet(self.elem_type, self.expiration_time, self.capacity, self.time,
                           _elems_to_indices=self._elems_to_indices.old, _indices_to_elems=self._indices_to_elems.old,_indices_to_times=self._indices_to_times.old)

    @property
    def full(self):
        return (self._elems_to_indices.length == self.capacity) & \
               self._indices_to_times.forall(lambda k, v: (self.time < self.expiration_time) | (self.time - self.expiration_time <= v))

    def did_refresh(self, item):
        if item not in self._elems_to_indices:
            return False
        return self._indices_to_times[self._elems_to_indices[item]] == self.time

    def get_by_index(self, index):
        if index not in self._indices_to_times:
            return None
        if (self.time >= self.expiration_time) & (self.time - self.expiration_time > self._indices_to_times[index]):
            return None
        if index not in self._indices_to_elems:
            return None
        assert self._indices_to_elems[index] in self._elems_to_indices
        assert index == self._elems_to_indices[self._indices_to_elems[index]]
        return self._indices_to_elems[index]

    def get_index(self, item):
        if item not in self._elems_to_indices:
            return None
        return self._elems_to_indices[item]

    def __contains__(self, item):
        if item not in self._elems_to_indices:
            return False
        return (self.time < self.expiration_time) | (self.time - self.expiration_time <= self._indices_to_times[self._elems_to_indices[item]])

class ExpiringDualMap:
    def __init__(self, elem_type, expiration_time, capacity, time, _elems_to_indices=None, _elems_rev_to_indices=None, _indices_to_elems=None, _indices_to_elems_rev=None, _indices_to_times=None):
        self.elem_type = elem_type
        self.expiration_time = expiration_time
        self.capacity = capacity
        self.time = time
        self._elems_to_indices = _elems_to_indices or Map(elem_type, "size_t")
        self._elems_rev_to_indices = _elems_rev_to_indices or Map(elem_type, "size_t")
        self._indices_to_elems = _indices_to_elems or Map("size_t", elem_type)
        self._indices_to_elems_rev = _indices_to_elems_rev or Map("size_t", elem_type)
        self._indices_to_times = _indices_to_times or Map("size_t", Time)

    @property
    def old(self):
        return ExpiringDualMap(self.elem_type, self.expiration_time, self.capacity, self.time,
                               _elems_to_indices=self._elems_to_indices.old,
                               _elems_rev_to_indices=self._elems_rev_to_indices.old,
                               _indices_to_elems=self._indices_to_elems.old,
                               _indices_to_elems_rev=self._indices_to_elems_rev.old,
                               _indices_to_times=self._indices_to_times.old)

    @property
    def full(self):
        return (self._elems_to_indices.length == self.capacity) & \
               self._indices_to_times.forall(lambda k, v: (self.time < self.expiration_time) | (self.time - self.expiration_time <= v))

    def get_by_reverse(self, item):
        if item not in self._elems_rev_to_indices:
            return None
        return self._indices_to_elems[self._elems_rev_to_indices[item]]

    def __contains__(self, item):
        if item in self._elems_to_indices:
            return (self.time < self.expiration_time) | (self.time - self.expiration_time <= self._indices_to_times[self._elems_to_indices[item]])
        if item in self._elems_rev_to_indices:
            return (self.time < self.expiration_time) | (self.time - self.expiration_time <= self._indices_to_times[self._elems_rev_to_indices[item]])
        return False
