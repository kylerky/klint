import angr
import claripy
from collections import namedtuple
from datetime import datetime
import inspect
import os
from pathlib import Path

from .common import *
from binary import bitsizes
from binary import utils
from binary.externals.os import config as os_config
from binary.externals.os import network as os_network
from binary.ghost_maps import *
from python import executor as py_executor


class SpecMap:
    def __init__(self, state, map, key_type, value_type):
        self._state = state
        self._map = map
        self._key_type = key_type
        self._value_type = value_type

    def forall(self, pred):
        pred = MapInvariant.new(self._state, self._map.meta, lambda i: (~i.present | pred(type_cast(self._state, i.key, self._key_type), type_cast(self._state, i.value, self._value_type)))._value)
        return ValueProxy(self._state, self._map.forall(self._state, pred))

def map_new(state, key_type, value_type):
    key_size = type_size(state, key_type) * 8
    value_size = type_size(state, value_type) * 8
    candidates = [m for (o, m) in state.maps if m.meta.key_size == key_size and m.meta.value_size == value_size]
    if len(candidates) == 0:
        # TODO padding can mess things up, ideally this should do candidate_size >= desired_size and then truncate
        raise VerificationException("No such map.")
    if len(candidates) > 1:
        raise VerificationException("Picking a candidate isn't implemented yet, sorry.")
    return SpecMap(state, candidates[0], key_type, value_type)


externals = {
    "Map": map_new
}

def handle_externals(name, *args, **kwargs):
    global current_state

    ext = externals[name]
    if inspect.isclass(ext): # it's a SimProcedure
        ext_inst = ext()
        ext_inst.state = current_state
        args = [a if isinstance(a, claripy.ast.base.Base) else claripy.BVV(a, bitsizes.size_t) for a in args]
        result = ext_inst.run(*args)
        if result.size() == bitsizes.bool and not result.symbolic:
            return not result.structurally_match(claripy.BVV(0, bitsizes.bool))
        return result
    else:
        return ext(current_state, *args)


def verify(data, spec):
    global current_state
    current_state = create_angr_state(data.constraints)
    current_state.maps = data.maps

    packet = SpecPacket(current_state, data.network)

    transmitted_packet = None
    if data.network.transmitted:
        if len(data.network.transmitted) > 1:
            raise "TODO support symbolic packets as ORs of all of them"
        transmitted_packet = data.network.transmitted[0]

    result = py_executor.execute(
        spec_text=spec,
        spec_fun_name="spec",
        spec_args=[packet, data.config, transmitted_packet], # TODO: add device count somewhere... maybe make it an attr (not item) of config
        spec_external_names=externals.keys(),
        spec_external_handler=handle_externals
    )

    if result is not None and not result:
        raise VerificationException("Spec returned False")

    if data.network.transmitted and not got_transmitted_packet:
        raise VerificationException("There is a packet but the spec says there should not be")

    print("NF verif done! at", datetime.now())