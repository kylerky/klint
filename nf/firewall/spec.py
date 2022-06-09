Prefix = {
    "length": "uint8_t",
    "prefix": "uint32_t"
}

RuleKey = {
    "src_handle": "uint16_t",
    "dst_handle": "uint16_t",
    "src_port": "uint16_t",
    "dst_port": "uint16_t",
    "type": "uint8_t"
}

AddrHandle = {
    "v": "uint16_t"
}

Flow = {
    'src_ip': 32,
    'dst_ip': 32,
    'src_port': 16,
    'dst_port': 16,
    'protocol': 8
}

# taken from router/spec.py
def matches(route, ip):
    return (route.prefix >> route.length) == (ip >> route.length)

def firewall_rule_lookup(rules, t, src_handle, dst_handle, flow):
    assert ((flow['protocol'] == 6) | (flow['protocol'] == 17))

    keys = [{
       "src_handle": src_handle,
       "dst_handle": dst_handle,
       "src_port": flow['src_port'],
       "dst_port": flow['dst_port'],
       "type": t
    }, {
       "src_handle": src_handle,
       "dst_handle": dst_handle,
       "src_port": const(RuleKey["src_port"], 0),
       "dst_port": flow['dst_port'],
       "type": t
    }, {
       "src_handle": src_handle,
       "dst_handle": dst_handle,
       "src_port": flow['src_port'],
       "dst_port": const(RuleKey["dst_port"], 0),
       "type": t
    }, {
       "src_handle": src_handle,
       "dst_handle": dst_handle,
       "src_port": const(RuleKey["src_port"], 0),
       "dst_port": const(RuleKey["dst_port"], 0),
       "type": t
    }]

    for k in keys:
        if k in rules:
            return (True, rules[k])
    return (False, None)

def firewall_rule_lookup_satisfy(rules, t, src_handle, dst_handle, flow, predicate):
    result = firewall_rule_lookup((rules, t, src_handle, dst_handle, flow)
    return result[0] & predicate(result[1])

def accept(packet, flow, flows, transmitted_packet, output_device):
    if flow not in flows:
        assert flows.old.full
    else:
        # TODO: Implement did_refresh for ExpiringDualMap
        # assert flows.did_refresh(flow)
        pass

    assert transmitted_packet is not None
    assert transmitted_packet.device == output_device

def spec(packet, config, transmitted_packet):
    if packet.device == config["management device"]:
        # TODO specify the behaviour here?
         return

    if (packet.ipv4 is None) | (packet.tcpudp is None):
        assert transmitted_packet is None
        return

    flows = ExpiringDualMap(Flow, config["expiration time"], config["max flows"], packet.time)
    prefixes = Map(Prefix, "int16_t")
    rules = Map(RuleKey, "size_t")

    output_device = 0
    if packet.device == config["external device"]:
        output_device = config["internal device"]
    else:
        output_device = config["external device"]

    flow = {
        'src_ip': packet.ipv4.src,
        'dst_ip': packet.ipv4.dst,
        'src_port': packet.tcpudp.src,
        'dst_port': packet.tcpudp.dst,
        'protocol': packet.ipv4.protocol
    }
    original_snat_flow = flows.get_by_reverse(flow)
    if original_snat_flow is not None:
        flow['dst_ip'] = original_snat_flow.src_ip
        flow['dst_port'] = original_snat_flow.src_port

    RULE_TYPE_ACCEPT = const(RuleKey["type"], 1)
    RULE_VALUE_DROP_MASK = const("size_t", 2) if flow['protocol'] == 6 else const("size_t", 1)

    # the deny rules have higher priorities over the flow table
    # so that we can stop established flows with the deny rules
    if exists_batch(
            (Prefix, Prefix, AddrHandle, AddrHandle),
            lambda src, dst, src_handle, dst_handle: (
                             prefixes.__contains__(src) &
                             prefixes.__contains__(dst) &
                             matches(src, flow['src_ip']) &
                             matches(dst, flow['dst_ip']) &
                             prefixes.forall(lambda k, v: ~matches(k, flow['src_ip']) | (k.length > src.length) | (v == src_handle.v)) &
                             prefixes.forall(lambda k, v: ~matches(k, flow['dst_ip']) | (k.length > dst.length) | (v == dst_handle.v)) &
                             firewall_rule_lookup_satisfy(
                                 rules,
                                 RULE_TYPE_ACCEPT,
                                 src_handle.v,
                                 dst_handle.v,
                                 flow,
                                 lambda v: (v & RULE_VALUE_DROP_MASK) != 0))):
        assert transmitted_packet is None
        return

    RULE_VALUE_ACCEPT_MASK = const("size_t", 8) if flow['protocol'] == 6 else const("size_t", 4)
    if (flow in flows.old or
        exists_batch(
            (Prefix, Prefix, AddrHandle, AddrHandle),
            lambda src, dst, src_handle, dst_handle: (
                             prefixes.__contains__(src) &
                             prefixes.__contains__(dst) &
                             matches(src, flow['src_ip']) &
                             matches(dst, flow['dst_ip']) &
                             prefixes.forall(lambda k, v: ~matches(k, flow['src_ip']) | (k.length > src.length) | (v == src_handle.v)) &
                             prefixes.forall(lambda k, v: ~matches(k, flow['dst_ip']) | (k.length > dst.length) | (v == dst_handle.v)) &
                             firewall_rule_lookup_satisfy(
                                 rules,
                                 RULE_TYPE_ACCEPT,
                                 src_handle.v,
                                 dst_handle.v,
                                 flow,
                                 lambda v: (v & RULE_VALUE_ACCEPT_MASK) != 0)))):
        # TODO: specify the behaviour of SNAT
        # in addition to the fact that the firewall has sent something
        accept(packet, flow, flows, transmitted_packet, output_device)
        print("Packet accepted according to rules")
        return

    assert transmitted_packet is None
