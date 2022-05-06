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

def firewall_rule_match(rules, t, src_handle, dst_handle, packet):
    return rules.__contains__({
       "src_handle": src_handle,
       "dst_handle": dst_handle,
       "src_port": packet.tcpudp.src,
       "dst_port": packet.tcpudp.dst,
       "type": t
    }) | rules.__contains__({
       "src_handle": src_handle,
       "dst_handle": dst_handle,
       "src_port": const(RuleKey["src_port"], 0),
       "dst_port": packet.tcpudp.dst,
       "type": t
    }) | rules.__contains__({
       "src_handle": src_handle,
       "dst_handle": dst_handle,
       "src_port": packet.tcpudp.src,
       "dst_port": const(RuleKey["dst_port"], 0),
       "type": t
    }) | rules.__contains__({
       "src_handle": src_handle,
       "dst_handle": dst_handle,
       "src_port": const(RuleKey["src_port"], 0),
       "dst_port": const(RuleKey["dst_port"], 0),
       "type": t
    })

def accept(packet, flow, flows, transmitted_packet, output_device):
    if flow not in flows:
        assert flows.old.full
    else:
        assert flows.did_refresh(flow)

    assert transmitted_packet is not None
    assert transmitted_packet.data == packet.data
    assert transmitted_packet.device == output_device

def spec(packet, config, transmitted_packet):
    if packet.device == config["management device"]:
        # TODO specify the behaviour here?
         return

    if (packet.ipv4 is None) | (packet.tcpudp is None):
        assert transmitted_packet is None
        return

    flows = ExpiringSet(Flow, config["expiration time"], config["max flows"], packet.time)
    prefixes = Map(Prefix, "int16_t")
    rules = Map(RuleKey, "size_t")

    output_device = 0
    flow = {}
    if packet.device == config["external device"]:
        flow = {
            'src_ip': packet.ipv4.dst,
            'dst_ip': packet.ipv4.src,
            'src_port': packet.tcpudp.dst,
            'dst_port': packet.tcpudp.src,
            'protocol': packet.ipv4.protocol
        }
        output_device = config["internal device"]
    else:
        flow = {
            'src_ip': packet.ipv4.src,
            'dst_ip': packet.ipv4.dst,
            'src_port': packet.tcpudp.src,
            'dst_port': packet.tcpudp.dst,
            'protocol': packet.ipv4.protocol
        }
        output_device = config["external device"]


    if flow in flows.old:
        accept(packet, flow, flows, transmitted_packet, output_device)
        return


    RULE_TYPE_DROP = const(RuleKey["type"], 0)
    RULE_TYPE_ACCEPT = const(RuleKey["type"], 1)

    if transmitted_packet is not None:
        print("A packet is transmitted")
        assert exists_batch(
            (Prefix, Prefix, AddrHandle, AddrHandle),
            lambda src, dst, src_handle, dst_handle: (
                             prefixes.__contains__(src) &
                             prefixes.__contains__(dst) &
                             matches(src, packet.ipv4.src) &
                             matches(dst, packet.ipv4.dst) &
                             prefixes.forall(lambda k, v: ~matches(k, packet.ipv4.src) | (k.length > src.length) | (v == src_handle.v)) &
                             prefixes.forall(lambda k, v: ~matches(k, packet.ipv4.dst) | (k.length > dst.length) | (v == dst_handle.v)) &
                             firewall_rule_match(rules, RULE_TYPE_ACCEPT, src_handle.v, dst_handle.v, packet)
            )
        )
        assert ~exists_batch(
            (Prefix, Prefix, AddrHandle, AddrHandle),
            lambda src, dst, src_handle, dst_handle: (
                             prefixes.__contains__(src) &
                             prefixes.__contains__(dst) &
                             matches(src, packet.ipv4.src) &
                             matches(dst, packet.ipv4.dst) &
                             prefixes.forall(lambda k, v: ~matches(k, packet.ipv4.src) | (k.length > src.length) | (v == src_handle.v)) &
                             prefixes.forall(lambda k, v: ~matches(k, packet.ipv4.dst) | (k.length > dst.length) | (v == dst_handle.v)) &
                             firewall_rule_match(rules, RULE_TYPE_DROP, src_handle.v, dst_handle.v, packet)
            )
        )
