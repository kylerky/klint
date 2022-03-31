Prefix = {
    "length": "uint8_t",
    "prefix": "uint32_t"
}

PrefixPair = {
    "src": Prefix,
    "dst": Prefix
}

RuleKey = {
    "src": "uint32_t",
    "dst": "uint32_t",
    "src_port": "uint16_t",
    "dst_port": "uint16_t",
    "src_prefixlen": "uint8_t",
    "dst_prefixlen": "uint8_t",
    "type": "uint8_t"
}

Flow = {
    'src_ip': 32,
    'dst_ip': 32,
    'src_port': 16,
    'dst_port': 16,
    'protocol': 8
}

RULE_TYPE_DROP = 0
RULE_TYPE_ACCEPT = 1

# taken from router/spec.py
def matches(route, ip):
    return (route.dest >> route.length) == (ip >> route.length)

def firewall_rule_match(rules, t, src_prefix, dst_prefix, packet):
    return rules.__contains__({
        "src": p.src.prefix,
        "src_prefixlen": p.src.length,
        "dst": p.dst.prefix,
        "dst_prefixlen": p.dst.length,
        "src_port": packet.tcpudp.src,
        "dst_port": packet.tcpudp.dst,
        "type": t
    }) or rules.__contains__({
        "src": p.src.prefix,
        "src_prefixlen": p.src.length,
        "dst": p.dst.prefix,
        "dst_prefixlen": p.dst.length,
        "src_port": 0,
        "dst_port": packet.tcpudp.dst,
        "type": t
    }) or rules.__contains__({
        "src": p.src.prefix,
        "src_prefixlen": p.src.length,
        "dst": p.dst.prefix,
        "dst_prefixlen": p.dst.length,
        "src_port": packet.tcpudp.src,
        "dst_port": 0,
        "type": t
    }) or rules.__contains__({
        "src": p.src.prefix,
        "src_prefixlen": p.src.length,
        "dst": p.dst.prefix,
        "dst_prefixlen": p.dst.length,
        "src_port": 0,
        "dst_port": 0,
        "type": t
    })

def accept(packet, flow, flows, transmitted_packet):
    if flow not in flows:
        assert flows.old.full
    else:
        assert flows.did_refresh(flow)

    assert transmitted_packet is not None
    assert transmitted_packet.data == packet.data
    assert transmitted_packet.device == 1 - packet.device

def spec(packet, config, transmitted_packet):
    if (packet.ipv4 is None) | (packet.tcpudp is None):
        assert transmitted_packet is None
        return

    flows = ExpiringSet(Flow, config["expiration time"], config["max flows"], packet.time)
    prefixes = Map(Prefix, "int64_t")
    rules = Map(RuleKey, "uint64_t")

    if packet.device == config.devices_count - 1:
        # TODO specify the behaviour here?
         return

    flow = {}
    if packet.device == config["external device"]:
        flow = {
            'src_ip': packet.ipv4.dst,
            'dst_ip': packet.ipv4.src,
            'src_port': packet.tcpudp.dst,
            'dst_port': packet.tcpudp.src,
            'protocol': packet.ipv4.protocol
        }
    else:
        flow = {
            'src_ip': packet.ipv4.src,
            'dst_ip': packet.ipv4.dst,
            'src_port': packet.tcpudp.src,
            'dst_port': packet.tcpudp.dst,
            'protocol': packet.ipv4.protocol
        }


    if flow in flows:
        accept(packet, flow, flows, transmitted_packet)
        return

    if exists(
            PrefixPair,
            lambda p: prefixes.__contains__(p.src) &
                      prefixes.__contains__(p.dst) &
                      matches(p.src, packet.ipv4.src) &
                      matches(p.dst, packet.ipv4.dst) &
                      firewall_rule_match(rules, RULE_TYPE_DROP, p.src, p.dst, packet)
    ):
    # if firewall_rule_match(rules, RULE_TYPE_DROP, {"length": 32, "prefix": packet.ipv4.src}, {"length": 32, "prefix": packet.ipv4.dst}, packet):
        assert transmitted_packet is None
        return

    if exists(
            PrefixPair,
            lambda p: prefixes.__contains__(p.src) &
                      prefixes.__contains__(p.dst) &
                      matches(p.src, packet.ipv4.src) &
                      matches(p.dst, packet.ipv4.dst) &
                      firewall_rule_match(rules, RULE_TYPE_ACCEPT, p.src, p.dst, packet)
    ):
    # if firewall_rule_match(rules, RULE_TYPE_ACCEPT, {"length": 32, "prefix": packet.ipv4.src}, {"length": 32, "prefix": packet.ipv4.dst}, packet):
        accept(packet, flow, flows, transmitted_packet)
        return

    # the default policy is to drop
    assert transmitted_packet is None
