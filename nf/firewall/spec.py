Prefix = {
    "length": "uint8_t",
    "prefix": "uint32_t"
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

# taken from router/spec.py
def matches(route, ip):
    return (route.prefix >> route.length) == (ip >> route.length)

def firewall_rule_match(rules, t, src_prefix, dst_prefix, packet):
    return (
    {
       "src": src_prefix.prefix,
       "dst": dst_prefix.prefix,
       "src_port": packet.tcpudp.src,
       "dst_port": packet.tcpudp.dst,
       "src_prefixlen": src_prefix.length,
       "dst_prefixlen": dst_prefix.length,
       "type": t
    } in rules or
    {
       "src": src_prefix.prefix,
       "dst": dst_prefix.prefix,
       "src_port": const(RuleKey["src_port"], 0),
       "dst_port": packet.tcpudp.dst,
       "src_prefixlen": src_prefix.length,
       "dst_prefixlen": dst_prefix.length,
       "type": t
    } in rules or
    {
       "src": src_prefix.prefix,
       "dst": dst_prefix.prefix,
       "src_port": packet.tcpudp.src,
       "dst_port": const(RuleKey["dst_port"], 0),
       "src_prefixlen": src_prefix.length,
       "dst_prefixlen": dst_prefix.length,
       "type": t
    } in rules or
    {
       "src": src_prefix.prefix,
       "dst": dst_prefix.prefix,
       "src_port": const(RuleKey["src_port"], 0),
       "dst_port": const(RuleKey["dst_port"], 0),
       "src_prefixlen": src_prefix.length,
       "dst_prefixlen": dst_prefix.length,
       "type": t
    } in rules)

def accept(packet, flow, flows, transmitted_packet):
    if flow not in flows:
        assert flows.old.full
    else:
        assert flows.did_refresh(flow)

    assert transmitted_packet is not None
    assert transmitted_packet.data == packet.data
    assert transmitted_packet.device == 1 - packet.device

def spec(packet, config, transmitted_packet):
    RULE_TYPE_DROP = const(RuleKey["type"], 0)
    RULE_TYPE_ACCEPT = const(RuleKey["type"], 1)

    if (packet.ipv4 is None) | (packet.tcpudp is None):
        assert transmitted_packet is None
        return

    flows = ExpiringSet(Flow, config["expiration time"], config["max flows"], packet.time)
    prefixes = Map(Prefix, "int16_t")
    rules = Map(RuleKey, "size_t")

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

    if exists_batch(
            (Prefix, Prefix),
            lambda src, dst: (src in prefixes) &
                             (dst in prefixes) &
                             matches(src, packet.ipv4.src) &
                             matches(dst, packet.ipv4.dst) &
                             prefixes.forall(lambda k, v: ~matches(k, packet.ipv4.src) | (k.length <= src.length)) &
                             prefixes.forall(lambda k, v: ~matches(k, packet.ipv4.dst) | (k.length <= dst.length)) &
                             firewall_rule_match(rules, RULE_TYPE_DROP, src, dst, packet)
    ):
        assert transmitted_packet is None
        return

    if exists_batch(
            (Prefix, Prefix),
            lambda src, dst: (src in prefixes) &
                             (dst in prefixes) &
                             matches(src, packet.ipv4.src) &
                             matches(dst, packet.ipv4.dst) &
                             prefixes.forall(lambda k, v: ~matches(k, packet.ipv4.src) | (k.length <= src.length)) &
                             prefixes.forall(lambda k, v: ~matches(k, packet.ipv4.dst) | (k.length <= dst.length)) &
                             firewall_rule_match(rules, RULE_TYPE_ACCEPT, src, dst, packet)
    ):
        accept(packet, flow, flows, transmitted_packet)
        return

    assert transmitted_packet is None
