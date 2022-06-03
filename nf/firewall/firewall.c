#include "net/tx.h"
#include <stdint.h>

#include "net/skeleton.h"
#include "net/packet.h"

#include "os/config.h"
#include "os/log.h"
#include "os/time.h"
#include "os/memory.h"

#include "structs/lpm.h"
#include "structs/map.h"
#include "structs/index_pool.h"

#include "flow_table.h"

static device_t external_device;
static device_t internal_device;
static device_t management_device;

static struct flow_table *flows;
static struct lpm *prefix_matcher;
static struct map *rules;

static struct nat_target *nat_targets;

static size_t max_nat_targets;

struct rule_key {
	uint16_t src_handle;
	uint16_t dst_handle;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t type;
	uint8_t _padding;
};

static struct rule_key *rule_keys;
static struct index_pool *rule_handle_allocator;

const uint8_t RULE_TYPE_DROP = 0;
const uint8_t RULE_TYPE_ACCEPT = 1;
const uint8_t RULE_TYPE_IS_TCP_MASK = 2;
const uint8_t RULE_TYPE_SNAT = 4;

struct nat_target {
	uint32_t ip;
	uint16_t port;
	uint8_t _padding[2];
};

const uint16_t DYNAMIC_SNAT_START_PORT = 1024;

bool nf_init(device_t devices_count)
{
	if (devices_count != 3) {
		/* os_debug("The number of devices is not 3"); */
		return false;
	}

	time_t expiration_time;
	time_t rule_expiration_time;
	size_t max_flows;
	size_t max_rules;
	if (!os_config_get_device("external device", devices_count,
				  &external_device) ||
	    !os_config_get_device("internal device", devices_count,
				  &internal_device) ||
	    !os_config_get_device("management device", devices_count,
				  &management_device) ||
	    !os_config_get_time("expiration time", &expiration_time) ||
	    !os_config_get_size("max flows", &max_flows) ||
	    !os_config_get_size("max NAT targets", &max_nat_targets) ||
	    !os_config_get_size("max rules", &max_rules) ||
	    !os_config_get_time("rule expiration time",
				&rule_expiration_time)) {
		/* os_debug("NF failed to get the configurations"); */
		return false;
	}

	flows = flow_table_alloc(expiration_time, max_flows,
				 DYNAMIC_SNAT_START_PORT);
	prefix_matcher = lpm_alloc();
	rules = map_alloc(sizeof(struct rule_key), max_rules);

	rule_keys = os_memory_alloc(max_rules, sizeof(struct rule_key));
	rule_handle_allocator =
		index_pool_alloc(max_rules, rule_expiration_time);

	nat_targets =
		os_memory_alloc(max_nat_targets, sizeof(struct nat_target));
	return true;
}

bool check_rules_map(uint16_t src_handle, uint16_t dst_handle, uint8_t type,
		     struct net_tcpudp_header *tcpudp_header, size_t *value)
{
	// look up the matching rule if any
	struct rule_key key = {
		.src_handle = src_handle,
		.dst_handle = dst_handle,
		.src_port = tcpudp_header->src_port,
		.dst_port = tcpudp_header->dst_port,
		.type = type,
	};

	if (map_get(rules, &key, value)) {
		return true;
	}

	// set src_port to wildcard (0 for wildcard)
	key.src_port = 0;
	if (map_get(rules, &key, value)) {
		return true;
	}

	// restore the src_port
	// and set dst_port to wildcard (0 for wildcard)
	key.src_port = tcpudp_header->src_port;
	key.dst_port = 0;
	if (map_get(rules, &key, value)) {
		return true;
	}

	// set both dst_port and src_port to wildcard (0 for wildcard)
	key.src_port = 0;
	if (map_get(rules, &key, value)) {
		return true;
	}
	return false;
}

void nf_handle_management(struct net_packet *packet)
{
	char *data = &packet->data[1];
	char type = packet->data[0];
	switch (type) {
	case 0: {
		os_debug("Receive an LPM update.");

		lpm_update_elem(prefix_matcher, ((uint32_t *)data)[0],
				((uint8_t *)data)[4], ((uint16_t *)data)[3]);
	} break;
	case 1: {
		os_debug("Receive a rule table update.");

		struct rule_key *key_ptr = (struct rule_key *)&data[0];
		key_ptr->_padding = 0;

		size_t dummy;
		size_t *value_ptr = (size_t *)&key_ptr[1];
		size_t new_value = *value_ptr;
		if (new_value >= max_nat_targets) {
			break;
		}

		if (!map_get(rules, key_ptr, &dummy)) {
			bool was_used;
			size_t index;
			if (index_pool_borrow(rule_handle_allocator,
					      packet->time, &index,
					      &was_used)) {
				if (was_used) {
					map_remove(rules, &rule_keys[index]);
				}

				rule_keys[index] = *key_ptr;

				map_set(rules, &rule_keys[index], new_value);
			}
		}
	} break;
	case 2: {
		os_debug("Receive an NAT target update.");

		uint64_t *index_ptr = (uint64_t *)&data[0];
		uint64_t index = *index_ptr;
		if (index >= max_nat_targets) {
			break;
		}

		struct nat_target *target_ptr =
			(struct nat_target *)&index_ptr[1];
		nat_targets[index] = *target_ptr;
	} break;
	default:
		// ignore
		break;
	}
}

void maybe_snat(uint16_t src_handle, uint16_t dst_handle, time_t time,
		struct net_ipv4_header *ipv4_header,
		struct net_tcpudp_header *tcpudp_header,
		enum net_transmit_flags *flags)
{
	size_t target_index;
	if (!check_rules_map(src_handle, dst_handle, RULE_TYPE_SNAT,
			     tcpudp_header, &target_index)) {
		struct flow flow = {
			.src_ip = ipv4_header->src_addr,
			.dst_ip = ipv4_header->dst_addr,
			.src_port = tcpudp_header->src_port,
			.dst_port = tcpudp_header->dst_port,
			.protocol = ipv4_header->next_proto_id,
		};

		struct flow reverse_flow = {
			.src_ip = ipv4_header->dst_addr,
			.dst_ip = ipv4_header->src_addr,
			.src_port = tcpudp_header->dst_port,
			.dst_port = tcpudp_header->src_port,
			.protocol = ipv4_header->next_proto_id,
		};

		flow_table_add_flow(flows, time, &flow, false, &reverse_flow);
		return;
	}

	struct nat_target *target = &nat_targets[target_index];

	struct flow flow = {
		.src_ip = ipv4_header->src_addr,
		.dst_ip = ipv4_header->dst_addr,
		.src_port = tcpudp_header->src_port,
		.dst_port = tcpudp_header->dst_port,
		.protocol = ipv4_header->next_proto_id,
	};

	struct flow reverse_flow = {
		.src_ip = ipv4_header->dst_addr,
		.dst_ip = target->ip,
		.src_port = tcpudp_header->dst_port,
		.dst_port = target->port,
		.protocol = ipv4_header->next_proto_id,
	};

	flow_table_add_flow(flows, time, &flow, true, &reverse_flow);

	net_packet_checksum_update_32(ipv4_header, ipv4_header->src_addr,
				      target->ip, true);
	net_packet_checksum_update(ipv4_header, tcpudp_header->src_port,
				   target->port, false);
	ipv4_header->src_addr = target->ip;
	tcpudp_header->src_port = target->port;
	*flags = UPDATE_ETHER_ADDRS;
}

void maybe_snat_reverse(time_t time, struct net_ipv4_header *ipv4_header,
			struct net_tcpudp_header *tcpudp_header,
			enum net_transmit_flags *flags)
{
	struct flow flow = {
		.src_ip = ipv4_header->src_addr,
		.dst_ip = ipv4_header->dst_addr,
		.src_port = tcpudp_header->src_port,
		.dst_port = tcpudp_header->dst_port,
		.protocol = ipv4_header->next_proto_id,
	};

	struct flow original_flow;
	if (!flow_table_get_by_reverse(flows, time, &flow, &original_flow)) {
		return;
	}

	net_packet_checksum_update_32(ipv4_header, ipv4_header->dst_addr,
				      original_flow.src_ip, true);
	net_packet_checksum_update(ipv4_header, tcpudp_header->dst_port,
				   original_flow.src_port, false);
	ipv4_header->dst_addr = original_flow.src_ip;
	tcpudp_header->dst_port = original_flow.src_port;
	*flags = UPDATE_ETHER_ADDRS;
}

void nf_handle(struct net_packet *packet)
{
	if (packet->device == management_device) {
		// "Management" interface
		nf_handle_management(packet);
		return;
	}

	struct net_ether_header *ether_header;
	struct net_ipv4_header *ipv4_header;
	struct net_tcpudp_header *tcpudp_header;
	if (!net_get_ether_header(packet, &ether_header) ||
	    !net_get_ipv4_header(ether_header, &ipv4_header) ||
	    !net_get_tcpudp_header(ipv4_header, &tcpudp_header)) {
		os_debug("Not TCP/UDP over IPv4 over Ethernet");
		return;
	}

	enum net_transmit_flags transmit_flags = NONE;
	maybe_snat_reverse(packet->time, ipv4_header, tcpudp_header,
			   &transmit_flags);

	uint16_t src_handle;
	uint32_t src_prefix;
	uint8_t src_prefixlen;
	uint16_t dst_handle;
	uint32_t dst_prefix;
	uint8_t dst_prefixlen;

	bool has_handles =
		lpm_lookup_elem(prefix_matcher, ipv4_header->src_addr,
				&src_handle, &src_prefix, &src_prefixlen) &&
		lpm_lookup_elem(prefix_matcher, ipv4_header->dst_addr,
				&dst_handle, &dst_prefix, &dst_prefixlen);

	uint8_t mask = ipv4_header->next_proto_id == IP_PROTOCOL_TCP ?
			       RULE_TYPE_IS_TCP_MASK :
			       0;
	size_t dummy_index;
	if (has_handles &&
	    check_rules_map(src_handle, dst_handle, mask | RULE_TYPE_DROP,
			    tcpudp_header, &dummy_index)) {
		os_debug("Drop a packet due to the deny rules");
		return;
	}

	struct flow flow = {
		.src_ip = ipv4_header->src_addr,
		.dst_ip = ipv4_header->dst_addr,
		.src_port = tcpudp_header->src_port,
		.dst_port = tcpudp_header->dst_port,
		.protocol = ipv4_header->next_proto_id,
	};
	if (flow_table_has(flows, packet->time, &flow) ||
	    flow_table_has_reverse(flows, packet->time, &flow) ||
	    (has_handles &&
	     check_rules_map(src_handle, dst_handle, mask | RULE_TYPE_ACCEPT,
			     tcpudp_header, &dummy_index))) {
		if (has_handles) {
			maybe_snat(src_handle, dst_handle, packet->time,
				   ipv4_header, tcpudp_header, &transmit_flags);
		}

		device_t output_device = packet->device == external_device ?
						 internal_device :
						 external_device;
		net_transmit(packet, output_device, transmit_flags);
		return;
	}

	os_debug("Drop a packet due to the default policy");
}
