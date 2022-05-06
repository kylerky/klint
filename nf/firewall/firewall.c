#include <stdint.h>

#include "net/skeleton.h"

#include "os/config.h"
#include "os/log.h"
#include "os/time.h"
#include "os/memory.h"

#include "structs/lpm.h"
#include "structs/map.h"
#include "structs/index_pool.h"

#include "flow_table.h"

static device_t external_device;
static device_t management_device;

static struct flow_table *table;
static struct lpm *prefix_matcher;
static struct map *rules;

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

bool nf_init(device_t devices_count)
{
	if (devices_count != 3) {
		os_debug("The number of devices is not 3");
		return false;
	}

	time_t expiration_time;
	time_t rule_expiration_time;
	size_t max_flows;
	size_t max_rules;
	if (!os_config_get_device("external device", devices_count - 1,
				  &external_device) ||
	    !os_config_get_time("expiration time", &expiration_time) ||
	    !os_config_get_size("max flows", &max_flows) ||
	    !os_config_get_size("max rules", &max_rules) ||
	    !os_config_get_time("rule expiration time",
				&rule_expiration_time)) {
		os_debug("NF failed to get the configurations");
		return false;
	}
	management_device = devices_count - 1;

	table = flow_table_alloc(expiration_time, max_flows);
	prefix_matcher = lpm_alloc();
	rules = map_alloc(sizeof(struct rule_key), max_rules);

	rule_keys = os_memory_alloc(max_rules, sizeof(struct rule_key));
	rule_handle_allocator =
		index_pool_alloc(max_rules, rule_expiration_time);
	return true;
}

bool check_rules_map(struct lpm *matcher, uint8_t type,
		     struct net_ipv4_header *ipv4_header,
		     struct net_tcpudp_header *tcpudp_header)
{
	uint16_t src_handle;
	uint32_t src_prefix;
	uint8_t src_prefixlen;
	if (!lpm_lookup_elem(matcher, ipv4_header->src_addr, &src_handle,
			     &src_prefix, &src_prefixlen)) {
		return false;
	}

	uint16_t dst_handle;
	uint32_t dst_prefix;
	uint8_t dst_prefixlen;
	if (!lpm_lookup_elem(matcher, ipv4_header->dst_addr, &dst_handle,
			     &dst_prefix, &dst_prefixlen)) {
		return false;
	}

	// look up the matching rule if any
	struct rule_key key = {
		.src_handle = src_handle,
		.dst_handle = dst_handle,
		.src_port = tcpudp_header->src_port,
		.dst_port = tcpudp_header->dst_port,
		.type = type,
	};

	size_t predicate;
	if (map_get(rules, &key, &predicate)) {
		return true;
	}

	// set src_port to wildcard (0 for wildcard)
	key.src_port = 0;
	if (map_get(rules, &key, &predicate)) {
		return true;
	}

	// restore the src_port
	// and set dst_port to wildcard (0 for wildcard)
	key.src_port = tcpudp_header->src_port;
	key.dst_port = 0;
	if (map_get(rules, &key, &predicate)) {
		return true;
	}

	// set both dst_port and src_port to wildcard (0 for wildcard)
	key.src_port = 0;
	if (map_get(rules, &key, &predicate)) {
		return true;
	}
	return false;
}

bool check_rules(struct net_ipv4_header *ipv4_header,
		 struct net_tcpudp_header *tcpudp_header)
{
	if (check_rules_map(prefix_matcher, RULE_TYPE_DROP, ipv4_header,
			    tcpudp_header)) {
		return false;
	}

	if (check_rules_map(prefix_matcher, RULE_TYPE_ACCEPT, ipv4_header,
			    tcpudp_header)) {
		return true;
	}
	// the default policy is to drop the packets that are not accepted
	return false;
}

void nf_handle_management(struct net_packet *packet)
{
	char *data = &packet->data[1];
	if (packet->data[0] == 0) {
		os_debug("Receive an LPM update.");

		lpm_update_elem(prefix_matcher, ((uint32_t *)data)[0],
				((uint8_t *)data)[4], ((uint16_t *)data)[3]);
	} else {
		os_debug("Receive a rule table update.");

		struct rule_key *key_ptr =
			(struct rule_key *)&((uint32_t *)data)[0];
		key_ptr->_padding = 0;

		size_t dummy;
		if (!map_get(rules, key_ptr, &dummy)) {
			bool was_used;
			size_t index;
			if (index_pool_borrow(rule_handle_allocator,
					      packet->time, &index,
					      &was_used)) {
				if (was_used) {
					map_remove(rules, &rule_keys[index]);
				}
				size_t *pred_ptr = (size_t *)&key_ptr[1];
				size_t new_pred = *pred_ptr;

				rule_keys[index] = *key_ptr;

				map_set(rules, &rule_keys[index], new_pred);
			}
		}
	}
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

	struct flow flow;
	if (packet->device == external_device) {
		flow = ((struct flow){
			// inverted!
			.src_ip = ipv4_header->dst_addr,
			.dst_ip = ipv4_header->src_addr,
			.src_port = tcpudp_header->dst_port,
			.dst_port = tcpudp_header->src_port,
			.protocol = ipv4_header->next_proto_id,

		});
	} else {
		flow = ((struct flow){
			.src_ip = ipv4_header->src_addr,
			.dst_ip = ipv4_header->dst_addr,
			.src_port = tcpudp_header->src_port,
			.dst_port = tcpudp_header->dst_port,
			.protocol = ipv4_header->next_proto_id,
		});
	}

	if (flow_table_has_external(table, packet->time, &flow) ||
	    check_rules(ipv4_header, tcpudp_header)) {
		flow_table_learn_internal(table, packet->time, &flow);

		net_transmit(packet, 1 - packet->device, 0);
		return;
	}

	os_debug("Drop a new flow from the external");
}
