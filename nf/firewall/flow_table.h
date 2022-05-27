#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/time.h"
#include "os/memory.h"
#include "structs/index_pool.h"
#include "structs/map.h"

struct flow {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t _padding[3];
};

struct flow_table {
	struct flow *flows;
	struct flow *reverse_flows;
	struct map *flow_indexes;
	struct map *reverse_flow_indexes;
	struct index_pool *port_allocator;
	uint16_t start_port;
	uint8_t _padding[6];
};

static inline struct flow_table *
flow_table_alloc(time_t expiration_time, size_t max_flows, uint16_t start_port)
{
	struct flow_table *table =
		os_memory_alloc(1, sizeof(struct flow_table));
	table->flows = os_memory_alloc(max_flows, sizeof(struct flow));
	table->reverse_flows = os_memory_alloc(max_flows, sizeof(struct flow));
	table->flow_indexes = map_alloc(sizeof(struct flow), max_flows);
	table->reverse_flow_indexes = map_alloc(sizeof(struct flow), max_flows);
	table->port_allocator = index_pool_alloc(max_flows, expiration_time);
	table->start_port = start_port;
	return table;
}

static inline int flow_table_add_flow(struct flow_table *table, time_t time,
				      struct flow *flow, bool dynamic_snat,
				      struct flow *reverse_flow)
{
	size_t index;
	bool was_used;
	if (map_get(table->flow_indexes, flow, &index)) {
		index_pool_refresh(table->port_allocator, time, index);
		if ((table->reverse_flows->dst_ip != reverse_flow->dst_ip) ||
		    (table->reverse_flows->dst_port !=
		     reverse_flow->dst_port)) {
			map_remove(table->reverse_flow_indexes,
				   &table->reverse_flows[index]);
			table->reverse_flows[index] = *reverse_flow;
			map_set(table->reverse_flow_indexes,
				&(table->reverse_flows[index]), index);
		}
		return 0;
	}

	size_t reverse_index;
	if (map_get(table->reverse_flow_indexes, reverse_flow,
		    &reverse_index)) {
		// conflict with an existing flow
		return 1;
	}

	if (!index_pool_borrow(table->port_allocator, time, &index,
			       &was_used)) {
		return 2;
	}

	if (was_used) {
		map_remove(table->flow_indexes, &(table->flows[index]));
		map_remove(table->reverse_flow_indexes,
			   &(table->reverse_flows[index]));
	}

	if (dynamic_snat && reverse_flow->dst_port == 0) {
		reverse_flow->dst_port = table->start_port + index;
	}

	table->flows[index] = *flow;
	table->reverse_flows[index] = *reverse_flow;
	map_set(table->flow_indexes, &(table->flows[index]), index);
	map_set(table->reverse_flow_indexes, &(table->reverse_flows[index]),
		index);
	return 0;
}

static inline bool flow_table_get_by_reverse(struct flow_table *table,
					     time_t time,
					     struct flow *reverse_flow,
					     struct flow *flow)
{
	size_t index;
	if (map_get(table->reverse_flow_indexes, reverse_flow, &index) &&
	    index_pool_used(table->port_allocator, time, index)) {
		index_pool_refresh(table->port_allocator, time, index);
		*flow = table->flows[index];
		return true;
	}
	return false;
}

static inline bool flow_table_has(struct flow_table *table, time_t time,
				  struct flow *flow)
{
	size_t index;
	if (map_get(table->flow_indexes, flow, &index) &&
	    index_pool_used(table->port_allocator, time, index)) {
		index_pool_refresh(table->port_allocator, time, index);
		return true;
	}

	return false;
}

static inline bool flow_table_has_reverse(struct flow_table *table, time_t time,
					  struct flow *flow)
{
	size_t index;
	if (map_get(table->reverse_flow_indexes, flow, &index) &&
	    index_pool_used(table->port_allocator, time, index)) {
		index_pool_refresh(table->port_allocator, time, index);
		return true;
	}

	return false;
}
