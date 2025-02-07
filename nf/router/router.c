#include "net/skeleton.h"

#include "os/log.h"

#include "structs/lpm.h"


static device_t devices_count;
static struct lpm* lpm;

bool nf_init(device_t _devices_count)
{
	devices_count = _devices_count;
	lpm = lpm_alloc();
	return true;
}


void nf_handle(struct net_packet* packet)
{
	if (packet->device == devices_count - 1) {
		// "Management" interface, obviously not practical but just to show it can be done
		lpm_update_elem(lpm, ((uint32_t*) packet->data)[0], ((uint8_t*)packet->data)[4], ((uint16_t*)packet->data)[3]);
		return;
	}

	struct net_ether_header* ether_header;
	struct net_ipv4_header* ipv4_header;
	if (!net_get_ether_header(packet, &ether_header) || !net_get_ipv4_header(ether_header, &ipv4_header)) {
		os_debug("Not IPv4 over Ethernet");
		return;
	}

	if ((ipv4_header->version_ihl >> 4) != 4u) {
		os_debug("Not IPv4");
		return;
	}

	if ((ipv4_header->version_ihl & 0xF) < 5u) { // ihl is in units of 4 bytes
		os_debug("IPv4 header too short");
		return;
	}

	if (ipv4_header->total_length < ((ipv4_header->version_ihl & 0xF) * 4u)) {
		os_debug("Total length too short");
		return;
	}

	if (!net_ipv4_checksum_valid(ipv4_header)) {
		os_debug("Bad packet checksum");
		return;
	}

	if (ipv4_header->time_to_live == 0u) {
		os_debug("Packet lifetime is over");
		return;
	}

	device_t dst_device;
	uint32_t out_prefix;
	uint8_t out_prefixlen;
	if (lpm_lookup_elem(lpm, ipv4_header->dst_addr, &dst_device, &out_prefix, &out_prefixlen)) {
		net_transmit(packet, dst_device, UPDATE_ETHER_ADDRS);
	}
}
