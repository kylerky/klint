// Originally from the TinyNF project, modified to use new abstractions

// Network abstractions.
// A 'device' represents a physical network card: https://en.wikipedia.org/wiki/Network_interface_controller
// Devices only handle packets destined to them by default, by looking at packets' MAC address: https://en.wikipedia.org/wiki/MAC_address
// Devices can be set into 'promiscuous' mode to handle all packets regardless of MAC address.
// Each device has one 'queue' to receive packet, and multiple 'queues' to transmit packets.
// An 'agent' handles packets received on one input device, forwarding them through zero or more output devices as needed.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/pci.h"


// Configuration API
// -----------------

struct tn_net_device;
struct tn_net_agent;

struct tn_net_device* tn_net_device_alloc(struct os_pci_address pci_address);
void tn_net_device_set_promiscuous(struct tn_net_device* device);
uint64_t tn_net_device_get_mac(struct tn_net_device* device); // only the lowest 48 bits are nonzero, in big-endian

// Assumes the input should not be an output. (It'd be nice to have the flexibility, but in practice we don't need it for now)
struct tn_net_agent* tn_net_agent_alloc(size_t input_index, size_t devices_count, struct tn_net_device** devices);


// Packet processing API
// ---------------------

// Sets outputs[N] = length of the packet on device N, where 0 means drop (devices are in the order they were added)
typedef void tn_net_packet_handler(size_t index, uint8_t* packet, size_t length, size_t* output_lengths);
// Runs the agents forever using the given handler
_Noreturn void tn_net_run(size_t agents_count, struct tn_net_agent** agents, tn_net_packet_handler* handler);
