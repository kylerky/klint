/*
 * Copyright 2018 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// compat layer for Polycube
#include "polycube.h"

#ifndef FDB_TIMEOUT
#define FDB_TIMEOUT 300
#endif

#include <bcc/helpers.h>
#include <bcc/proto.h>

#include <uapi/linux/bpf.h>
//#include <uapi/linux/filter.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/pkt_cls.h>

#define REASON_FLOODING 0x01

struct fwd_entry {
  u32 timestamp;
  u32 port;
} __attribute__((packed, aligned(8)));

BPF_TABLE("hash", __be64, struct fwd_entry, fwdtable, 1024);

struct eth_hdr {
  __be64 dst : 48;
  __be64 src : 48;
  __be16 proto;
} __attribute__((packed));

static __always_inline u32 time_get_sec() {
  return bpf_ktime_get_ns();
}

static int handle_rx(struct CTXTYPE *ctx,
                                     struct pkt_metadata *md) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct eth_hdr *eth = data;

  if (data + sizeof(*eth) > data_end)
    return RX_DROP;

  u32 in_ifc = ctx->ingress_ifindex;

  pcn_log(ctx, LOG_TRACE, "Received a new packet from port %d", in_ifc);
  pcn_log(ctx, LOG_TRACE, "mac src:%M dst:%M", eth->src, eth->dst);

  // LEARNING PHASE
  __be64 src_key = eth->src;
  u32 now = time_get_sec();

  struct fwd_entry *entry = bpf_map_lookup_elem(&fwdtable, &src_key);

  if (!entry) {
    struct fwd_entry e;  // used to update the entry in the fdb

    e.timestamp = now;
    e.port = in_ifc;

    bpf_map_update_elem(&fwdtable, &src_key, &e, BPF_ANY);
    pcn_log(ctx, LOG_TRACE, "MAC: %M learned", src_key);
  } else {
    entry->port = in_ifc;
    entry->timestamp = now;
    bpf_map_update_elem(&fwdtable, &src_key, entry, BPF_ANY);
  }

  // FORWARDING PHASE: select interface(s) to send the packet
  __be64 dst_mac = eth->dst;
  // lookup in forwarding table fwdtable
  entry = bpf_map_lookup_elem(&fwdtable, &dst_mac);
  if (!entry) {
    pcn_log(ctx, LOG_DEBUG, "Entry not found for dst-mac: %M", dst_mac);
    goto DO_FLOODING;
  }

  u64 timestamp = entry->timestamp;

  // Check if the entry is still valid (not too old)
  if ((now - timestamp) > FDB_TIMEOUT) {
    pcn_log(ctx, LOG_TRACE, "Entry is too old. FLOODING");
    bpf_map_delete_elem(&fwdtable, &dst_mac);
    goto DO_FLOODING;
  }

  pcn_log(ctx, LOG_TRACE, "Entry is valid. FORWARDING");

FORWARD:;
  u32 dst_interface = entry->port;  // workaround for verifier

  // HIT in forwarding table
  // redirect packet to dst_interface

  /* do not send packet back on the ingress interface */
  if (dst_interface == in_ifc) {
    pcn_log(
        ctx, LOG_TRACE,
        "Destination interface is equals to the input interface. DROP packet");
    return RX_DROP;
  }

  pcn_log(ctx, LOG_DEBUG, "Redirect packet to port %d", dst_interface);
  return pcn_pkt_redirect(ctx, md, dst_interface);

DO_FLOODING:
  pcn_log(ctx, LOG_DEBUG, "Flooding required: sending packet to controller");
  pcn_pkt_controller(ctx, md, REASON_FLOODING);
  return RX_DROP;
}
