/*
 * Copyright (c) 2011 Nicira, Inc.
 * Copyright (c) 2012 Cisco Systems, Inc.
 * Copyright (c) 2013 Freescale, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef VPORT_VXLAN_H
#define VPORT_VXLAN_H 1

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/xfrm.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/xfrm.h>

#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"

#define VXLAN_UDP_PORT 4341
#define VXLAN_MCAST_PORT 4341
#define VXLAN_IPSEC_SRC_PORT 4564

#define VXLAN_FLAGS 0x08000000	/* struct vxlanhdr.vx_flags required value. */

/**
 * struct vxlanhdr - VXLAN header
 * @vx_flags: Must have the exact value %VXLAN_FLAGS.
 * @vx_vni: VXLAN Network Identifier (VNI) in top 24 bits, low 8 bits zeroed.
 */
struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};


#if 0
enum {
    VXLAN_MAC_ENTRY_FLAGS_NONE = (0),
    VXLAN_MAC_ENTRY_FLAGS_LEARNED = (1 << 0),
    VXLAN_MAC_ENTRY_FLAGS_CONFIGURED = (1 << 1),
};
#endif

struct vxlan_mac_entry {
    struct rcu_head    rcu;
    struct hlist_node  hash_node;
    struct list_head   lru_link;
	u32                vni;
    __be32             peer; 
    unsigned long      age;
    u8                 macaddr[ETH_ALEN];
};


static inline struct vxlanhdr *vxlan_hdr(const struct sk_buff *skb)
{
	return (struct vxlanhdr *)(udp_hdr(skb) + 1);
}

#define VXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct vxlanhdr))

static inline int vxlan_hdr_len(const struct tnl_mutable_config *mutable)
{
	return VXLAN_HLEN;
}

struct genl_family;

int ovs_vxlan_init (void);
void ovs_vxlan_exit (void);
int ovs_vxlan_peer_add (u32 vni, __be32 peer_vtep, struct sk_buff *reply);
int ovs_vxlan_peer_del (u32 vni, __be32 peer_vtep, struct sk_buff *reply);
int ovs_vxlan_vme_del (u32 vni, u8 *macaddr, struct sk_buff *reply);
int ovs_vxlan_peer_dump (struct genl_family *vxlan_family, struct sk_buff *skb, struct netlink_callback *cb);
int ovs_vxlan_vme_dump (struct genl_family *vxlan_family, struct sk_buff *skb, struct netlink_callback *cb);

#endif /* VPORT_VXLAN_H */

