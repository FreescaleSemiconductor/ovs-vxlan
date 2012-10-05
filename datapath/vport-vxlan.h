 /*
 * Copyright (c) 2011 Nicira Networks.
 * Copyright (c) 2012 Cisco Systems Inc.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
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

struct vxlan_vport {
	struct rcu_head rcu;
	struct hlist_node hash_node;

	char name[IFNAMSIZ];

	struct tnl_mutable_config __rcu *mutable;

    struct net          *net;
    struct socket __rcu *rcv_socket;  /* VTEP receive socket */
    struct socket __rcu *mcast_socket; /* MULTICAST receive/send socket */
    struct hlist_head __rcu *mac_table;

    struct tnl_ops tnl_ops;
};


enum {
    VXLAN_MAC_ENTRY_FLAGS_NONE = (0),
    VXLAN_MAC_ENTRY_FLAGS_LEARNED = (1 << 0),
    VXLAN_MAC_ENTRY_FLAGS_CONFIGURED = (1 << 1),
};

struct vxlan_mac_entry {
    struct rcu_head    rcu;
    struct hlist_node  hash_node;
    __be32             peer; 
    u8                 macaddr[ETH_ALEN];
    u16                flags;
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


int ovs_vxlan_init (void);
void ovs_vxlan_exit (void);

#endif /* VPORT_VXLAN_H */

