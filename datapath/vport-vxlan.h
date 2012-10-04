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

struct vxlan_mutable_config {
    struct rcu_head   rcu;
    u32               vni;
    __be32            vtep;
    __be32            mcast_ip;

    u32	              flags;
    u16               vtep_port;
    u16               mcast_port;
    u8                eth_addr[ETH_ALEN];

    u8	              tos;
    u8	              ttl;
    u32               seq;

};

struct vxlan_vport {
	struct rcu_head rcu;
	struct hlist_node hash_node;

	char name[IFNAMSIZ];

	struct vxlan_mutable_config __rcu *mutable;

	spinlock_t cache_lock;
	struct tnl_cache __rcu *cache;	/* Protected by RCU/cache_lock. */

#ifdef NEED_CACHE_TIMEOUT
	/*
	 * If we must rely on expiration time to invalidate the cache, this is
	 * the interval.  It is randomized within a range (defined by
	 * MAX_CACHE_EXP in tunnel.c) to avoid synchronized expirations caused
	 * by creation of a large number of tunnels at a one time.
	 */
	unsigned long cache_exp_interval;
#endif

    struct net          *net;
    struct socket __rcu *rcv_socket;  /* VTEP receive socket */
    struct socket __rcu *mcast_socket; /* MULTICAST receive/send socket */
    struct hlist_head __rcu *mac_table;
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

int ovs_vxlan_init (void);
void ovs_vxlan_exit (void);

#endif /* VPORT_VXLAN_H */

