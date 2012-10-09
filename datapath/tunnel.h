/*
 * Copyright (c) 2007-2012 Nicira, Inc.
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

#ifndef TUNNEL_H
#define TUNNEL_H 1

#include <linux/version.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "flow.h"
#include "openvswitch/tunnel.h"
#include "vport.h"

/*
 * The absolute minimum fragment size.  Note that there are many other
 * definitions of the minimum MTU.
 */
#define IP_MIN_MTU 68

/*
 * One of these goes in struct tnl_ops and in tnl_find_port().
 * These values are in the same namespace as other TNL_T_* values, so
 * only the least significant 10 bits are available to define protocol
 * identifiers.
 */
#define TNL_T_PROTO_GRE		0
#define TNL_T_PROTO_CAPWAP	1
#define TNL_T_PROTO_VXLAN	2

/* These flags are only needed when calling tnl_find_port(). */
#define TNL_T_KEY_EXACT		(1 << 10)
#define TNL_T_KEY_MATCH		(1 << 11)
#define TNL_T_IPSEC		(1 << 12)

/* Private flags not exposed to userspace in this form. */
#define TNL_F_IN_KEY_MATCH	(1 << 16) /* Store the key in tun_id to
					   * match in flow table. */
#define TNL_F_OUT_KEY_ACTION	(1 << 17) /* Get the key from a SET_TUNNEL
					   * action. */

/* All public tunnel flags. */
#define TNL_F_PUBLIC (TNL_F_CSUM | TNL_F_TOS_INHERIT | TNL_F_TTL_INHERIT | \
		      TNL_F_DF_INHERIT | TNL_F_DF_DEFAULT | TNL_F_PMTUD | \
		      TNL_F_HDR_CACHE | TNL_F_IPSEC)

/**
 * struct port_lookup_key - Tunnel port key, used as hash table key.
 * @in_key: Key to match on input, 0 for wildcard.
 * @net: Network namespace of the port.
 * @saddr: IPv4 source address to match, 0 to accept any source address.
 * @daddr: IPv4 destination of tunnel.
 * @tunnel_type: Set of TNL_T_* flags that define lookup.
 */
struct port_lookup_key {
	__be64 in_key;
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
	__be32 saddr;
	__be32 daddr;
	u32    tunnel_type;
};

#define PORT_KEY_LEN	(offsetof(struct port_lookup_key, tunnel_type) + \
			 FIELD_SIZEOF(struct port_lookup_key, tunnel_type))

static inline struct net *port_key_get_net(const struct port_lookup_key *key)
{
	return read_pnet(&key->net);
}

static inline void port_key_set_net(struct port_lookup_key *key, struct net *net)
{
	write_pnet(&key->net, net);
}

/**
 * struct tnl_mutable_config - modifiable configuration for a tunnel.
 * @key: Used as key for tunnel port.  Configured via OVS_TUNNEL_ATTR_*
 * attributes.
 * @rcu: RCU callback head for deferred destruction.
 * @seq: Sequence number for distinguishing configuration versions.
 * @tunnel_hlen: Tunnel header length.
 * @eth_addr: Source address for packets generated by tunnel itself
 * (e.g. ICMP fragmentation needed messages).
 * @out_key: Key to use on output, 0 if this tunnel has no fixed output key.
 * @flags: TNL_F_* flags.
 * @tos: IPv4 TOS value to use for tunnel, 0 if no fixed TOS.
 * @ttl: IPv4 TTL value to use for tunnel, 0 if no fixed TTL.
 */
struct tnl_mutable_config {
	struct port_lookup_key key;
	struct rcu_head rcu;

	unsigned seq;

	unsigned tunnel_hlen;

	unsigned char eth_addr[ETH_ALEN];

	/* Configured via OVS_TUNNEL_ATTR_* attributes. */
	__be64	out_key;
	u32	flags;
	u8	tos;
	u8	ttl;

	/* Multicast configuration. */
	int	mlink;

    /* VXLAN sepcific configuration */
    u32               vni;
    __be32            vtep;
    __be32            mcast_ip;
    u16               vtep_port;
    u16               mcast_port;
};

struct tnl_ops {
	u32 tunnel_type;	/* Put the TNL_T_PROTO_* type in here. */
	u8 ipproto;		/* The IP protocol for the tunnel. */

	/*
	 * Source and destination port for the tunnel.  This is necessary
	 * if the tunnel protocol is using TCP or UDP within IPsec.  The
	 * IPsec transformation is done as part of the route lookup, so
	 * setting the transport port must be done early.
	 */
	__be16 sport;
	__be16 dport;

	/*
	 * Returns the length of the tunnel header that will be added in
	 * build_header() (i.e. excludes the IP header).  Returns a negative
	 * error code if the configuration is invalid.
	 */
	int (*hdr_len)(const struct tnl_mutable_config *);

	/*
	 * Builds the static portion of the tunnel header, which is stored in
	 * the header cache.  In general the performance of this function is
	 * not too important as we try to only call it when building the cache
	 * so it is preferable to shift as much work as possible here.  However,
	 * in some circumstances caching is disabled and this function will be
	 * called for every packet, so try not to make it too slow.
	 */
	void (*build_header)(const struct vport *,
			     const struct tnl_mutable_config *, void *header);

	/*
	 * Updates the cached header of a packet to match the actual packet
	 * data.  Typical things that might need to be updated are length,
	 * checksum, etc.  The IP header will have already been updated and this
	 * is the final step before transmission.  Returns a linked list of
	 * completed SKBs (multiple packets may be generated in the event
	 * of fragmentation).
	 */
	struct sk_buff *(*update_header)(const struct vport *,
					 const struct tnl_mutable_config *,
					 struct dst_entry *, struct sk_buff *);
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
/*
 * On these kernels we have a fast mechanism to tell if the ARP cache for a
 * particular destination has changed.
 */
#define HAVE_HH_SEQ
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
/*
 * On these kernels we have a fast mechanism to tell if the routing table
 * has changed.
 */
#define HAVE_RT_GENID
#endif
#if !defined(HAVE_HH_SEQ) || !defined(HAVE_RT_GENID)
/* If we can't detect all system changes directly we need to use a timeout. */
#define NEED_CACHE_TIMEOUT
#endif
struct tnl_cache {
	struct rcu_head rcu;

	int len;		/* Length of data to be memcpy'd from cache. */
	int hh_len;		/* Hardware hdr length, cached from hh_cache. */

	/* Sequence number of mutable->seq from which this cache was
	 * generated. */
	unsigned mutable_seq;

#ifdef HAVE_HH_SEQ
	/*
	 * The sequence number from the seqlock protecting the hardware header
	 * cache (in the ARP cache).  Since every write increments the counter
	 * this gives us an easy way to tell if it has changed.
	 */
	unsigned hh_seq;
#endif

#ifdef NEED_CACHE_TIMEOUT
	/*
	 * If we don't have direct mechanisms to detect all important changes in
	 * the system fall back to an expiration time.  This expiration time
	 * can be relatively short since at high rates there will be millions of
	 * packets per second, so we'll still get plenty of benefit from the
	 * cache.  Note that if something changes we may blackhole packets
	 * until the expiration time (depending on what changed and the kernel
	 * version we may be able to detect the change sooner).  Expiration is
	 * expressed as a time in jiffies.
	 */
	unsigned long expiration;
#endif

	/*
	 * The routing table entry that is the result of looking up the tunnel
	 * endpoints.  It also contains a sequence number (called a generation
	 * ID) that can be compared to a global sequence to tell if the routing
	 * table has changed (and therefore there is a potential that this
	 * cached route has been invalidated).
	 */
	struct rtable *rt;

	/*
	 * If the output device for tunnel traffic is an OVS internal device,
	 * the flow of that datapath.  Since all tunnel traffic will have the
	 * same headers this allows us to cache the flow lookup.  NULL if the
	 * output device is not OVS or if there is no flow installed.
	 */
	struct sw_flow *flow;

	/* The cached header follows after padding for alignment. */
};

struct tnl_vport {
	struct rcu_head rcu;
	struct hlist_node hash_node;

	char name[IFNAMSIZ];
	const struct tnl_ops *tnl_ops;

	struct tnl_mutable_config __rcu *mutable;

	/*
	 * ID of last fragment sent (for tunnel protocols with direct support
	 * fragmentation).  If the protocol relies on IP fragmentation then
	 * this is not needed.
	 */
	atomic_t frag_id;

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

    struct socket __rcu *vxlan_rcv_socket;  /* VTEP receive socket */
    struct socket __rcu *vxlan_mcast_socket; /* MULTICAST socket */
    struct hlist_head __rcu *vxlan_mac_table;

};


static inline u32 port_hash(const struct port_lookup_key *key)
{
	return jhash2((u32 *)key, (PORT_KEY_LEN / sizeof(u32)), 0);
}

struct vport *ovs_tnl_create(const struct vport_parms *, const struct vport_ops *,
			     const struct tnl_ops *);
void ovs_tnl_destroy(struct vport *);

int ovs_tnl_set_options(struct vport *, struct nlattr *);
int ovs_tnl_get_options(const struct vport *, struct sk_buff *);

int ovs_tnl_set_addr(struct vport *vport, const unsigned char *addr);
const char *ovs_tnl_get_name(const struct vport *vport);
const unsigned char *ovs_tnl_get_addr(const struct vport *vport);
int ovs_tnl_send(struct vport *vport, struct sk_buff *skb);
void ovs_tnl_rcv(struct vport *vport, struct sk_buff *skb, u8 tos);

struct vport *ovs_tnl_find_port(struct net *net, __be32 saddr, __be32 daddr,
				__be64 key, int tunnel_type,
				const struct tnl_mutable_config **mutable);
bool ovs_tnl_frag_needed(struct vport *vport,
			 const struct tnl_mutable_config *mutable,
			 struct sk_buff *skb, unsigned int mtu, __be64 flow_key);
void ovs_tnl_free_linked_skbs(struct sk_buff *skb);

void ovs_tnl_port_table_add_port(struct vport *vport);
void ovs_tnl_port_table_move_port(struct vport *vport,
                            struct tnl_mutable_config *new_mutable);
void ovs_tnl_port_table_remove_port(struct vport *vport);
struct vport * ovs_tnl_port_table_lookup(struct port_lookup_key *key,
				       const struct tnl_mutable_config **pmutable);
void ovs_tnl_assign_config_rcu(struct vport *vport,
			      struct tnl_mutable_config *new_config);
void ovs_tnl_free_config_rcu(struct rcu_head *rcu);
void ovs_tnl_free_mutable_rtnl(struct tnl_mutable_config *mutable);
void ovs_tnl_port_table_dump (void);

int ovs_tnl_init(void);
void ovs_tnl_exit(void);

static inline struct tnl_vport *tnl_vport_priv(const struct vport *vport)
{
	return vport_priv(vport);
}

static inline struct 
vport *tnl_vport_to_vport(const struct tnl_vport *tnl_vport)
{
        return vport_from_priv(tnl_vport);
}

#endif /* tunnel.h */
