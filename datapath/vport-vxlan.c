 /*
 * Copyright (c) 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/xfrm.h>
#include <linux/igmp.h>                 /* for ip_mc_join_group */

#include <net/icmp.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/inet_connection_sock.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"
#include "vport-vxlan.h"

#define UDP_ENCAP_VXLAN (10)
#define VXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct vxlanhdr))
#define VXPORT_TABLE_SIZE  (1024)
#define VXLAN_MAC_TABLE_SIZE  (1024)


static struct vport *vxlan_create(const struct vport_parms *parms);
static void vxlan_destroy(struct vport *vport);
static int vxlan_set_addr(struct vport *vport, const u8 *addr);
static const char * vxlan_get_name(const struct vport *vport);
static const u8 * vxlan_get_addr(const struct vport *vport);
static int vxlan_set_options(struct vport *vport, struct nlattr *options);
static int vxlan_get_options(const struct vport *vport, struct sk_buff *skb);
static int vxlan_send(struct vport *vport, struct sk_buff *skb);
static int vxlan_rcv(struct sock *sk, struct sk_buff *skb);
static int vxlan_mcast_rcv(struct sock *sk, struct sk_buff *skb);
static void vxlan_mac_table_entry_learn (struct vxlan_vport *vxport, struct iphdr *iph, struct sk_buff *skb);

const struct vport_ops ovs_vxlan_vport_ops = {
	.type		      = OVS_VPORT_TYPE_VXLAN,
	.flags		      = VPORT_F_TUN_ID,
	.create		      = vxlan_create,
	.destroy	      = vxlan_destroy,
	.set_addr	      = vxlan_set_addr,
	.get_name	      = vxlan_get_name,
	.get_addr	      = vxlan_get_addr,
	.get_options	  = vxlan_get_options,
	.set_options	  = vxlan_set_options,
	.get_dev_flags	  = ovs_vport_gen_get_dev_flags,
	.is_running       = ovs_vport_gen_is_running,
	.get_operstate	  = ovs_vport_gen_get_operstate,
	.send             = vxlan_send,
};


static struct hlist_head *vxport_table __read_mostly;


static inline struct vxlan_vport *
vxlan_vport_priv (const struct vport *vport)
{
    return (struct vxlan_vport *)vport_priv(vport);
}

/* RCU callback to free mutable configuration */
static void
vxlan_rcu_mutble_free_cb(struct rcu_head *rcu)
{
	struct vxlan_mutable_config *c;

    c = container_of(rcu, struct vxlan_mutable_config, rcu);

	kfree(c);
}

static struct hlist_head *
vxlan_get_vxport_table_bucket (u32 vni)
{
    u32 hash;
    struct hlist_head *h;
        
    hash = jhash2(&vni, 1, 0);
    h = &vxport_table [(hash & (VXPORT_TABLE_SIZE - 1))];

    return h;
}

static int
vxlan_add_vxport (u32 vni, struct vxlan_vport *vxport)
{
    struct hlist_head *h;

    h = vxlan_get_vxport_table_bucket (vni);
    hlist_add_head_rcu (&vxport->hash_node, h);

    return 0;
}

static void
vxlan_del_vxport (struct vxlan_vport *vxport)
{
    hlist_del_init_rcu (&vxport->hash_node);
}


static void
vxlan_rcu_vme_free_cb(struct rcu_head *rcu)
{
	struct vxlan_mac_entry *vme;

    vme = container_of(rcu, struct vxlan_mac_entry, rcu);

	kfree(vme);
}

static int
vxlan_vme_add (struct vxlan_vport *vxport, __be32 peer_vtep, 
                u8 *macaddr, u32 flags)
{
    struct vxlan_mac_entry *vme;
    struct hlist_head      *bucket, *mac_table;
    u32                     hash;

    vme = kzalloc (sizeof (struct vxlan_mac_entry), GFP_KERNEL);
    if (vme == NULL)
        return -ENOMEM;

    vme->peer = peer_vtep;
    memcpy (vme->macaddr, macaddr, ETH_ALEN);
    vme->flags = flags;

    hash = jhash (macaddr, ETH_ALEN, 0);
    mac_table = rcu_dereference_rtnl(vxport->mac_table);
    bucket = &mac_table [(hash & (VXLAN_MAC_TABLE_SIZE - 1))];
    hlist_add_head_rcu (&vme->hash_node, bucket);

    return 0;
}

static __be32
vxlan_vme_get_peer_vtep (struct vxlan_vport *vxport, u8 *macaddr)
{
    struct vxlan_mac_entry *vme;
    struct hlist_head      *bucket, *mac_table;
    struct hlist_node      *node;
    u32                     hash;

    hash = jhash (macaddr, ETH_ALEN, 0);
    mac_table = rcu_dereference_rtnl(vxport->mac_table);
    bucket = &mac_table [(hash & (VXLAN_MAC_TABLE_SIZE - 1))];

	hlist_for_each_entry_rcu(vme, node, bucket, hash_node) {
        if (memcmp (vme->macaddr, macaddr, ETH_ALEN) == 0) {
            return vme->peer;
        }
    }

    return 0;
}


static struct vxlan_vport *
vxlan_get_vxport (u32 vni)
{
    struct hlist_node  *node;
    struct hlist_head  *bucket;
    struct vxlan_vport *vxport;

    bucket = vxlan_get_vxport_table_bucket (vni);

	hlist_for_each_entry_rcu(vxport, node, bucket, hash_node) {
		struct vxlan_mutable_config *mutable;

        /* This whole business of rcu_*_rtnl is sickening */
		mutable = rcu_dereference_rtnl(vxport->mutable);
        if (mutable->vni == vni) {
            return vxport;
        }
	}

    return NULL;
}

static int
vxlan_open_socket (__be32  addr, u16 port, struct socket **socket)
{
	struct sockaddr_in sin;
	struct ip_mreqn mreq;
    struct sock * sk;
	int err;

	err = sock_create(AF_INET, SOCK_DGRAM, 0, socket);
	if (err) {
        pr_warn ("Failed to create socket for: 0x%x:%d", addr, port);
        return err;
    }

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	sin.sin_port = htons(port);
	err = kernel_bind(*socket, (struct sockaddr *)&sin,
                      sizeof(struct sockaddr_in));
	if (err) {
        pr_warn ("Failed to bind socket for: 0x%x:%d", addr, port);
		goto error_sock;
    }

    sk = (*socket)->sk;
	udp_sk(sk)->encap_type = UDP_ENCAP_VXLAN;

    if (ipv4_is_multicast(addr) == false) {
        udp_sk(sk)->encap_rcv = vxlan_rcv;
        return 0;
    }
	udp_sk(sk)->encap_rcv = vxlan_mcast_rcv;

    return 0;

    /* Add to multicast group that we are interested in. */
	memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = addr;
    //mreq.imr_address.s_addr = addr;

	lock_sock(sk);
    err = ip_mc_join_group (sk, &mreq);
	release_sock(sk);

    if (err < 0) {
        pr_warn("Failed to set multicast socket option --> %d", err);
        goto error_sock;
    }

#if 0
    struct net_device *dev;
    struct rtable *rt;
    struct flowi4  fl;
    memset(&fl, 0, sizeof(fl));
    fl.daddr = addr;
    fl.saddr = 0;
    fl.flowi4_tos = 0;
    fl.flowi4_proto = IPPROTO_UDP;
    
    rt = ip_route_output_key(net, &fl);
    if (IS_ERR (rt)) {
        pr_warn (" --> Route error. rt=%p", rt);
        return -1;
    }
    
    dev = ovs_rt_dst(rt).dev;
    ip_rt_put(rt);
    if (__in_dev_get_rtnl(dev) == NULL)
        return -EADDRNOTAVAIL;
    ip_mc_inc_group(__in_dev_get_rtnl(dev), daddr);
#endif
    
    return 0;

 error_sock:
	sock_release(*socket);
    *socket = NULL;
    return err;
}


static void
vxlan_close_socket (struct socket *socket)
{
    if (socket == NULL)
        return;
    
    sock_release (socket);
}

static struct vport *
vxlan_create(const struct vport_parms *parms)
{
	struct vport                   *vport;
	struct vxlan_vport             *vxport;
	struct vxlan_mutable_config    *mutable;
    struct hlist_head              *mac_table;
	int                            initial_frag_id, err, i;

	vport = ovs_vport_alloc(sizeof(struct vxlan_vport),
                            &ovs_vxlan_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	mac_table = kmalloc(VXLAN_MAC_TABLE_SIZE * sizeof(struct hlist_head*),
            GFP_KERNEL);
	if (mac_table == NULL) {
		err = -ENOMEM;
		goto error_free_vport;
    }

	for (i = 0; i < VXLAN_MAC_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&mac_table[i]);

	vxport = vxlan_vport_priv(vport);
	strcpy(vxport->name, parms->name);
	mutable = kzalloc(sizeof(struct vxlan_mutable_config), GFP_KERNEL);
	if (!mutable) {
		err = -ENOMEM;
		goto error_free_mac_table;
	}
	random_ether_addr(mutable->eth_addr);
	rcu_assign_pointer(vxport->mutable, mutable);

	get_random_bytes(&initial_frag_id, sizeof(int));
	//atomic_set(&vxport->frag_id, initial_frag_id);
    vxport->net = ovs_dp_get_net(parms->dp);

    err = vxlan_set_options (vport, parms->options);
	if (err)
		goto error_free_mutable;

    rcu_assign_pointer (vxport->mac_table, mac_table);

	spin_lock_init(&vxport->cache_lock);

#ifdef NEED_CACHE_TIMEOUT
	vxport->cache_exp_interval = MAX_CACHE_EXP -
				       (net_random() % (MAX_CACHE_EXP / 2));
#endif

	return vport;

error_free_mutable:
	kfree(mutable);
error_free_mac_table:
    kfree (mac_table);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static void
vxlan_destroy(struct vport *vport)
{
	struct vxlan_vport            *vxport;
    struct socket                 *rcv_socket, *mcast_socket;
    struct vxlan_mutable_config   *mutable;
    struct hlist_head             *mac_table;
    struct vxlan_mac_entry        *vme;
    struct hlist_node             *node;
    struct hlist_head             *bucket;
    int                            i;

	vxport = vxlan_vport_priv(vport);
    rcv_socket = rtnl_dereference(vxport->rcv_socket);
    vxlan_close_socket (rcv_socket);
    mcast_socket = rtnl_dereference(vxport->mcast_socket);
    vxlan_close_socket (mcast_socket);

    mutable = rtnl_dereference(vxport->mutable);
	call_rcu(&mutable->rcu, vxlan_rcu_mutble_free_cb);

    mac_table = rtnl_dereference(vxport->mac_table);
    for (i = 0; i < VXLAN_MAC_TABLE_SIZE; i++) {
        bucket = &mac_table [i];
        hlist_for_each_entry_rcu(vme, node, bucket, hash_node) {
            hlist_del_init_rcu (&vme->hash_node);
            call_rcu(&vme->rcu, vxlan_rcu_vme_free_cb);
        }
    }

    vxlan_del_vxport (vxport);
}

static int
vxlan_set_addr(struct vport *vport, const u8 *addr)
{
    return 0;
}

static const char *
vxlan_get_name(const struct vport *vport)
{
	const struct vxlan_vport *vxlan_vport = vxlan_vport_priv(vport);

	return vxlan_vport->name;
}

static const u8 *
vxlan_get_addr(const struct vport *vport)
{
	const struct vxlan_vport *vxport = vxlan_vport_priv(vport);

	return rcu_dereference_rtnl(vxport->mutable)->eth_addr;
}


static const struct nla_policy vxlan_nl_policy[OVS_TUNNEL_ATTR_MAX + 1] = {
	[OVS_TUNNEL_ATTR_FLAGS]        = { .type = NLA_U32 },
	[OVS_TUNNEL_ATTR_TOS]          = { .type = NLA_U8 },
	[OVS_TUNNEL_ATTR_TTL]          = { .type = NLA_U8 },

	[OVS_TUNNEL_ATTR_SRC_IPV4]     = { .type = NLA_U32 },
	[OVS_TUNNEL_ATTR_VTEP_PORT]    = { .type = NLA_U16 },
    [OVS_TUNNEL_ATTR_IN_KEY]       = { .type = NLA_U64 },
    [OVS_TUNNEL_ATTR_OUT_KEY]      = { .type = NLA_U64 },
    [OVS_TUNNEL_ATTR_DST_IPV4]     = { .type = NLA_U32 },
    [OVS_TUNNEL_ATTR_MCAST_PORT]   = { .type = NLA_U16 },
};

static int
vxlan_parse_options (struct vxlan_mutable_config *mutable,
                     struct nlattr *options)
{
	struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1];
	int err;
    __be64  vni;

	if (!options)
		return -EINVAL;

	err = nla_parse_nested(a, OVS_TUNNEL_ATTR_MAX, options, vxlan_nl_policy);
	if (err) {
        pr_warn("%s:%d", __FILE__, __LINE__);
		return err;
    }

	if (!a[OVS_TUNNEL_ATTR_FLAGS] ||
        !a[OVS_TUNNEL_ATTR_SRC_IPV4] ||
        !a[OVS_TUNNEL_ATTR_IN_KEY] ||
        !a[OVS_TUNNEL_ATTR_DST_IPV4]) {
        pr_warn("%s:%d", __FILE__, __LINE__);
		return -EINVAL;
    }

	mutable->flags = nla_get_u32(a[OVS_TUNNEL_ATTR_FLAGS]) & TNL_F_PUBLIC;
	mutable->vtep = nla_get_be32(a[OVS_TUNNEL_ATTR_SRC_IPV4]);
	mutable->mcast_ip = nla_get_be32(a[OVS_TUNNEL_ATTR_DST_IPV4]);
	vni = nla_get_be64(a[OVS_TUNNEL_ATTR_IN_KEY]);
	mutable->vni = (u32)(be64_to_cpu(vni) >> 40);

	if (a[OVS_TUNNEL_ATTR_TOS]) {
		mutable->tos = nla_get_u8(a[OVS_TUNNEL_ATTR_TOS]);
		/* Reject ToS config with ECN bits set. */
		if (mutable->tos & INET_ECN_MASK) {
            pr_warn("%s:%d", __FILE__, __LINE__);
			return -EINVAL;
        }
	}

	if (a[OVS_TUNNEL_ATTR_TTL])
		mutable->ttl = nla_get_u8(a[OVS_TUNNEL_ATTR_TTL]);

    if (a[OVS_TUNNEL_ATTR_VTEP_PORT])
        mutable->vtep_port = nla_get_u16(a[OVS_TUNNEL_ATTR_VTEP_PORT]);
    else
        mutable->vtep_port = VXLAN_UDP_PORT;

    if (a[OVS_TUNNEL_ATTR_MCAST_PORT])
        mutable->mcast_port = nla_get_u16(a[OVS_TUNNEL_ATTR_MCAST_PORT]);
    else
        mutable->mcast_port = VXLAN_MCAST_PORT;
        
	return 0;
}

static int
vxlan_set_options(struct vport *vport, struct nlattr *options)
{
	struct vxlan_vport                   *vxport;
	struct vxlan_mutable_config          *old_mutable;
	struct vxlan_mutable_config          *mutable;
	int                                   err;
    struct socket                        *rcv_socket, *old_rcv_socket;
    struct socket                        *mcast_socket, *old_mcast_socket;

    rcv_socket = old_rcv_socket = old_mcast_socket = NULL;
    
    vxport = vxlan_vport_priv(vport);
	mutable = kzalloc(sizeof(struct vxlan_mutable_config), GFP_KERNEL);
	if (!mutable) {
		err = -ENOMEM;
		goto error;
	}

	/* Copy fields whose values should be retained. */
	old_mutable = rtnl_dereference(vxport->mutable);
	mutable->seq = old_mutable->seq + 1;
	memcpy(mutable->eth_addr, old_mutable->eth_addr, ETH_ALEN);

    err = vxlan_parse_options (mutable, options);
    if (err != 0) {
        pr_warn ("%s:%d", __FILE__, __LINE__);
        goto error_free;
    }
    
    pr_warn ("VNI: %d, VTEP: 0x%x:%d, MCAST: 0x%x:%d",
             mutable->vni, mutable->vtep, mutable->vtep_port,
             mutable->mcast_ip, mutable->mcast_port);
    
    if ((mutable->vtep != old_mutable->vtep) ||
        (mutable->vtep_port != old_mutable->vtep_port)) {
        err = vxlan_open_socket (mutable->vtep, mutable->vtep_port,
                                   &rcv_socket);
        if (err != 0) {
            pr_warn ("%s:%d", __FILE__, __LINE__);
            goto error_free;
        }

        old_rcv_socket = rtnl_dereference(vxport->rcv_socket);
        rcu_assign_pointer(vxport->rcv_socket, rcv_socket);
        vxlan_close_socket (old_rcv_socket);
    }

    if ((mutable->mcast_ip != old_mutable->mcast_ip) ||
        (mutable->mcast_port != old_mutable->mcast_port)) {
        err = vxlan_open_socket (mutable->mcast_ip, mutable->mcast_port,
                                   &mcast_socket);
        if (err != 0) {
            pr_warn ("%s:%d", __FILE__, __LINE__);
            goto sock_free;
        }

        old_mcast_socket = rtnl_dereference(vxport->mcast_socket);
        rcu_assign_pointer(vxport->mcast_socket, mcast_socket);
        vxlan_close_socket(old_mcast_socket);
    }

	rcu_assign_pointer(vxport->mutable, mutable);
	call_rcu(&old_mutable->rcu, vxlan_rcu_mutble_free_cb);

    vxlan_add_vxport (mutable->vni, vxport);
    
    pr_warn ("VNI: %d, VTEP: 0x%x:%d, MCAST: 0x%x:%d",
             mutable->vni, mutable->vtep, mutable->vtep_port,
             mutable->mcast_ip, mutable->mcast_port);


	return 0;
    
 sock_free:
    vxlan_close_socket (rcv_socket);
 error_free:
	kfree(mutable);
 error:
	return err;
}

static int
vxlan_get_options(const struct vport *vport, struct sk_buff *skb)
{
	const struct vxlan_vport *vxlan_vport;
	const struct vxlan_mutable_config *mutable;


    vxlan_vport = vxlan_vport_priv(vport);
    mutable = rcu_dereference_rtnl(vxlan_vport->mutable);

	if (nla_put_u32(skb, OVS_TUNNEL_ATTR_FLAGS, mutable->flags & TNL_F_PUBLIC))
		goto nla_put_failure;

	if (mutable->tos && nla_put_u8(skb, OVS_TUNNEL_ATTR_TOS, mutable->tos))
		goto nla_put_failure;

	if (mutable->ttl && nla_put_u8(skb, OVS_TUNNEL_ATTR_TTL, mutable->ttl))
		goto nla_put_failure;

	if (nla_put_be32(skb, OVS_TUNNEL_ATTR_SRC_IPV4, mutable->vtep))
		goto nla_put_failure;

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_VTEP_PORT, mutable->vtep_port))
		goto nla_put_failure;

	if (nla_put_be64(skb, OVS_TUNNEL_ATTR_IN_KEY, cpu_to_be64(mutable->vni)))
		goto nla_put_failure;

	if (nla_put_be64(skb, OVS_TUNNEL_ATTR_OUT_KEY, cpu_to_be64(mutable->vni)))
		goto nla_put_failure;

	if (nla_put_be32(skb, OVS_TUNNEL_ATTR_DST_IPV4, mutable->mcast_ip))
        goto nla_put_failure;

    if (nla_put_u16(skb, OVS_TUNNEL_ATTR_MCAST_PORT, mutable->mcast_port))
        goto nla_put_failure;

	return 0;

nla_put_failure:
    pr_warn ("Error vxlan_get_options");
	return -EMSGSIZE;
}


/* -- Traffic handling -- */

static inline struct
vxlanhdr *vxlan_hdr(const struct sk_buff *skb)
{
	return (struct vxlanhdr *)(udp_hdr(skb) + 1);
}

#if 0
static inline void
vxlan_tunnel_build_header(void *header, __be64 tun_id)
{
	struct udphdr *udph = header;
	struct vxlanhdr *vxh = (struct vxlanhdr *)(udph + 1);

	udph->dest = htons(VXLAN_DST_PORT);
	udph->check = 0;

	vxh->vx_flags = htonl(VXLAN_FLAGS);
	vxh->vx_vni = htonl(be64_to_cpu(tun_id) << 8);
}
#endif



static void
vxlan_mac_table_entry_learn (struct vxlan_vport *vxport, struct iphdr *iph, 
        struct sk_buff *skb)
{
	struct ethhdr *eh;
    struct vxlan_mutable_config *mutable;
        
    mutable = rcu_dereference_rtnl(vxport->mutable);
	skb_reset_mac_header(skb);
	eh = eth_hdr(skb);
    vxlan_vme_add (vxport, iph->saddr, eh->h_source, 
                      VXLAN_MAC_ENTRY_FLAGS_LEARNED);
}

static int
vxlan_send(struct vport *vport, struct sk_buff *skb)
{
    return -1;
}

/* Called with rcu_read_lock and BH disabled. */
static int
vxlan_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct vport *vport;
	struct vxlan_vport *vxport;
	struct vxlanhdr *vxh;
	//const struct vxlan_mutable_config *mutable;
	struct iphdr *iph;
	int tunnel_type;
	__be64 key;
    u32    vni;

	if (unlikely(!pskb_may_pull(skb, VXLAN_HLEN + ETH_HLEN)))
		goto error;

	vxh = vxlan_hdr(skb);
	if (unlikely(vxh->vx_flags != htonl(VXLAN_FLAGS) ||
		     vxh->vx_vni & htonl(0xff)))
		goto error;

	__skb_pull(skb, VXLAN_HLEN);

    vni = ntohl(vxh->vx_vni) & 0x00FFFFFF;
	key = cpu_to_be64(vni);

	tunnel_type = TNL_T_PROTO_VXLAN;

    /* - XXX
	if (sec_path_esp(skb))
		tunnel_type |= TNL_T_IPSEC; */

	iph = ip_hdr(skb);
    vxport = vxlan_get_vxport (vni);
	if (unlikely(vxport == NULL)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		goto error;
	}
	skb_postpull_rcsum(skb, skb_transport_header(skb), VXLAN_HLEN + ETH_HLEN);

	/* Save outer tunnel values */
	OVS_CB(skb)->tun_ipv4_src = iph->saddr;
	OVS_CB(skb)->tun_ipv4_dst = iph->daddr;
	OVS_CB(skb)->tun_ipv4_tos = iph->tos;
	OVS_CB(skb)->tun_ipv4_ttl = iph->ttl;
    OVS_CB(skb)->tun_id = key;

    vxlan_mac_table_entry_learn (vxport, iph, skb);
    vport = vport_from_priv(vxport);
	ovs_tnl_rcv(vport, skb, iph->tos);

    return 0;

error:
	kfree_skb(skb);

	return 0;
}

/* Called with rcu_read_lock and BH disabled. */
static int
vxlan_mcast_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct iphdr    *iph;
    struct udphdr   *udp;
    static int       count;
    __be32           saddr;

    saddr = inet_sk(sk)->inet_rcv_saddr;
    udp = udp_hdr(skb);
	iph = ip_hdr(skb);

    if (iph->saddr == saddr) {
        /* This packet is sent by us. Discard */
        kfree_skb(skb);
        return 0;
    }
    count++;

    pr_warn ("--> udplen=%d, skblen=%d, headroom=%d, skbdatalen=%d, "
             "transporoffset=%d, networkoffset=%d",
             ntohs(udp->len),
             skb->len,
             skb_headroom(skb),
             skb->data_len,
             skb_transport_offset(skb),
             skb_network_offset(skb)
             );

    //ovs_vxlan_udp_send_skb (sk, skb);

	kfree_skb(skb);

	return 0;
}


void
ovs_vxlan_exit () 
{ 
    if (vxport_table)
        kfree (vxport_table);
}

int
ovs_vxlan_init()
{
    int i;

	vxport_table = kmalloc(VXPORT_TABLE_SIZE * sizeof(struct hlist_head *),
            GFP_KERNEL);
	if (vxport_table == NULL)
		return -ENOMEM;

	for (i = 0; i < VXPORT_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&vxport_table[i]);


	return 0;
}

#else
#warning VXLAN tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
