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
#include <linux/in_route.h>
#include <linux/inetdevice.h>
#include <linux/jiffies.h>
#include <linux/time.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/inet_connection_sock.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"
#include "vport-vxlan.h"

#define UDP_ENCAP_VXLAN                       (10)
#define VXPORT_TABLE_SIZE                     (1024)
#define VXLAN_MAC_TABLE_SIZE                  (1024)
#define VXLAN_MAC_TABLE_AGEOUT_INTERVAL       (5 * HZ)
#define VXLAN_MAC_TABLE_AGEOUT_STAGGER_COUNT  (5) /* XXX - Explain */
#define VXLAN_UPPER_STAGGER_COUNT             (100)

#ifdef OVS_VXLAN_DEBUG_ENABLE
#define OVS_VXLAN_DEBUG(fmt, arg...) printk(KERN_WARNING fmt, ##arg)
#else
#define OVS_VXLAN_DEBUG(fmt, arg...) (void)0
#endif

#ifdef OVS_VXLAN_VME_DEBUG_ENABLE
#define OVS_VXLAN_VME_DEBUG(fmt, arg...) printk(KERN_WARNING fmt, ##arg)
#else
#define OVS_VXLAN_VME_DEBUG(fmt, arg...) (void)0
#endif


struct vxlan_mac_hlr_table {
    struct hlist_head   hash_table;
    struct list_head    lru_list;
    spinlock_t          lock;
};

static struct vport *vxlan_create(const struct vport_parms *parms);
static void vxlan_destroy(struct vport *vport);
static int vxlan_set_options(struct vport *vport, struct nlattr *options);
static int vxlan_get_options(const struct vport *vport, struct sk_buff *skb);
static int vxlan_send(struct vport *vport, struct sk_buff *skb);
static int vxlan_rcv(struct sock *sk, struct sk_buff *skb);
static int vxlan_mcast_rcv(struct sock *sk, struct sk_buff *skb);
static struct vxlan_mac_entry *vxlan_vme_get_peer_vtep (u32 vni, u8 *macaddr, __be32 peer_vtep, u32 age);
static struct sk_buff * vxlan_update_header(const struct vport *vport,
                    const struct tnl_mutable_config *mutable,
					struct dst_entry *dst, struct sk_buff *skb);
static void vxlan_build_header(const struct vport *vport, 
                   const struct tnl_mutable_config *mutable, void *header);
static int vxlan_set_config (struct vport *vport, struct nlattr *options, 
        struct tnl_mutable_config  *mutable,
        struct tnl_mutable_config  *old_mutable);
static void vxlan_mac_table_cleaner(struct work_struct *work);

const struct vport_ops ovs_vxlan_vport_ops = {
	.type		      = OVS_VPORT_TYPE_VXLAN,
	.flags		      = VPORT_F_TUN_ID,
	.create		      = vxlan_create,
	.destroy	      = vxlan_destroy,
	.set_addr	      = ovs_tnl_set_addr,
	.get_name	      = ovs_tnl_get_name,
	.get_addr	      = ovs_tnl_get_addr,
	.get_options	  = vxlan_get_options,
	.set_options	  = vxlan_set_options,
	.get_dev_flags	  = ovs_vport_gen_get_dev_flags,
	.is_running       = ovs_vport_gen_is_running,
	.get_operstate	  = ovs_vport_gen_get_operstate,
	.send             = vxlan_send,
};

static const struct tnl_ops ovs_vxlan_tnl_ops = {
        .tunnel_type    = TNL_T_PROTO_VXLAN,
        .ipproto        = IPPROTO_UDP,
        .dport          = htons(VXLAN_UDP_PORT),
        .hdr_len        = vxlan_hdr_len,
        .build_header   = vxlan_build_header,
        .update_header  = vxlan_update_header,
};

static const struct tnl_ops ovs_ipsec_vxlan_tnl_ops = {
        .tunnel_type    = TNL_T_PROTO_VXLAN | TNL_T_IPSEC,
        .ipproto        = IPPROTO_UDP,
        .sport          = htons(VXLAN_IPSEC_SRC_PORT),
        .dport          = htons(VXLAN_UDP_PORT),
        .hdr_len        = vxlan_hdr_len,
        .build_header   = vxlan_build_header,
        .update_header  = vxlan_update_header,
};


static DECLARE_DELAYED_WORK(vxlan_mac_table_ageout_wq, vxlan_mac_table_cleaner);
static int vxlan_vport_count = 0;
static int vxlan_cleaner_start_index = 0;
static struct vxlan_mac_hlr_table *vxlan_mac_table;
static LIST_HEAD(vxlan_socket_list);
static spinlock_t vxlan_socket_lock;

static void
vxlan_rcu_vme_free_cb(struct rcu_head *rcu)
{
	struct vxlan_mac_entry *vme;

    vme = container_of(rcu, struct vxlan_mac_entry, rcu);

	kfree(vme);
}

static inline int
vxlan_vme_add (u32 vni, __be32 peer_vtep, u8 *macaddr, u32 flags, u32 age)
{
    struct vxlan_mac_entry       *vme;
    struct vxlan_mac_hlr_table   *hh;
    u32                           hash;

    vme = kzalloc (sizeof (struct vxlan_mac_entry), GFP_ATOMIC);
    if (!vme)
        return -ENOMEM;

    vme->peer = peer_vtep;
    vme->vni = vni;
    memcpy (vme->macaddr, macaddr, ETH_ALEN);
    vme->flags = flags;
    vme->age = msecs_to_jiffies(age) + jiffies;

    hash = jhash (macaddr, ETH_ALEN, 0);

    hh = &vxlan_mac_table [(hash & (VXLAN_MAC_TABLE_SIZE - 1))];

    spin_lock (&hh->lock);

    hlist_add_head_rcu (&vme->hash_node, &hh->hash_table);

    if (flags & VXLAN_MAC_ENTRY_FLAGS_LEARNED) {
        list_add_tail_rcu(&vme->lru_link, &hh->lru_list);
    }

    spin_unlock (&hh->lock);

    OVS_VXLAN_VME_DEBUG("NEW VME. vni: %d, saddr: 0x%x, "
            "mac:%x:%x:%x:%x:%x:%x, flags: 0x%x",
            vni, vme->peer, 
            vme->macaddr[0], vme->macaddr[1], vme->macaddr[2], 
            vme->macaddr[3], vme->macaddr[4], vme->macaddr[5], 
            vme->flags);

    return 0;
}

static void
vxlan_vme_delete (struct vxlan_mac_entry *vme, bool rcu_free)
{
    OVS_VXLAN_VME_DEBUG("DELETING VME. vni: %d, saddr: 0x%x, "
            "mac:%x:%x:%x:%x:%x:%x, flags: 0x%x",
            vme->vni, vme->peer, 
            vme->macaddr[0], vme->macaddr[1], vme->macaddr[2], 
            vme->macaddr[3], vme->macaddr[4], vme->macaddr[5], 
            vme->flags);


    if (vme->flags & VXLAN_MAC_ENTRY_FLAGS_LEARNED) {
        list_del_rcu(&vme->lru_link);
    }

    hlist_del_init_rcu (&vme->hash_node);

    if (rcu_free == true)
        call_rcu(&vme->rcu, vxlan_rcu_vme_free_cb);
    else
        kfree (vme);
}

static struct vxlan_mac_entry *
vxlan_vme_get_peer_vtep (u32 vni, u8 *macaddr, __be32 peer_vtep, u32 age)
{
    struct vxlan_mac_entry         *vme;
    struct vxlan_mac_hlr_table     *hh;
    struct hlist_node              *node;
    u32                             hash;

    hash = jhash (macaddr, ETH_ALEN, 0);
    hh = &vxlan_mac_table [(hash & (VXLAN_MAC_TABLE_SIZE - 1))];

	hlist_for_each_entry_rcu(vme, node, &hh->hash_table, hash_node) {
        if ((vme->vni == vni) && 
            (memcmp (vme->macaddr, macaddr, ETH_ALEN) == 0)) {

            if (vme->flags & VXLAN_MAC_ENTRY_FLAGS_LEARNED) {

                spin_lock (&hh->lock);
                vme->age = msecs_to_jiffies(vme->age) + jiffies;
                vme->peer = (peer_vtep != 0) ? peer_vtep : vme->peer;
                list_del_rcu(&vme->lru_link);
                list_add_tail_rcu(&vme->lru_link, &hh->lru_list);
                spin_unlock (&hh->lock);

            }

            OVS_VXLAN_VME_DEBUG("VME FOUND. vni: %d, saddr: 0x%x, "
                    "mac:%x:%x:%x:%x:%x:%x, flags: 0x%x",
                    vme->vni, vme->peer, 
                    vme->macaddr[0], vme->macaddr[1], vme->macaddr[2], 
                    vme->macaddr[3], vme->macaddr[4], vme->macaddr[5], 
                    vme->flags);

            return vme;
        }
    }

    OVS_VXLAN_VME_DEBUG("VME NOT FOUND. vni: %d, saddr: 0x%x, "
            "mac:%x:%x:%x:%x:%x:%x",
            vni, peer_vtep, 
            macaddr[0], macaddr[1], macaddr[2], 
            macaddr[3], macaddr[4], macaddr[5]);

    return NULL;
}

#define VXLAN_VME_UT (1)
#ifdef VXLAN_VME_UT
static void
vxlan_vme_ut_add_entries (int count)
{
    __be32 saddr;
    u32    vni;
    u8     eth_addr [ETH_ALEN];
    int    i;

    for (i = 0; i < count; i++) {
        get_random_bytes (&saddr, 4);
        get_random_bytes (&vni, 3);
        vni = vni & 0x00FFFFFF;
	    random_ether_addr(eth_addr);

        if (vxlan_vme_get_peer_vtep(vni, eth_addr, 0, 1000) == NULL) {
            vxlan_vme_add (vni, saddr, eth_addr, 
                    VXLAN_MAC_ENTRY_FLAGS_LEARNED, 1000);
        }
    }
    pr_warn ("UT: Added %d entries", count);
}
#endif

static void 
vxlan_mac_table_cleaner(struct work_struct *work)
{
    int                          i, j, k, deleted = 0;
    struct vxlan_mac_entry      *vme;
    struct vxlan_mac_hlr_table  *hh;

    rcu_read_lock ();

    for (k = 0, i = vxlan_cleaner_start_index; 
            (i < VXLAN_MAC_TABLE_SIZE) && (k < VXLAN_UPPER_STAGGER_COUNT);
            i++, k++) {

        hh = &vxlan_mac_table [i];

        for (j = 0; (j < VXLAN_MAC_TABLE_AGEOUT_STAGGER_COUNT) && 
                (!list_empty(&hh->lru_list)); j++) {
            vme = list_first_entry(&hh->lru_list, struct vxlan_mac_entry, 
                    lru_link);
            if (jiffies >= vme->age) {
                if (spin_trylock (&hh->lock)) {
                    vxlan_vme_delete (vme, true);
                    deleted++;
                    spin_unlock (&hh->lock);
                }
                else {
                    OVS_VXLAN_VME_DEBUG("Failed to get spin lock");
                    continue;
                }
            }
            else {
                /*
                 * If the first entry is not old, then it is guaranteed 
                 * that next won't be old. This is because we always move 
                 * last accessed entry to the tail.
                 */
                OVS_VXLAN_VME_DEBUG("%d: VALID: jiffies=%lu, vme->age: %lu",
                        j, jiffies, vme->age);
                break;
            }
        }

    }

    rcu_read_unlock ();

#ifdef VXLAN_VME_UT
    if (deleted != 0)
        pr_warn ("Deleted: %d entries", deleted);

    vxlan_vme_ut_add_entries (100);
#endif
    
    vxlan_cleaner_start_index = (i == VXLAN_MAC_TABLE_SIZE) ? 0 : i;

    OVS_VXLAN_VME_DEBUG("global cleaner index: %d, i: %d", 
            vxlan_cleaner_start_index, i);

    schedule_delayed_work(&vxlan_mac_table_ageout_wq,
            VXLAN_MAC_TABLE_AGEOUT_INTERVAL);
}


static int
__vxlan_open_tnl_socket (struct tnl_mutable_config *mutable, __be32 addr, 
                       u16 port, struct tnl_socket **retnl_socket, int *mlink)
{
    struct net_device *dev;
    struct tnl_socket *tnl_socket;
    struct rtable *rt;
    struct sockaddr_in sin;
    struct sock * sk;
    struct socket *socket;
    int err;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	struct flowi fl;
#else
    struct flowi4 fl;
#endif

    OVS_VXLAN_DEBUG("Trying to Create a socket: 0x%x:%d", addr, port);

	list_for_each_entry_rcu(tnl_socket, &vxlan_socket_list, node) {
        socket = tnl_socket->socket;
        if ((inet_sk(socket->sk)->inet_rcv_saddr == addr) &&
                (inet_sk(socket->sk)->inet_sport == htons(port))) {
            OVS_VXLAN_DEBUG("Found existing socket: 0x%x:%d", addr, port);
            atomic_inc (&tnl_socket->refcount);
            *retnl_socket = tnl_socket;
            return 0;
        }
    }

    tnl_socket = kzalloc (sizeof (struct tnl_socket), GFP_KERNEL);
    if (tnl_socket == NULL) {
        return -ENOMEM;
    }

	err = sock_create(AF_INET, SOCK_DGRAM, 0, &socket);
	if (err) {
        pr_warn ("vxlan: Failed to create socket for: 0x%x:%d", addr, port);
        return err;
    }

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	sin.sin_port = htons(port);
	err = kernel_bind(socket, (struct sockaddr *)&sin,
                      sizeof(struct sockaddr_in));
	if (err) {
        pr_warn ("vxlan: Failed to bind socket for: 0x%x:%d, err=%d", 
                addr, port, err);
		goto error;
    }

    sk = (socket)->sk;
	udp_sk(sk)->encap_type = UDP_ENCAP_VXLAN;

    if (ipv4_is_multicast(addr) == false) {
        udp_sk(sk)->encap_rcv = vxlan_rcv;
    }
    else {
        memset(&fl, 0, sizeof(fl));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
        fl.nl_u.ip4_vdaddr = addr;
        fl.nl_u.ip4_vsaddr = mutable->vtep;
        fl.proto = IPPROTO_UDP;
        rt = ip_route_output_key(sock_net(sk), &rt, &fl);
#else
        fl.daddr = addr;
        fl.saddr = mutable->vtep;
        fl.flowi4_proto = IPPROTO_UDP;
        rt = ip_route_output_key(sock_net(sk), &fl);
#endif

        if (IS_ERR (rt)) {
            pr_warn ("vxlan: Multicast Route error. SRC=0x%x, DST=0x%x, rt=%p", 
                    mutable->vtep, addr, rt);
            err = -EHOSTUNREACH;
            goto error;
        }

        dev = rt_dst(rt).dev;
        ip_rt_put(rt);
        if (__in_dev_get_rtnl(dev) == NULL) {
            err = -EADDRNOTAVAIL;
            goto error;
        }

        udp_sk(sk)->encap_rcv = vxlan_mcast_rcv;
        *mlink = dev->ifindex;
        ip_mc_inc_group(__in_dev_get_rtnl(dev), addr);
    }

    list_add_tail_rcu(&tnl_socket->node, &vxlan_socket_list);
    atomic_set (&tnl_socket->refcount, 1);
    tnl_socket->socket = socket;
    *retnl_socket = tnl_socket;

    OVS_VXLAN_DEBUG("Created new %s socket: 0x%x:%d", 
            ((ipv4_is_multicast(addr) == false) ?  " " : "MULTICAST"),
            addr, port);

    return 0;

 error:
	sock_release(socket);
    kfree (tnl_socket);
    *retnl_socket = NULL;

    return err;
}

static int
vxlan_open_tnl_socket (struct tnl_mutable_config *mutable, __be32 addr, 
                       u16 port, struct tnl_socket **retnl_socket, int *mlink)
{
    int err;

    //spin_lock(&vxlan_socket_lock);
    err = __vxlan_open_tnl_socket (mutable, addr, port, retnl_socket, mlink);
    //spin_unlock(&vxlan_socket_lock);

    return err;
}


static void
vxlan_tnl_socket_free_cb(struct rcu_head *rcu)
{
	struct tnl_socket *tnl_socket;

    tnl_socket = container_of(rcu, struct tnl_socket, rcu);

	kfree(tnl_socket);
}

static void
__vxlan_release_tnl_socket (struct tnl_mutable_config *mutable, 
        struct tnl_socket *tnl_socket)
{
    __be32 saddr;
    struct socket *socket;

    if (tnl_socket == NULL)
        return;

    socket = tnl_socket->socket;
    saddr = inet_sk(socket->sk)->inet_rcv_saddr;

    OVS_VXLAN_DEBUG("Refcount: %d, 0x%x:%d", tnl_socket->refcount.counter,
            saddr, ntohs(inet_sk(socket->sk)->inet_sport));

    if (atomic_dec_and_test(&tnl_socket->refcount)) {
        OVS_VXLAN_DEBUG("Released SOCKET(refc=%d), 0x%x:%d", 
                tnl_socket->refcount.counter, saddr, 
                ntohs(inet_sk(socket->sk)->inet_sport));

        if ((ipv4_is_multicast(saddr) == true) && (mutable->mlink)) {
            struct in_device *in_dev;
            in_dev = inetdev_by_index(port_key_get_net(&mutable->key), 
                                     mutable->mlink);
            if (in_dev)
                ip_mc_dec_group(in_dev, mutable->key.daddr);
        }
        sock_release (tnl_socket->socket);
        list_del_rcu(&tnl_socket->node);
        call_rcu(&tnl_socket->rcu, vxlan_tnl_socket_free_cb);
    }
}

static void
vxlan_release_tnl_socket (struct tnl_mutable_config *mutable, 
        struct tnl_socket *tnl_socket)
{
    //spin_lock(&vxlan_socket_lock);
    __vxlan_release_tnl_socket (mutable, tnl_socket);
    //spin_unlock(&vxlan_socket_lock);
}

static struct vport *
vxlan_create(const struct vport_parms *parms)
{
	struct vport                   *vport;
	struct tnl_vport               *vxport;
	struct tnl_mutable_config      *mutable, *old_mutable;
	int                             initial_frag_id, err;

    mutable = old_mutable = NULL;
	vport = ovs_vport_alloc(sizeof(struct tnl_vport),
                            &ovs_vxlan_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	vxport = tnl_vport_priv(vport);
	strcpy(vxport->name, parms->name);

	mutable = kzalloc(sizeof(struct tnl_mutable_config), GFP_KERNEL);
	old_mutable = kzalloc(sizeof(struct tnl_mutable_config), GFP_KERNEL);
	if (!mutable || !old_mutable) {
		err = -ENOMEM;
        if (mutable) kfree (mutable);
        if (old_mutable) kfree (old_mutable);
		goto error_free_vport;
	}

	random_ether_addr(old_mutable->eth_addr);
	get_random_bytes(&initial_frag_id, sizeof(int));
    atomic_set(&vxport->frag_id, initial_frag_id);

    if (vxlan_set_config (vport, parms->options, mutable, old_mutable) != 0) {
		goto error_free_mutables;
    }

    if (mutable->flags & TNL_T_IPSEC) {
        vxport->tnl_ops = &ovs_ipsec_vxlan_tnl_ops;
    }
    else {
        vxport->tnl_ops = &ovs_vxlan_tnl_ops;
    }
    rcu_assign_pointer (vxport->mutable, mutable);

	spin_lock_init(&vxport->cache_lock);
#ifdef NEED_CACHE_TIMEOUT
	vxport->cache_exp_interval = MAX_CACHE_EXP -
				       (net_random() % (MAX_CACHE_EXP / 2));
#endif

	ovs_tnl_port_table_add_port(vport);
    kfree (old_mutable);

    vxlan_vport_count++;
    if (vxlan_vport_count == 1) {
        schedule_delayed_work(&vxlan_mac_table_ageout_wq,
                VXLAN_MAC_TABLE_AGEOUT_INTERVAL);
        OVS_VXLAN_DEBUG("STARTING DELAYED WORK: %d", vxlan_vport_count);
    }
    OVS_VXLAN_DEBUG("vxlan_create: VPORT COUNT: %d", vxlan_vport_count);

	return vport;

error_free_mutables:
	kfree(mutable);
    kfree (old_mutable);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static void
vxlan_destroy(struct vport *vport)
{
	struct tnl_vport              *vxport;
    struct tnl_socket             *tnl_socket;
    struct tnl_mutable_config     *mutable;

	vxport = tnl_vport_priv(vport);
    OVS_VXLAN_DEBUG("Destroying vxport: %s", vxport->name);

    mutable = rtnl_dereference(vxport->mutable);

    tnl_socket = rtnl_dereference(vxport->vxlan_rcv_socket);
    vxlan_release_tnl_socket (mutable, tnl_socket);

    tnl_socket = rtnl_dereference(vxport->vxlan_mcast_socket);
    vxlan_release_tnl_socket (mutable, tnl_socket);

    ovs_tnl_destroy (vport);

    vxlan_vport_count--;
    if (vxlan_vport_count == 0) {
		cancel_delayed_work_sync(&vxlan_mac_table_ageout_wq);
        OVS_VXLAN_DEBUG("CANCELING DELAYED WORK: %d", vxlan_vport_count);
    }
    OVS_VXLAN_DEBUG("vxlan_destroy: VPORT COUNT: %d", vxlan_vport_count);
}

static const struct nla_policy vxlan_nl_policy[OVS_TUNNEL_ATTR_MAX + 1] = {
	[OVS_TUNNEL_ATTR_FLAGS]        = { .type = NLA_U32 },
	[OVS_TUNNEL_ATTR_TOS]          = { .type = NLA_U8 },
	[OVS_TUNNEL_ATTR_TTL]          = { .type = NLA_U8 },

	[OVS_TUNNEL_ATTR_SRC_IPV4]     = { .type = NLA_U32 },
    [OVS_TUNNEL_ATTR_DST_IPV4]     = { .type = NLA_U32 },
	[OVS_TUNNEL_ATTR_VTEP_PORT]    = { .type = NLA_U16 },
    [OVS_TUNNEL_ATTR_IN_KEY]       = { .type = NLA_U64 },
    [OVS_TUNNEL_ATTR_MCAST_PORT]   = { .type = NLA_U16 },
};

static int
vxlan_parse_options (struct tnl_mutable_config *mutable,
                     struct nlattr *options)
{
	struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1];
	int err;
    __be64  vni;

	if (!options)
		return -EINVAL;

	err = nla_parse_nested(a, OVS_TUNNEL_ATTR_MAX, options, vxlan_nl_policy);
	if (err) {
		return err;
    }

	if (!a[OVS_TUNNEL_ATTR_FLAGS] ||
        !a[OVS_TUNNEL_ATTR_SRC_IPV4] ||
        !a[OVS_TUNNEL_ATTR_IN_KEY] ||
        !a[OVS_TUNNEL_ATTR_DST_IPV4]) {
		return -EINVAL;
    }

	mutable->flags = nla_get_u32(a[OVS_TUNNEL_ATTR_FLAGS]) & TNL_F_PUBLIC;
	mutable->vtep = nla_get_be32(a[OVS_TUNNEL_ATTR_SRC_IPV4]);
	mutable->mcast_ip = nla_get_be32(a[OVS_TUNNEL_ATTR_DST_IPV4]);
	vni = nla_get_be64(a[OVS_TUNNEL_ATTR_IN_KEY]);
	mutable->vni = (u32)(be64_to_cpu(vni) & 0x00FFFFFF);

	if (a[OVS_TUNNEL_ATTR_TOS]) {
		mutable->tos = nla_get_u8(a[OVS_TUNNEL_ATTR_TOS]);
		/* Reject ToS config with ECN bits set. */
		if (mutable->tos & INET_ECN_MASK) {
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
        
    mutable->mac_entry_age = 1000; /* 1 seconds. 1000 milli seconds */

	return 0;
}

static int
vxlan_set_config (struct vport *vport, struct nlattr *options, 
        struct tnl_mutable_config  *mutable,
        struct tnl_mutable_config  *old_mutable)
{
	struct tnl_vport    *vxport;
    struct tnl_socket   *rcv_socket, *old_rcv_socket;
    struct tnl_socket   *mcast_socket, *old_mcast_socket;
	int                  err, mlink;

    mcast_socket = rcv_socket = old_rcv_socket = old_mcast_socket = NULL;
    
    vxport = tnl_vport_priv(vport);

	/* Copy fields whose values should be retained. */
	mutable->seq = old_mutable->seq + 1;
	memcpy(mutable->eth_addr, old_mutable->eth_addr, ETH_ALEN);

    err = vxlan_parse_options (mutable, options);
    if (err != 0)
        goto error;

    OVS_VXLAN_DEBUG("NEW -> VNI: %d, VTEP: 0x%x:%d, MCAST: 0x%x:%d, NET: %p",
            mutable->vni, mutable->vtep, mutable->vtep_port,
            mutable->mcast_ip, mutable->mcast_port,
            ovs_dp_get_net(vport->dp));

    mutable->tunnel_hlen = VXLAN_HLEN + sizeof (struct iphdr);
    mutable->out_key = cpu_to_be64(mutable->vni);
	port_key_set_net(&mutable->key, ovs_dp_get_net(vport->dp));
    mutable->key.in_key = cpu_to_be64(mutable->vni);
    mutable->key.tunnel_type = (TNL_T_PROTO_VXLAN | TNL_T_KEY_EXACT);

    if (mutable->flags & TNL_F_IPSEC)
        mutable->key.tunnel_type |= TNL_T_IPSEC;
    
    /* Let's check if we already have an interface persent with same VNI */
    if (mutable->vni != old_mutable->vni) {
        struct port_lookup_key key;
        const struct tnl_mutable_config *m;
        memcpy (&key, &mutable->key, sizeof(struct port_lookup_key));
        if (unlikely (ovs_tnl_port_table_lookup (&key, &m))) {
            OVS_VXLAN_DEBUG("An interface already exits with the same VNI: %d", 
                    mutable->vni);
		    return -EEXIST;
        }
    }

    if ((mutable->vtep != old_mutable->vtep) ||
        (mutable->vtep_port != old_mutable->vtep_port)) {
        err = vxlan_open_tnl_socket (mutable, mutable->vtep, mutable->vtep_port,
                                   &rcv_socket, &mlink);
        if (err != 0) {
            goto error;
        }
        old_rcv_socket = rtnl_dereference(vxport->vxlan_rcv_socket);
        rcu_assign_pointer(vxport->vxlan_rcv_socket, rcv_socket);
        vxlan_release_tnl_socket (mutable, old_rcv_socket);
    }

    if ((mutable->mcast_ip != old_mutable->mcast_ip) ||
        (mutable->mcast_port != old_mutable->mcast_port)) {
        err = vxlan_open_tnl_socket (mutable, mutable->mcast_ip, 
                                 mutable->mcast_port, &mcast_socket, &mlink);
        if (err != 0) {
            goto sock_free;
        }

        old_mcast_socket = rtnl_dereference(vxport->vxlan_mcast_socket);
        rcu_assign_pointer(vxport->vxlan_mcast_socket, mcast_socket);
        vxlan_release_tnl_socket(mutable, old_mcast_socket);
        mutable->mlink = mlink;
    }

	return 0;
    
 sock_free:
    vxlan_release_tnl_socket (mutable, rcv_socket);
 error:
	return err;
}

static int
vxlan_set_options(struct vport *vport, struct nlattr *options)
{
	struct tnl_vport                 *vxport;
	struct tnl_mutable_config          *old_mutable, *mutable;
    int                              err;
    
    vxport = tnl_vport_priv(vport);

	/* Copy fields whose values should be retained. */
	old_mutable = rtnl_dereference(vxport->mutable);

	mutable = kzalloc(sizeof(struct tnl_mutable_config), GFP_KERNEL);
	if (!mutable) {
		err = -ENOMEM;
		goto error;
	}

    if (vxlan_set_config (vport, options, mutable, old_mutable) != 0) {
        goto error_free;
    }

	if (port_hash(&mutable->key) != port_hash(&old_mutable->key))
		ovs_tnl_port_table_move_port(vport, mutable);
	else
		ovs_tnl_assign_config_rcu(vport, mutable);

    ovs_tnl_free_mutable_rtnl (mutable);

    OVS_VXLAN_DEBUG ("REAL -> VNI: %d, VTEP: 0x%x:%d, MCAST: 0x%x:%d",
            mutable->vni, mutable->vtep, mutable->vtep_port,
            mutable->mcast_ip, mutable->mcast_port);

	return 0;
    
 error_free:
	kfree(mutable);
 error:
	return err;
}

static int
vxlan_get_options(const struct vport *vport, struct sk_buff *skb)
{
	const struct tnl_vport *vxlan_vport;
	const struct tnl_mutable_config *mutable;


    vxlan_vport = tnl_vport_priv(vport);
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

	if (nla_put_be32(skb, OVS_TUNNEL_ATTR_DST_IPV4, mutable->mcast_ip))
        goto nla_put_failure;

    if (nla_put_u16(skb, OVS_TUNNEL_ATTR_MCAST_PORT, mutable->mcast_port))
        goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}


/* -- Traffic handling -- */

static void 
vxlan_build_header(const struct vport *vport, 
                   const struct tnl_mutable_config *mutable, void *header)
{

	struct udphdr *udph = header;
	struct vxlanhdr *vxh = (struct vxlanhdr *)(udph + 1);

	//udph->dest = htons(mutable->vtep_port);
	udph->check = 0;

	vxh->vx_flags = htonl(VXLAN_FLAGS);
	vxh->vx_vni = htonl(mutable->vni << 8);
}

static struct sk_buff *
vxlan_update_header(const struct vport *vport,
                    const struct tnl_mutable_config *mutable,
					struct dst_entry *dst, struct sk_buff *skb)
{
	struct udphdr *udph = udp_hdr(skb);
	struct vxlanhdr *vxh = (struct vxlanhdr *)(udph + 1);

	if (mutable->flags & TNL_F_OUT_KEY_ACTION)
		vxh->vx_vni = htonl(mutable->vni);

	udph->source = htons(mutable->vtep_port); 
	udph->dest = htons(OVS_CB(skb)->vxlan_udp_port);
	udph->len = htons(skb->len - skb_transport_offset(skb));

	/*
	 * Allow our local IP stack to fragment the outer packet even if the
	 * DF bit is set as a last resort.  We also need to force selection of
	 * an IP ID here because Linux will otherwise leave it at 0 if the
	 * packet originally had DF set.
	 */
	skb->local_df = 1;
	__ip_select_ident(ip_hdr(skb), dst, 0);

	return skb;
}

static int
vxlan_send(struct vport *vport, struct sk_buff *skb)
{
	struct iphdr               *iph;
	struct ethhdr              *eh;
    struct vxlan_mac_entry     *vme;
    struct tnl_mutable_config  *mutable;
    struct tnl_vport         *vxport;

	vxport    = tnl_vport_priv(vport);
    mutable   = rtnl_dereference(vxport->mutable);
	eh        = eth_hdr(skb);
	iph       = ip_hdr(skb);

    vme = vxlan_vme_get_peer_vtep (mutable->vni, eh->h_dest, 0, 
                                    mutable->mac_entry_age);

    OVS_VXLAN_DEBUG("vxlan_send[VNI=%d,len=%d]: "
            "SMAC:%x:%x:%x:%x:%x:%x, " 
            "DMAC:%x:%x:%x:%x:%x:%x, "
            "ETH_TYPE: 0x%x, "
            "saddr: 0x%x, "
            "daddr: 0x%x, "
            "VERSION: %d, "
            "PEER: 0x%x ",
            mutable->vni,
            skb->len,

            eh->h_source[0], 
            eh->h_source[1], 
            eh->h_source[2], 
            eh->h_source[3], 
            eh->h_source[4], 
            eh->h_source[5], 

            eh->h_dest[0], 
            eh->h_dest[1], 
            eh->h_dest[2], 
            eh->h_dest[3], 
            eh->h_dest[4], 
            eh->h_dest[5],
            ntohs(eh->h_proto),

            iph->saddr,
            iph->daddr,
            iph->version,
            ((vme) ? vme->peer : 0)
            );

    if (vme) {
        OVS_CB(skb)->tun_ipv4_dst = vme->peer;
        OVS_CB(skb)->vxlan_udp_port = mutable->vtep_port;
    }
    else if (mutable->mcast_ip) {
        /* 
         * We could not find the PEER VTEP for this mac address. This is 
         * where we want to do the multicast.
         */
        OVS_CB(skb)->tun_ipv4_dst = mutable->mcast_ip;
        OVS_CB(skb)->vxlan_udp_port = mutable->mcast_port;
    }
    else {
        goto error;
    }
    OVS_CB(skb)->tun_ipv4_src = mutable->vtep;

    return ovs_tnl_send (vport, skb);

error:
    ovs_vport_record_error(vport, VPORT_E_TX_DROPPED);
    kfree_skb(skb);
    return 0;
}


static bool 
sec_path_esp(struct sk_buff *skb)
{
	struct sec_path *sp = skb_sec_path(skb);

	if (sp) {
		int i;

		for (i = 0; i < sp->len; i++)
			if (sp->xvec[i]->id.proto == XFRM_PROTO_ESP)
				return true;
	}

	return false;
}

/* Called with rcu_read_lock and BH disabled. */
static int
vxlan_rcv_process (struct sock *sk, struct sk_buff *skb, bool multicast)
{
    struct port_lookup_key key;
    const struct tnl_mutable_config *m;
    struct vport     *vport;
	struct tnl_vport *vxport;
	struct vxlanhdr *vxh;
	struct iphdr *iph;
    u32    vni;
	struct ethhdr *eh;
    struct tnl_mutable_config *mutable;
    struct vxlan_mac_entry *vme;

    if (!rcu_read_lock_held ()) {
        OVS_VXLAN_VME_DEBUG("RCU READ LOCK is NOT HELD");
    }

	if (unlikely(!pskb_may_pull(skb, VXLAN_HLEN + ETH_HLEN)))
		goto error;

	iph = ip_hdr(skb);
	vxh = vxlan_hdr(skb);

    OVS_VXLAN_DEBUG("vxlan_rcv_process: %s(%d): SRC: 0x%x, DST: 0x%x",
            ((multicast == true) ? "MCAST" : "NORMAL"),
            multicast, iph->saddr, iph->daddr);

	if (unlikely(vxh->vx_flags != htonl(VXLAN_FLAGS) ||
		     vxh->vx_vni & htonl(0xff))) {
		goto error;
    }

    vni = ntohl(vxh->vx_vni) >> 8;

    memset (&key, 0, sizeof(struct port_lookup_key));
    key.in_key = cpu_to_be64(vni);

    key.tunnel_type = (TNL_T_PROTO_VXLAN | TNL_T_KEY_EXACT);
	if (sec_path_esp(skb))
		key.tunnel_type |= TNL_T_IPSEC;

	port_key_set_net(&key, dev_net(skb->dev));

    vport = ovs_tnl_port_table_lookup (&key, &m);
	if (unlikely(vport == NULL)) {
        ovs_tnl_port_table_dump ();
        OVS_VXLAN_DEBUG("VXPORT not found. KEY: 0x%llx, NET: %p, TYPE: 0x%x",
                key.in_key, key.net, key.tunnel_type);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		goto error;
	}
    vxport = tnl_vport_priv (vport);
    mutable = rcu_dereference_rtnl(vxport->mutable);

	__skb_pull(skb, VXLAN_HLEN);

	skb_postpull_rcsum(skb, skb_transport_header(skb), VXLAN_HLEN + ETH_HLEN);
	skb_reset_mac_header(skb);
	eh = eth_hdr(skb);

    vme = vxlan_vme_get_peer_vtep(vni, eh->h_source, iph->saddr, 
                                   mutable->mac_entry_age);

    if (unlikely(!vme)) {
        /* New Entry. Learn the entry. */
        vxlan_vme_add(vni, iph->saddr, eh->h_source, 
                VXLAN_MAC_ENTRY_FLAGS_LEARNED, mutable->mac_entry_age);
    }

	/* Save outer tunnel values */
	OVS_CB(skb)->tun_ipv4_src = iph->saddr;
	OVS_CB(skb)->tun_ipv4_dst = iph->daddr;
	OVS_CB(skb)->tun_ipv4_tos = iph->tos;
	OVS_CB(skb)->tun_ipv4_ttl = iph->ttl;
    OVS_CB(skb)->tun_id       = key.in_key;

	ovs_tnl_rcv(vport, skb, iph->tos);

    return 0;

error:
    ovs_vport_record_error(vport, VPORT_E_RX_DROPPED);
	kfree_skb(skb);
	return 0;
}

/* Called with rcu_read_lock and BH disabled. */
static int
vxlan_rcv(struct sock *sk, struct sk_buff *skb)
{
    return vxlan_rcv_process (sk, skb, false);
}

static int
vxlan_mcast_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct iphdr    *iph;
    __be32           saddr;

    saddr = inet_sk(sk)->inet_rcv_saddr;
	iph = ip_hdr(skb);

    /* This packet is sent by us. Discard. Silently. */
    if (iph->saddr == saddr) {
        kfree_skb(skb);
        return 0;
    }

    return vxlan_rcv_process (sk, skb, true);
}

int
ovs_vxlan_init()
{
	int                             i;

	vxlan_mac_table = kzalloc(VXLAN_MAC_TABLE_SIZE * 
                                sizeof(struct vxlan_mac_hlr_table),
                            GFP_KERNEL);
	if (vxlan_mac_table == NULL)
		return -ENOMEM;

	for (i = 0; i < VXLAN_MAC_TABLE_SIZE; i++) {
        struct vxlan_mac_hlr_table *hh = &vxlan_mac_table[i];
		INIT_HLIST_HEAD(&hh->hash_table);
		INIT_LIST_HEAD(&hh->lru_list);
        spin_lock_init (&hh->lock);
    }

    spin_lock_init (&vxlan_socket_lock);

    return 0;
}

void
ovs_vxlan_exit()
{
    struct vxlan_mac_entry  *vme;
    struct vxlan_mac_hlr_table *hh;
    struct hlist_node       *node;
    int                      i;

    for (i = 0; i < VXLAN_MAC_TABLE_SIZE; i++) {
        hh = &vxlan_mac_table [i];
        spin_lock (&hh->lock);
        hlist_for_each_entry_rcu(vme, node, &hh->hash_table, hash_node) {
            vxlan_vme_delete (vme, false);
        }
        spin_unlock (&hh->lock);
    }

    kfree (vxlan_mac_table);
}


#else
#warning VXLAN tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
