/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
 * Copyright (c) 2012 Freescale, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/if_ether.h>
#include <ctype.h>

#include "command-line.h"
#include "netlink.h"
#include "netdev.h"
#include "ofpbuf.h"
#include "odp-util.h"
#include "packets.h"
#include "vlog.h"
#include "netlink-socket.h"
#include "socket-util.h"
#include "timeval.h"
#include <netinet/ether.h>

VLOG_DEFINE_THIS_MODULE(vxctl);

#define VXLAN_STATUS_MSG_SIZE (256)
struct vxlan_nl_data {
    struct {
        unsigned int vni:1;
        unsigned int vtep:1;
        unsigned int mac:1;
    } flags;

    uint32_t         vni;
    struct in_addr   vtep;
    unsigned char    mac [ETH_ADDR_LEN];
    uint32_t         status_code;
    unsigned char    status_str [VXLAN_STATUS_MSG_SIZE];
    uint32_t         age;
};

static const struct nl_policy ovs_vxlan_policy[] = {
    [OVS_VXLAN_ATTR_VNI] = { .type = NL_A_U32, .optional = true },
    [OVS_VXLAN_ATTR_VTEP] = { .type = NL_A_U32, .optional = true },
    [OVS_VXLAN_ATTR_MAC] = { .type = NL_A_UNSPEC,
                             .min_len = ETH_ADDR_LEN,
                             .max_len = ETH_ADDR_LEN,
                             .optional = true },

    [OVS_VXLAN_ATTR_STATUS_CODE] = { .type = NL_A_U32, .optional = true },
    [OVS_VXLAN_ATTR_STATUS_STR] = { .type = NL_A_UNSPEC,
                                    .max_len = VXLAN_STATUS_MSG_SIZE,
                                    .optional = true },
    [OVS_VXLAN_ATTR_AGE] = { .type = NL_A_U32, .optional = true },
};


/* -m, --more: Output verbosity.
 * -d, --dryrun: Dry run. Don't write to kernel.
 *
 * So far only undocumented commands honor this option, so we don't document
 * the option itself. */
static int verbose;
static bool dryrun = false;
static const struct command all_commands[];
static struct nl_sock * genl_sock;
static int ovs_vxlan_family;

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);
static int vxlan_nl_send (uint8_t cmd, struct vxlan_nl_data * cfg);
static int vxlan_parse_nl_reply (struct ofpbuf *reply, struct vxlan_nl_data *r);

int
main(int argc, char *argv[])
{
    int error = -1;

    set_program_name(argv[0]);
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);

    error = nl_lookup_genl_family(OVS_VXLAN_FAMILY,
                                  &ovs_vxlan_family);
    if (error) {
        ovs_fatal(0, "VxLAN Netlink family '%s' does not exist. "
                  "The Open vSwitch kernel module may not support VxLAN.",
                  OVS_VXLAN_FAMILY);
    }

    error = nl_sock_create(NETLINK_GENERIC, &genl_sock);
    if (error) {
        ovs_fatal(0, "Failed to create netlink socket. error=%s",
                 strerror(errno));
    }
    
    run_command(argc - optind, argv + optind, all_commands);

    nl_sock_destroy (genl_sock);

    return 0;
}


static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_DUMMY = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"statistics", no_argument, NULL, 's'},
        {"more", no_argument, NULL, 'm'},
        {"dryrun", no_argument, NULL, 'd'},
        {"timeout", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'm':
            verbose++;
            break;

        case 'd':
            dryrun = true;
            break;

        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ovs_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: Open vSwitch VxLAN management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "  add-host vni=<VNI> vtep=<VTEP> host=<END Host> add a new host entry for a given VTEP and VNI\n"
           "  del-host vni=<VNI> host=<END Host> remove a host entry for a given VNI\n"
           "  del-vme vtep=<VTEP> vni=<VNI> ip=<MAC address>  remove a MAC entry  for a given VTEP and VNI\n"
           "  show                   prints the VXLAN MAC table\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOther options:\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}



static void
vxctl_show(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
}


static void
vxctl_help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
}

static bool
vxctl_parse_cmdline_args (int argc, char *argv[], struct vxlan_nl_data * cfg)
{
    int i;
    char *save_ptr;


    for (i = 1; i < argc; i++) {
        char *key, *value;
        
        key = strtok_r(argv[i], "=", &save_ptr);
        if (key == NULL)
            return true;

        value = strtok_r(NULL, "", &save_ptr);
        if (!value) {
            printf("Value must be specified for %s", key);
            return false;
        }
        
        if (strcmp(key, "vtep") == 0) {
            if (lookup_ip (value, &cfg->vtep) != 0) {
                return false;
            }
            cfg->flags.vtep = 1;
        } else if (strcmp(key, "vni") == 0) {
            cfg->vni = atoi(value);
            cfg->flags.vni = 1;
        } else if (strcmp(key, "mac") == 0) {
            struct ether_addr ea;
            if (ether_aton_r ((const char *)value, &ea)) {
                memcpy (cfg->mac, ea.ether_addr_octet, ETH_ALEN);
                cfg->flags.mac = 1;
            }
        } else if (strcmp(key, "peer") == 0) {
            if (lookup_ip (value, &cfg->vtep) != 0) {
                return false;
            }
            cfg->flags.vtep = 1;
        }
        else {
            printf("Unknown command: %s", key);
            return false;
        }
    }

    return true;
}

static void
print_peer (struct vxlan_nl_data *reply, char *msg)
{
    char *str = (msg) ? msg : "";

    printf ("%s\"%s\". vni=%d, vtep="IP_FMT"\n",
            str, reply->status_str, reply->vni, IP_ARGS(&reply->vtep.s_addr));
}

static void
vxctl_add_peer(int argc, char *argv[])
{
    struct vxlan_nl_data cfg;
    int e;

    bzero (&cfg, sizeof(cfg));
    if (vxctl_parse_cmdline_args (argc, argv, &cfg) == true) {
        if (cfg.flags.vni == 0 || cfg.flags.vtep == 0) {
            ovs_fatal (-1, "Supply vni and vtep address");
        }
        
        e = vxlan_nl_send (OVS_VXLAN_CMD_PEER_NEW, &cfg);
        if (e == 0) {
            if (cfg.status_code == 0) {
                if (verbose) {
                    print_peer (&cfg, NULL);
                }
            }
            else {
                print_peer (&cfg, "error:");
                exit (-cfg.status_code);
            }
        }
        else
            ovs_fatal (e, "Failed to send \"add-peer\" command");
    }
}

static void
vxctl_del_peer(int argc, char *argv[])
{
    struct vxlan_nl_data cfg;
    int e;

    bzero (&cfg, sizeof(cfg));
    if (vxctl_parse_cmdline_args (argc, argv, &cfg) == true) {
        if (cfg.flags.vni == 0 || cfg.flags.vtep == 0) {
            ovs_fatal (-1, "Supply vni and vtep address");
        }

        e = vxlan_nl_send (OVS_VXLAN_CMD_PEER_DEL, &cfg);
        if (e == 0) {
            if (cfg.status_code == 0) {
                if (verbose) {
                    print_peer (&cfg, NULL);
                }
            }
            else {
                print_peer (&cfg, "error:");
                exit (-cfg.status_code);
            }
        }
        else
            ovs_fatal (e, "Failed to send \"del-peer\" command");
    }
}

static void
vxctl_dump_peer (int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ofpbuf *buf, reply;
    struct ovs_header *ovs_header;
    struct nl_dump dump;
    int i=0;

    buf = ofpbuf_new(1024);

    nl_msg_put_genlmsghdr(buf, 0, ovs_vxlan_family,
                          NLM_F_REQUEST | NLM_F_ECHO,
                          OVS_VXLAN_CMD_PEER_DUMP, OVS_VXLAN_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;

    nl_dump_start(&dump, genl_sock, buf);
    ofpbuf_delete(buf);

    while (nl_dump_next(&dump, &reply)) {
        struct vxlan_nl_data d;
        bzero (&d, sizeof(d));
        vxlan_parse_nl_reply (&reply, &d);
        printf ("    vni=%d    vtep="IP_FMT"\n",
                d.vni, IP_ARGS(&d.vtep.s_addr));
        i++;
    }
    nl_dump_done (&dump);

    if (i > 0)
        printf ("Total: %d\n", i);
        
}

static void
print_vme (struct vxlan_nl_data *reply, char *msg)
{
    char *str = (msg) ? msg : "";

    printf ("%s\"%s\". vni=%d, vtep="IP_FMT", macaddr="ETH_ADDR_FMT"\n",
            str, reply->status_str, reply->vni, IP_ARGS(&reply->vtep.s_addr),
            ETH_ADDR_ARGS(reply->mac));
}

static void
vxctl_del_vme(int argc, char *argv[])
{
    struct vxlan_nl_data cfg;
    int e;

    bzero (&cfg, sizeof(cfg));
    if (vxctl_parse_cmdline_args (argc, argv, &cfg) == true) {
        if (cfg.flags.vni == 0 || cfg.flags.mac == 0) {
            ovs_fatal (0, "Supply vni, vtep and MAC Address");
        }

        e = vxlan_nl_send (OVS_VXLAN_CMD_VME_DEL, &cfg);

        if (e == 0) {
            if (cfg.status_code == 0) {
                if (verbose) {
                    print_vme (&cfg, NULL);
                }
            }
            else {
                print_vme (&cfg, "error:");
                exit (-cfg.status_code);
            }
        }
        else
            ovs_fatal (0, "Failed to send \"del-vme\" command");
    }
}

static void
vxctl_dump_vme (int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ofpbuf *buf, reply;
    struct ovs_header *ovs_header;
    struct nl_dump dump;
    int i=0;
    float age;

    buf = ofpbuf_new(1024);

    nl_msg_put_genlmsghdr(buf, 0, ovs_vxlan_family,
                          NLM_F_REQUEST | NLM_F_ECHO,
                          OVS_VXLAN_CMD_VME_DUMP, OVS_VXLAN_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;

    nl_dump_start (&dump, genl_sock, buf);
    ofpbuf_delete(buf);

    while (nl_dump_next(&dump, &reply)) {
        struct vxlan_nl_data d;
        bzero (&d, sizeof(d));
        vxlan_parse_nl_reply (&reply, &d);
        age = (float)d.age/1000.0;
        printf ("    vni=%d    vtep="IP_FMT"    macaddr="ETH_ADDR_FMT"    age=%fsec(%u)\n",
                d.vni, IP_ARGS(&d.vtep.s_addr), ETH_ADDR_ARGS(d.mac), age, d.age);
        i++;
    }
    nl_dump_done (&dump);

    if (i > 0)
        printf ("Total: %d\n", i);

}


static const struct command all_commands[] = {
    { "add-peer", 2, INT_MAX, vxctl_add_peer },
    { "del-peer", 2, INT_MAX, vxctl_del_peer },
    { "dump-peer", 0, INT_MAX, vxctl_dump_peer },
    { "del-vme", 2, INT_MAX, vxctl_del_vme },
    { "dump-vme", 0, INT_MAX, vxctl_dump_vme },
    { "show", 0, INT_MAX, vxctl_show },
    { "help", 0, INT_MAX, vxctl_help },

    /* Undocumented commands for testing. */

    { NULL, 0, 0, NULL },
};


static int
vxlan_nl_send (uint8_t cmd, struct vxlan_nl_data * cfg)
{
    struct ofpbuf *buf, *reply;
    struct ovs_header *ovs_header;
    int error;

    buf = ofpbuf_new(1024);

    nl_msg_put_genlmsghdr(buf, 0, ovs_vxlan_family, NLM_F_REQUEST | NLM_F_ECHO,
                          cmd, OVS_VXLAN_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;

    nl_msg_put_u32(buf, OVS_VXLAN_ATTR_VNI, cfg->vni);
    nl_msg_put_u32(buf, OVS_VXLAN_ATTR_VTEP, cfg->vtep.s_addr);
    nl_msg_put_unspec(buf, OVS_VXLAN_ATTR_MAC, cfg->mac, ETH_ALEN);

    if (dryrun != true) {
        error = nl_sock_transact(genl_sock, buf, &reply);
        if (error == 0) {
            error = vxlan_parse_nl_reply (reply, cfg);
        }
    }
    else {
        error = 0;
    }

    ofpbuf_delete(buf);

    return error;
}

static int
vxlan_parse_nl_reply (struct ofpbuf *reply, struct vxlan_nl_data *r)
{
    struct nlattr *a[ARRAY_SIZE(ovs_vxlan_policy)];
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;

    ofpbuf_use_const(&b, reply->data, reply->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_vxlan_family
        || !nl_policy_parse(&b, 0, ovs_vxlan_policy, a,
                            ARRAY_SIZE(ovs_vxlan_policy))) {
        return EINVAL;
    }

    if (a[OVS_VXLAN_ATTR_VNI])
        r->vni = nl_attr_get_u32(a[OVS_VXLAN_ATTR_VNI]);

    if (a[OVS_VXLAN_ATTR_VTEP])
        r->vtep.s_addr = nl_attr_get_u32(a[OVS_VXLAN_ATTR_VTEP]);

    if (a[OVS_VXLAN_ATTR_MAC])
        memcpy (r->mac, nl_attr_get_unspec (a[OVS_VXLAN_ATTR_MAC], ETH_ALEN),
                ETH_ALEN);

    if (a[OVS_VXLAN_ATTR_STATUS_CODE])
        r->status_code = nl_attr_get_u32 (a[OVS_VXLAN_ATTR_STATUS_CODE]);

    if (a[OVS_VXLAN_ATTR_STATUS_STR]) {
        size_t s = nl_attr_get_size (a[OVS_VXLAN_ATTR_STATUS_STR]);
        memcpy (r->status_str,
                nl_attr_get_unspec (a[OVS_VXLAN_ATTR_STATUS_STR], s),
                s);
    }

    if (a[OVS_VXLAN_ATTR_AGE])
        r->age = nl_attr_get_u32 (a[OVS_VXLAN_ATTR_AGE]);

    return 0;
}
