/*
 * IS-IS Rout(e)ing protocol - isis_tlv.h
 *                             IS-IS TLV related routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _ZEBRA_ISIS_TLV_H
#define _ZEBRA_ISIS_TLV_H

/*
 * The list of TLVs we (should) support.
 * ____________________________________________________________________________
 * Name                   Value  IIH LSP SNP Status
 *                               LAN
 * ____________________________________________________________________________
 * 
 * Area Addresses             1   y   y   n  ISO10589
 * IIS Neighbors              2   n   y   n  ISO10589
 * ES Neighbors               3   n   y   n  ISO10589
 * IIS Neighbors              6   y   n   n  ISO10589
 * Padding                    8   y   n   n  ISO10589
 * LSP Entries                9   n   n   y  ISO10589
 * Authentication            10   y   y   y  ISO10589, RFC3567
 * Checksum                  12   y   n   y  RFC3358
 * TE IS Reachability        22   n   y   n  RFC3784
 * IS Alias                  24   n   y   n  RFC3786
 * IP Int. Reachability     128   n   y   n  RFC1195
 * Protocols Supported      129   y   y   n  RFC1195
 * IP Ext. Reachability     130   n   y   n  RFC1195
 * IDRPI                    131   n   y   y  RFC1195
 * IP Interface Address     132   y   y   n  RFC1195
 * TE Router ID             134   n   y   n  RFC3784
 * Extended IP Reachability 135   n   y   n  RFC3784
 * Dynamic Hostname         137   n   y   n  RFC2763
 * Shared Risk Link Group   138   n   y   y  draft-ietf-isis-gmpls-extensions
 * Restart TLV              211   y   n   n  RFC3847
 * MT IS Reachability       222   n   y   n  draft-ietf-isis-wg-multi-topology
 * MT Supported             229   y   y   n  draft-ietf-isis-wg-multi-topology
 * IPv6 Interface Address   232   y   y   n  draft-ietf-isis_ipv6
 * MT IP Reachability       235   n   y   n  draft-ietf-isis-wg-multi-topology
 * IPv6 IP Reachability     236   n   y   n  draft-ietf-isis_ipv6
 * MT IPv6 IP Reachability  237   n   y   n  draft-ietf-isis-wg-multi-topology
 * P2P Adjacency State      240   y   n   n  RFC3373
 * IIH Sequence Number      241   y   n   n  draft-shen-isis-iih-sequence
 * Router Capability        242   -   -   -  draft-ietf-isis-caps
 * Port Capability	    243   n   y   n  draft-eastlake-trill-bridge-isis
 *
 * 
 * IS Reachability sub-TLVs we (should) support.
 * ____________________________________________________________________________
 * Name                           Value   Status
 * ____________________________________________________________________________
 * Administartive group (color)       3   RFC3784
 * Link Local/Remote Identifiers      4   draft-ietf-isis-gmpls-extensions
 * IPv4 interface address             6   RFC3784
 * IPv4 neighbor address              8   RFC3784
 * Maximum link bandwidth             9   RFC3784
 * Reservable link bandwidth         10   RFC3784
 * Unreserved bandwidth              11   RFC3784
 * TE Default metric                 18   RFC3784
 * Link Protection Type              20   draft-ietf-isis-gmpls-extensions
 * Interface Switching Capability    21   draft-ietf-isis-gmpls-extensions
 *
 * 
 * IP Reachability sub-TLVs we (should) support.
 * ____________________________________________________________________________
 * Name                           Value   Status
 * ____________________________________________________________________________
 * 32bit administrative tag           1   draft-ietf-isis-admin-tags
 * 64bit administrative tag           2   draft-ietf-isis-admin-tags
 * Management prefix color          117   draft-ietf-isis-wg-multi-topology
 *
 *
 * Router Capability sub-TLVs we support (Values TBD, temporary for now).
 * ____________________________________________________________________________
 * Name                           Value   Status
 * ____________________________________________________________________________
 * TRILL Flags			     21	  draft-ietf-trill-rbridge-protocol
 * TRILL Nickname and Tree Root	     22	  draft-ietf-trill-rbridge-protocol
 * TRILL Distribution Tree Roots     23	  draft-ietf-trill-rbridge-protocol
 * TRILL VLANs and Bridge Roots	     24	  draft-ietf-trill-rbridge-protocol
 * TRILL ESADI Participation	     25	  draft-ietf-trill-rbridge-protocol
 * TRILL VLAN Groups		     26	  draft-ietf-trill-rbridge-protocol
 * TRILL VLAN Mapping		     27	  draft-ietf-trill-rbridge-protocol
 *
 *
 * Port Capability sub-TLVs we support
 * ____________________________________________________________________________
 * Name                           Value   Status
 * ____________________________________________________________________________
 * TRILL Special VLANs and Flags     10	  draft-ietf-trill-rbridge-protocol
 * TRILL Enabled VLANs		     11	  draft-ietf-trill-rbridge-protocol
 * TRILL Appointed Forwarders	     12	  draft-ietf-trill-rbridge-protocol
 */

#define AREA_ADDRESSES            1
#define IS_NEIGHBOURS             2
#define ES_NEIGHBOURS             3
#define LAN_NEIGHBOURS            6
#define PADDING                   8
#define LSP_ENTRIES               9
#define AUTH_INFO                 10
#define CHECKSUM                  12
#define TE_IS_NEIGHBOURS          22
#define IS_ALIAS                  24
#define IPV4_INT_REACHABILITY     128
#define PROTOCOLS_SUPPORTED       129
#define IPV4_EXT_REACHABILITY     130
#define IDRP_INFO                 131
#define IPV4_ADDR                 132
#define TE_ROUTER_ID              134
#define TE_IPV4_REACHABILITY      135
#define DYNAMIC_HOSTNAME          137
#define GRACEFUL_RESTART          211
#define IPV6_ADDR                 232
#define IPV6_REACHABILITY         236
#define WAY3_HELLO                240
#define ROUTER_CAPABILITY	  242
#define PORT_CAPABILITY		  243   /* TBD TRILL port capability TLV */

/* ROUTER_CAPABILITY sub-TLVs for TRILL */
#define	RCSTLV_TRILL_FLAGS	  21	/* TBD Flags */
#define RCSTLV_TRILL_NICKNAME	  22	/* TBD Nickname and Tree Root */
#define RCSTLV_TRILL_TREE_ROOTS	  23	/* TBD Distribution Tree Roots */
#define RCSTLV_TRILL_VLANSROOTS	  24	/* TBD VLANs and Bridge Roots */
#define RCSTLV_TRILL_ESADI	  25	/* TBD ESADI Participation */
#define RCSTLV_TRILL_VLANGROUPS	  26	/* TBD VLAN Groups */
#define RCSTLV_TRILL_VLANMAPPING  27	/* TBD VLAN Mapping */

/* PORT_CAPABILITY sub-TLVs for TRILL */
#define PCSTLV_VLANS		  10	/* Special VLANs and Flags */
#define PCSTLV_ENABLEDVLANS	  11	/* Enabled VLANs */
#define PCSTLV_APPFORWARDERS	  12	/* Appointed Forwarders */

#define IS_NEIGHBOURS_LEN (ISIS_SYS_ID_LEN + 5)
#define LAN_NEIGHBOURS_LEN 6
#define LSP_ENTRIES_LEN (10 + ISIS_SYS_ID_LEN)	/* FIXME: should be entry */
#define IPV4_REACH_LEN 12
#define IPV6_REACH_LEN 22
#define TLFLDS_LEN 2			         /* Length of Type & Len 8-bit fields */	
#define ROUTER_CAPABILITY_MIN_LEN  5		 /* Min len of router capability TLV */
#define ROUTER_CAPABILITY_MAX_LEN  250 		 /* Max len of router capability TLV */

/* TRILL Flags sub-TLV */
#define TRILL_FLAGS_SUBTLV_MIN_LEN 1 		 /* Len of sub-TLV val */
#define	TRILL_FLAGS_V0	0x80
#define	TRILL_FLAGS_V1	0x40
#define	TRILL_FLAGS_V2	0x20
#define	TRILL_FLAGS_V3	0x10

#define TRILL_NICKNAME_SUBTLV_MIN_LEN 7 	 /* Len of TRILL nickname sub-TLV value field */
#define TRILL_VLANSNBRIROOTS_SUBTLV_MIN_LEN 4    /* Len of variable len TRILL VLANs and Bridge Roots sub-TLV value field */
#define PCSTLV_VLANS_LEN	 4		 /* Exact len of port capability VLANs sub-TLV */
#define PCSTLV_VLANFWDERS_MIN_LEN 6		 /* Min. len of each appointed forwarders sub-TLV */
#define PCSTLV_ENABLEDVLANS_MIN_LEN 3		 /* Min. len of enabled VLANS sub-TLV */

/* struct for neighbor */
struct is_neigh
{
  struct metric metrics;
  u_char neigh_id[ISIS_SYS_ID_LEN + 1];
};

/* struct for te is neighbor */
struct te_is_neigh
{
  u_char neigh_id[ISIS_SYS_ID_LEN + 1];
  u_char te_metric[3];
  u_char sub_tlvs_length;
};

/* Decode and encode three-octet metric into host byte order integer */
#define GET_TE_METRIC(t) \
  (((unsigned)(t)->te_metric[0]<<16) | ((t)->te_metric[1]<<8) | \
   (t)->te_metric[2])
#define SET_TE_METRIC(t, m) \
  (((t)->te_metric[0] = (m) >> 16), \
   ((t)->te_metric[1] = (m) >> 8), \
   ((t)->te_metric[2] = (m)))

/* struct for es neighbors */
struct es_neigh
{
  struct metric metrics;
  /* approximate position of first, we use the
   * length ((uchar*)metric-1) to know all     */
  u_char first_es_neigh[ISIS_SYS_ID_LEN];

};

struct partition_desig_level2_is
{
  struct list *isis_system_ids;
};

/* struct for lan neighbors */
struct lan_neigh
{
  u_char LAN_addr[6];
};

#ifdef __SUNPRO_C
#pragma pack(1)
#endif

/* struct for LSP entry */
struct lsp_entry
{
  u_int16_t rem_lifetime;
  u_char lsp_id[ISIS_SYS_ID_LEN + 2];
  u_int32_t seq_num;
  u_int16_t checksum;
} __attribute__ ((packed));

#ifdef __SUNPRO_C
#pragma pack()
#endif

/* struct for checksum */
struct checksum
{
  u_int16_t checksum;
};

/* ipv4 reachability */
struct ipv4_reachability
{
  struct metric metrics;
  struct in_addr prefix;
  struct in_addr mask;
};

/* te router id */
struct te_router_id
{
  struct in_addr id;
};

/* te ipv4 reachability */
struct te_ipv4_reachability
{
  u_int32_t te_metric;
  u_char control;
  u_char prefix_start;		/* since this is variable length by nature it only */
};				/* points to an approximate location */



struct idrp_info
{
  u_char len;
  u_char *value;
};

#ifdef HAVE_IPV6
struct ipv6_reachability
{
  u_int32_t metric;
  u_char control_info;
  u_char prefix_len;
  u_char prefix[16];
};

/* bits in control_info */
#define CTRL_INFO_DIRECTION    0x80
#define DIRECTION_UP           0
#define DIRECTION_DOWN         1
#define CTRL_INFO_DISTRIBUTION 0x40
#define DISTRIBUTION_INTERNAL  0
#define DISTRIBUTION_EXTERNAL  1
#define CTRL_INFO_SUBTLVS      0x20
#endif /* HAVE_IPV6 */

/* internal trill nickname struct */
struct trill_nickname
{
  u_int16_t name;		/* network byte order */
  u_int8_t priority;
};

/* Router Capability TLV: used in LSPs */
struct router_capability_tlv
{
  u_char router_id[4];		   /* 4 octet Router ID */
  u_int8_t flags;		   /* 1 octet flags */
};

/* internal router capability struct, includes tlv length */
struct router_capability
{
  u_int8_t len;  		/* total length of the TLV */
  struct router_capability_tlv rt_cap_tlv;
};

/* Port Capability TLV: used in Hellos */
struct port_capability_tlv
{
  u_int8_t len;
  u_int8_t value[1];
};

#ifdef __SUNPRO_C
#pragma pack(1)
#endif

/* LSP: ROUTER_CAPABILITY RCSTLV_TRILL_NICKNAME */
struct trill_nickname_subtlv
{
    u_int8_t tn_priority;
    u_int16_t tn_nickname;
    u_int16_t tn_trootpri;
    u_int16_t tn_treecount;
} __attribute__ ((packed));

#ifdef __SUNPRO_C
#pragma pack()
#endif

/* LSP: ROUTER_CAPABILITY RCSTLV_TRILL_VLANSROOTS */
struct trill_vlan_bridge_roots_subtlv
{
    u_int16_t vlan_start;
    u_int16_t vlan_end;
};

/* flags for vlan_start */
#define	TVRFS_M4	0x8000
#define	TVRFS_M6	0x4000
#define	TVRFS_OM	0x2000
#define	TVRFS_R		0x1000

/* Hello: PORT_CAPABILITY PCSTLV_VLANS */
struct trill_vlanflags_subtlv
{
    u_int16_t outer_vlan;
    u_int16_t desig_vlan;
};

/* flags for outer_vlan */
#define	TVFFO_AF	0x8000
#define	TVFFO_AC	0x4000
#define	TVFFO_VM	0x2000
#define	TVFFO_R		0x1000

/* Hello: PORT_CAPABILITY PCSTLV_APPFORWARDERS */
struct appointed_vlanfwder_subtlv
{
    u_int16_t appointee_nick;
    u_int16_t vlan_start;
    u_int16_t vlan_end;
};

/* Hello: PORT_CAPABILITY PCSTLV_ENABLEDVLANS */
struct trill_enabledvlans_subtlv
{
    u_int16_t start_vlan;
};

/*
 * Pointer to each tlv type, filled by parse_tlvs()
 */
struct tlvs
{
  struct list *area_addrs;
  struct list *is_neighs;
  struct list *te_is_neighs;
  struct list *es_neighs;
  struct list *lsp_entries;
  struct list *prefix_neighs;
  struct list *lan_neighs;
  struct checksum *checksum;
  struct nlpids *nlpids;
  struct list *ipv4_addrs;
  struct list *ipv4_int_reachs;
  struct list *ipv4_ext_reachs;
  struct list *te_ipv4_reachs;
  struct hostname *hostname;
  struct te_router_id *router_id;
#ifdef HAVE_IPV6
  struct list *ipv6_addrs;
  struct list *ipv6_reachs;
#endif
  struct isis_passwd auth_info;
  struct list *router_capabilities;
  struct list *port_capabilities;
};

/*
 * Own definitions - used to bitmask found and expected
 */

#define TLVFLAG_AREA_ADDRS                (1<<0)
#define TLVFLAG_IS_NEIGHS                 (1<<1)
#define TLVFLAG_ES_NEIGHS                 (1<<2)
#define TLVFLAG_PARTITION_DESIG_LEVEL2_IS (1<<3)
#define TLVFLAG_PREFIX_NEIGHS             (1<<4)
#define TLVFLAG_LAN_NEIGHS                (1<<5)
#define TLVFLAG_LSP_ENTRIES               (1<<6)
#define TLVFLAG_PADDING                   (1<<7)
#define TLVFLAG_AUTH_INFO                 (1<<8)
#define TLVFLAG_IPV4_INT_REACHABILITY     (1<<9)
#define TLVFLAG_NLPID                     (1<<10)
#define TLVFLAG_IPV4_EXT_REACHABILITY     (1<<11)
#define TLVFLAG_IPV4_ADDR                 (1<<12)
#define TLVFLAG_DYN_HOSTNAME              (1<<13)
#define TLVFLAG_IPV6_ADDR                 (1<<14)
#define TLVFLAG_IPV6_REACHABILITY         (1<<15)
#define TLVFLAG_TE_IS_NEIGHS              (1<<16)
#define TLVFLAG_TE_IPV4_REACHABILITY      (1<<17)
#define TLVFLAG_3WAY_HELLO                (1<<18)
#define TLVFLAG_TE_ROUTER_ID              (1<<19)
#define TLVFLAG_CHECKSUM                  (1<<20)
#define TLVFLAG_GRACEFUL_RESTART          (1<<21)
#define TLVFLAG_ROUTER_CAPABILITY         (1<<22)
#define TLVFLAG_PORT_CAPABILITY	          (1<<23)

void init_tlvs (struct tlvs *tlvs, uint32_t expected);
void free_tlvs (struct tlvs *tlvs);
int parse_tlvs (char *areatag, u_char * stream, int size,
		u_int32_t * expected, u_int32_t * found, struct tlvs *tlvs);
void free_tlv (void *val);

int add_tlv (u_char, u_char, u_char *, struct stream *);
int add_subtlv (u_char, u_char, u_char *, size_t, struct stream *);

int tlv_add_trill_nickname (struct trill_nickname *nick_info, struct stream *stream,
		struct isis_area *area);
int tlv_add_area_addrs (struct list *area_addrs, struct stream *stream);
int tlv_add_is_neighs (struct list *is_neighs, struct stream *stream);
int tlv_add_te_is_neighs (struct list *te_is_neighs, struct stream *stream);
int tlv_add_lan_neighs (struct list *lan_neighs, struct stream *stream);
int tlv_add_nlpid (struct nlpids *nlpids, struct stream *stream);
int tlv_add_checksum (struct checksum *checksum, struct stream *stream);
int tlv_add_authinfo (char auth_type, char authlen, u_char *auth_value,
		      struct stream *stream);
int tlv_add_ip_addrs (struct list *ip_addrs, struct stream *stream);
int tlv_add_in_addr (struct in_addr *, struct stream *stream, u_char tag);
int tlv_add_dynamic_hostname (struct hostname *hostname,
			      struct stream *stream);
int tlv_add_lsp_entries (struct list *lsps, struct stream *stream);
int tlv_add_ipv4_reachs (struct list *ipv4_reachs, struct stream *stream);
int tlv_add_te_ipv4_reachs (struct list *te_ipv4_reachs, struct stream *stream);
#ifdef HAVE_IPV6
int tlv_add_ipv6_addrs (struct list *ipv6_addrs, struct stream *stream);
int tlv_add_ipv6_reachs (struct list *ipv6_reachs, struct stream *stream);
#endif /* HAVE_IPV6 */

int tlv_add_trill_vlans(struct isis_circuit *);
int tlv_add_padding (struct stream *stream);

#endif /* _ZEBRA_ISIS_TLV_H */
