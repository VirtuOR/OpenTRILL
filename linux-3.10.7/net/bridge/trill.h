#ifndef _TRILL_H
#define _TRILL_H

#include <linux/types.h>
#include <linux/list.h>

#include "br_private.h"

//#ifndef

#define TRUE 1
#define FALSE 0

//#endif

#define ETHERTYPE_TRILL 0x22F3
#define ETHERTYPE_L2_IS_IS 0x22F4

#define MAXLINKNAMELEN 20

// Rbridges well-known Ethernet addresses used by TRILL */
#define ALL_RBRIDGES		{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x40 }
#define ALL_ISIS_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x41 }
#define ALL_ESADI_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x42 }
#define MULTICAST_MAC_ADDRS_MIN { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x43 }
#define MULTICAST_MAC_ADDRS_MAX { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x4F }

#define TRILL_PROTOCOL_VERSION 0
#define TRILL_RESERVED_BITS 0
#define TRILL_UNICAST 0
#define TRILL_DEFAULT_HOPCOUNT 10

// Rbridges Nickname range */
#define RBRIDGE_NICKNAME_MIN 		0x0000
#define RBRIDGE_NICKNAME_MAX 		0xFFFF

#define RBRIDGE_NICKNAME_NONE		RBRIDGE_NICKNAME_MIN
#define RBRIDGE_NICKNAME_MINRES		0xFFC0
#define RBRIDGE_NICKNAME_MAXRES		(RBRIDGE_NICKNAME_MAX - 1)
#define RBRIDGE_NICKNAME_UNUSED		RBRIDGE_NICKNAME_MAX

#define MIN_RBRIDGE_RANDOM_NICKNAME (RBRIDGE_NICKNAME_NONE + 1)
#define MAX_RBRIDGE_RANDOM_NICKNAME (RBRIDGE_NICKNAME_MINRES + 1)

struct trill_header {

	uint16_t th_version : 2;  	// Version of the protocol
	
	uint16_t th_reserved : 2;   	// Reserved field
	
	uint16_t th_multidest : 1;  	// Unicast vs. Multidestination frame
	
	uint16_t th_optslen_hi : 3;  // Options length high

	uint16_t th_optslen_lo : 2;  // Options length low
	
	uint16_t th_hopcount : 6;   	// Hop count

	u16 th_egressnick;   	// Egress nick
	
	u16 th_ingressnick;  	// Ingress nick
};
         
#define ALIGN_TRILL_HEADER		(sizeof (unsigned short))

#define SET_TRILL_OPTIONS_LENGTH(header,value) \
		do { \
				(header)->th_optslen_lo = (value)&0x03;		\
				(header)->th_optslen_hi = (value)>>2;		\
		} while (0)

#define GET_TRILL_OPSTIONS_LENGTH(header) \
		((header)->th_optslen_lo|((header)->th_optslen_hi<<2))
	
struct trill_nickinfo {
	// Nickname of the RBridge 
	u16	tni_nick;
	// Next-hop SNPA address to reach this RBridge */
	u8	tni_adjsnpa[6];
	// Link on our system to use to reach next-hop */
	u16	tni_ifindex;
	// Num of *our* adjacencies on a tree rooted at this RBridge */
	u16	tni_adjcount;
	// Num of distribution tree root nicks chosen by this RBridge */
	u16	tni_dtrootcount;
	/*
	 * Variable size bytes to store adjacency nicks, distribution
	 * tree roots and VLAN filter lists. Adjacency nicks and
	 * distribution tree roots are 16-bit fields.
	 *
	 * Number of VLAN filter lists is equal to tni_adjcount as
	 * the VLAN filter list is one per adjacency in each DT.
	 * VLAN filter list is a 512 byte bitmap with the set of VLANs
	 * that are reachable downstream via the adjacency.
	 */
}; 	

struct trill_listnick {
	u16	tln_nick;
	mac_addr	tln_nexthop;
	u32	tln_linkid;
	u8			tln_ours; // it is either TRUE or FALSE */
};

// Access the adjacency nick list at the end of trill_nickinfo */
#define	TNI_ADJNICKSPTR(v) ((unsigned short *)((struct trill_nickinfo *)(v)+1))
#define	TNI_ADJNICK(v, n) (TNI_ADJNICKSPTR(v)[(n)])

// Access the DT root nick list in trill_nickinfo after adjacency nicks */
#define	TNI_DTROOTNICKSPTR(v) (TNI_ADJNICKSPTR(v)+(v)->tni_adjcount)
#define	TNI_DTROOTNICK(v, n) (TNI_DTROOTNICKSPTR(v)[(n)])

// Access the VLAN filter list in trill_nickinfo_t after DT Roots */
#define	TNI_VLANFILTERSPTR(v) (TNI_DTROOTNICKSPTR(v)+(v)->tni_dtrootcount)
#define	TNI_VLANFILTERMAP(v, n) \
	(((unsigned short *)(TNI_VLANFILTERSPTR(v)))+((n)*((1<<12)/8)))

#define	TNI_TOTALSIZE(v) (sizeof (struct trill_nickinfo) + \
	(sizeof (unsigned short) * (v)->tni_adjcount) + \
	(sizeof (unsigned short) * (v)->tni_dtrootcount) + \
	(((1<<12)/8) * (v)->tni_adjcount))

/*
 * This is a special value used in the sockaddr_dl "selector" field to denote
 * that the packet represents a Bridging PDU.  The core STP instance is not
 * defined on a VLAN, so this overload is safe.  All other selector values are
 * used for TRILL IS-IS PDUs to indicate VLAN ID.
 */
#define	TRILL_TCI_BPDU	0xFFFF
//
#define	TRILL_KSSOCK_NAMES "recv", "sent", "drops", "encap", "decap", "forward"

// kstats per TRILL socket */
struct trill_kssock{
	u64			tks_recv;	// packets received */
	u64			tks_sent;	// packets sent through */
	u64			tks_drops;	// packets dropped */
	u64		    tks_encap;	// packets encapsulated */
	u64		    tks_decap;	// packets decapsulated */
	u64			tks_forward;	// packets forwarded */
};

//#define	KSPINCR(stat) ++(tsock->ts_kstats.stat)

#define	TRILL_NO_TCI	0	// No VLAN tag */
#define	TRILL_VLANS_ARRSIZE ((1<<12)/8)
#define	TRILL_VLANBIT(v) ((v) % 8)
#define	TRILL_VLANBYTE(v) ((v)/8)
#define	TRILL_VLANISSET(l, v) ((l)[TRILL_VLANBYTE(v)] & (1<<TRILL_VLANBIT(v)))

struct trill_node;

/*
 * TRILL instance structure, one for each TRILL instance running in
 * support of a bridge instance. Members ti_bridgename and ti_binst
 * refer to the specific bridge instance. The bridge instance in
 * question must be online before we can support and rely on it.
 * We rely on the bridge instance for TRILL sockets to transmit and
 * receive TRILL packets. Each TRILL instance holds the TRILL
 * forwarding and nick database in ti_nodes. trill_inst_rwlock
 * protects changes to the TRILL instances list. Within each TRILL
 * instance the ti_rwlock protects changes to the structure. A refcount
 * (ti_refs) helps in destroying the TRILL instance when all TRILL
 * sockets part of the instance are shutdown.
 */
struct trill_inst {
	//struct list_head	ti_instnode;
	u16			ti_nick; // our nickname */
	u16			ti_treeroot; // tree root nickname */
	struct trill_node	*ti_nodes[RBRIDGE_NICKNAME_MAX];
	u32				ti_nodecount;
	//struct hlist_node	ti_socklist;                        // unresolved entity **********************************************
	char				ti_bridgename[MAXLINKNAMELEN];
	rwlock_t			ti_rwlock;
	u32				ti_refs;
	struct net_bridge	*ti_binst;
};

/*
 * TRILL socket structure. IS-IS daemon opens a TRILL socket for
 * each broadcast link the TRILL IS-IS protocol instance is
 * running on. TRILL specific link properties, state and stats
 * are stored as well. ts_vlanfwder indicates whether the RBridges
 * is the designated forwarder on the link for a particular VLAN.
 * A refcount (ts_refs) ensures the last consumer (TRILL module
 * or the IS-IS daemon) destroys the socket.
 //
typedef struct trillsocket_s {
	struct list_head		ts_socklistnode;
	uint8_t			ts_state;
	bridge_link_t		*ts_link;
	struct sockaddr_ll	ts_lladdr;
	uint16_t		ts_desigvlan;
	kstat_t			*ts_ksp;
	trill_kssock_t		ts_kstats;
	trill_inst_t		*ts_tip;
	uint_t			ts_refs;
	uint_t			ts_flags;
	sock_upcalls_t		*ts_conn_upcalls;	// Upcalls to sockfs //
	sock_upper_handle_t	ts_conn_upper_handle;	// sonode //
	boolean_t		ts_flow_ctrld;
	kmutex_t		ts_socklock;
	uint_t			ts_sockthreadcount;
	kcondvar_t		ts_sockthreadwait;
	kcondvar_t		ts_sockclosewait;
} trill_sock_t;
*/
/*
 * TRILL socket flags (ts_flags). TSF_SHUTDOWN indicates the TRILL socket
 * owner (IS-IS daemon process) had done a close on the socket and other
 * consumers (TRILL threads) should not pass any packets downstream.
 * TSF_CLOSEWAIT indicates socket close is in progress.
 */
#define	TSF_SHUTDOWN	0x0001
#define	TSF_CLOSEWAIT	0x0002

/*
 * TRILL node information structure. Holds information to reach the
 * TRILL node and other RBridge information specified in trill_nick_info_t
 */
struct trill_node {
	//trill_sock_t		*tn_tsp;
	struct trill_nickinfo	*tn_ni;
	u32			tn_refs;
};

// Limit to alloc max 1MB per trill_nickinfo received from user daemon */
#define	TNI_MAXSIZE	(1<<30)
	
extern void trill_recv_pkt(struct sk_buff *skb);

extern void trill_encap_pkt(struct sk_buff *skb);

extern void trill_broadcast_pkt(struct sk_buff *skb);

extern void trill_testing(struct sk_buff *skb);
extern struct sk_buff *create_trill_header(struct sk_buff *skb,
					struct trill_node *nick_entry,
					bool trill_header_ok,
					size_t msglen,
					bool multidest,
					unsigned short ingess_nick,
					unsigned short egress_nick,
					const unsigned char *source_addr);
extern struct sk_buff *create_trill_header1(struct sk_buff *skb,bool trill_header_ok,size_t msglen);

extern struct sk_buff *decapsulate_trill_header(struct sk_buff *skb);

extern int trill_del_nick(struct trill_inst *trill_inst1, uint16_t nick, bool lockheld);

extern int trill_add_nick(struct trill_nickinfo *ni,bool self);

extern int trill_set_treeroot(uint16_t treeroot);

extern int __init trill_netlink_init(void);

extern void __exit trill_netlink_fini(void);

extern int __init trill_init(void);

extern void __exit trill_fini(void);

extern void space_check(struct sk_buff *skb);

#endif
