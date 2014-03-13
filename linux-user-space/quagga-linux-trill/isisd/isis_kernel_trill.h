#ifndef _ZEBRA_ISIS_KERNEL_TRILL_H
#define _ZEBRA_ISIS_KERNEL_TRILL_H

#include <zebra.h>
#include "bool.h"

#define ETHERTYPE_TRILL 0x22F3

/* Rbridges well-known Ethernet addresses used by TRILL */
#define ALL_RBRIDGES		{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x40 }
#define ALL_ISIS_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x41 }
#define ALL_ESADI_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x42 }

#define TRILL_PROTOCOL_VERSION 0
#define TRILL_RESERVED_BITS 0
#define TRILL_UNICAST 0
#define TRILL_DEFAULT_HOPCOUNT 10

/* Rbridges Nickname range */
#define RBRIDGE_NICKNAME_MIN 		0x0000
#define RBRIDGE_NICKNAME_MAX 		0xFFFF

#define RBRIDGE_NICKNAME_NONE		RBRIDGE_NICKNAME_MIN
#define RBRIDGE_NICKNAME_MINRES		0xFFC0
#define RBRIDGE_NICKNAME_MAXRES		(RBRIDGE_NICKNAME_MAX - 1)
#define RBRIDGE_NICKNAME_UNUSED		RBRIDGE_NICKNAME_MAX

#define MIN_RBRIDGE_RANDOM_NICKNAME (RBRIDGE_NICKNAME_NONE + 1)
#define MAX_RBRIDGE_RANDOM_NICKNAME (RBRIDGE_NICKNAME_MINRES + 1)

/* AF_TRILL IOCTL codes */
#define	TRILL_BASE	(0x54524c00)	/* base (TRL in hex) */
#define	TRILL_SETNICK	(TRILL_BASE + 0)    /* trill_node_t */
#define	TRILL_GETNICK	(TRILL_BASE + 1)    /* uint16_t */
#define	TRILL_ADDNICK	(TRILL_BASE + 2)    /* trill_node_t */
#define	TRILL_DELNICK	(TRILL_BASE + 3)    /* uint16_t */
#define	TRILL_DELALL	(TRILL_BASE + 4)    /* void */
#define	TRILL_HWADDR	(TRILL_BASE + 5)    /* uint8_t[ETHERADDRL] */
#define	TRILL_TREEROOT	(TRILL_BASE + 6)    /* uint16_t */
#define	TRILL_NEWBRIDGE	(TRILL_BASE + 7)    /* char[MAXLINKNAMELEN] */
#define	TRILL_VLANFWDER	(TRILL_BASE + 8)    /* uint8_t[TRILL_VLANS_ARRSIZE] */
#define	TRILL_DESIGVLAN (TRILL_BASE + 9)    /* uint16_t */
#define	TRILL_LISTNICK	(TRILL_BASE + 10)   /* trill_listnick_t */
#define	TRILL_GETBRIDGE	(TRILL_BASE + 11)   /* char[MAXLINKNAMELEN] */
#define	TRILL_PORTFLUSH	(TRILL_BASE + 12)   /* uint16_t */
#define	TRILL_NICKFLUSH	(TRILL_BASE + 13)   /* uint16_t */
#define	TRILL_GETMTU	(TRILL_BASE + 14)   /* uint_t * */

typedef struct mac_addr mac_addr;

struct mac_addr
{
	unsigned char	addr[6];
};

struct trill_header {

	uint8_t th_version : 2;  	// Version of the protocol
	
	uint8_t th_reserved : 2;   	// Reserved field
	
	uint8_t th_multidest : 1;  	// Unicast vs. Multidestination frame
	
	uint8_t th_optslen_hi : 3;  // Options length high

	uint8_t th_optslen_lo : 2;  // Options length low
	
	uint8_t th_hopcount : 6;   	// Hop count

	uint16_t th_egressnick;   	// Egress nick
	
	uint16_t th_ingressnick;  	// Ingress nick
};
         
#define ALIGN_TRILL_HEADER		(sizeof (uint16_t))

#define SET_TRILL_OPTIONS_LENGTH(header,value) \
		do { \
				(header)->th_optslen_lo = (value)&0x03;		\
				(header)->th_optslen_hi = (value)>>2;		\
		} while (0)

#define GET_TRILL_OPSTIONS_LENGTH(header) \
		((header)->th_optslen_lo|((header)->th_optslen_hi<<2))
		
struct trill_nickinfo {
	/* Nickname of the RBridge */
	uint16_t	tni_nick;
	/* Next-hop SNPA address to reach this RBridge */
	unsigned char	tni_adjsnpa[6];
	/* Link on our system to use to reach next-hop */
	uint32_t	tni_linkid;
	/* Num of *our* adjacencies on a tree rooted at this RBridge */
	uint16_t	tni_adjcount;
	/* Num of distribution tree root nicks chosen by this RBridge */
	uint16_t	tni_dtrootcount;
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

typedef struct trill_listnick_s {
	uint16_t	tln_nick;
	mac_addr	tln_nexthop;
	uint32_t	tln_linkid;
	Bool		tln_ours;
} trill_listnick_t;

/* Access the adjacency nick list at the end of trill_nickinfo_t */
#define	TNI_ADJNICKSPTR(v) ((uint16_t *)((struct trill_nickinfo *)(v)+1))
#define	TNI_ADJNICK(v, n) (TNI_ADJNICKSPTR(v)[(n)])

/* Access the DT root nick list in trill_nickinfo_t after adjacency nicks */
#define	TNI_DTROOTNICKSPTR(v) (TNI_ADJNICKSPTR(v)+(v)->tni_adjcount)
#define	TNI_DTROOTNICK(v, n) (TNI_DTROOTNICKSPTR(v)[(n)])

/* Access the VLAN filter list in trill_nickinfo_t after DT Roots */
#define	TNI_VLANFILTERSPTR(v) (TNI_DTROOTNICKSPTR(v)+(v)->tni_dtrootcount)
#define	TNI_VLANFILTERMAP(v, n) \
	(((uint8_t *)(TNI_VLANFILTERSPTR(v)))+((n)*((1<<12)/8)))

#define	TNI_TOTALSIZE(v) (sizeof (struct trill_nickinfo) + \
	(sizeof (uint16_t) * (v)->tni_adjcount) + \
	(sizeof (uint16_t) * (v)->tni_dtrootcount) + \
	(((1<<12)/8) * (v)->tni_adjcount))

/*
 * This is a special value used in the sockaddr_dl "selector" field to denote
 * that the packet represents a Bridging PDU.  The core STP instance is not
 * defined on a VLAN, so this overload is safe.  All other selector values are
 * used for TRILL IS-IS PDUs to indicate VLAN ID.
 */
#define	TRILL_TCI_BPDU	0xFFFF

#endif
