/*
 * IS-IS Rout(e)ing protocol - isis_vlans.h
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

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#ifndef  ISIS_VLANS_H
#define	ISIS_VLANS_H

/* TRILL IS-IS VLANs */
#define NO_TCI 0
#define DFLT_VLAN 1
#define VLANS_SIZE (1<<12)
#define VLANS_ARRSIZE (VLANS_SIZE/NBBY)
#define VLAN_MAX 4094
#define VLAN_MIN 1
#define VLANTCI(p) ((p)&((VLANS_SIZE)-1))

#define VLANBIT(v) ((v) % NBBY)
#define VLANBYTE(v) ((v)/NBBY)
#define CHECK_VLAN(p, v) ((p)[VLANBYTE(v)] & (1<<VLANBIT(v)))
#define SET_VLAN(p, v) \
       	do { \
          if ((v) > 0) \
       	    ((p)[VLANBYTE(v)] |= 1<<VLANBIT(v)); \
	} while (0)
#define CLEAR_VLAN(p, v) \
	do { \
          if ((v) > 0) \
	    ((p)[VLANBYTE(v)] &= ~(1<<VLANBIT(v))); \
	} while (0)

#define EACH_VLAN(p, v, c) \
	for ( \
	(v) = VLAN_MIN; \
        ((v) <= VLAN_MAX) && \
	((c) = CHECK_VLAN((p), (v)), 1); \
	(v)++ )

#define EACH_VLAN_SET(p, v, c) \
	EACH_VLAN(p, v, c) \
        if (c) \

#define EACH_VLAN_R(p, v, c) \
	for (; \
        ((v) <= VLAN_MAX) && \
	((c) = CHECK_VLAN((p), (v)), 1); \
	(v)++ ) \

#define EACH_VLAN_SET_R(p, v, c) \
	EACH_VLAN_R(p, v, c) \
	if (c) \

#define MERGE_VLANS(p, v, z) \
	do { \
	  for ((v) = 0; (v) < VLANS_ARRSIZE; (v)++) \
	   (p)[(v)] |= (z)[(v)]; \
	} while (0)

/* source: http://graphics.stanford.edu/~seander/bithacks.html */
#define REVERSE_BYTE(v) ((uint8_t)((((v) * 0x0802LU & 0x22110LU) | \
       	((v) * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16));

#define MAX_VLANS_SUBTLV_LEN 240 /* 255 - bytes for type, len, start vlan */

/* Encoded enabled VLANs information for Hello PDU PCTLV_ENABLEDVLANS */
struct trill_enabled_vlans_listnode
{
  uint16_t len;
  struct trill_enabledvlans_subtlv tlvdata;
};

/*
 * Entry on the inhibit_vlan list.  This should be rarely used; it corresponds
 * to receipt of a Hello message from some other node claiming AF status for a
 * VLAN for which we were appointed.
 */
struct trill_inhibit_vlan
{
  time_t reenable;
  u_int16_t vlan;
};

struct trill_circuit_vlans
{
  u_int16_t pvid;	 /* Default/Native VLAN for untagged frames */
  u_int16_t designated;	 /* Designated VLAN for the circuit */
  u_int16_t our_designated; /* Our choice for Designated VLAN */
  u_int8_t enabled[VLANS_ARRSIZE]; /* VLANs we could be the forwarder */
  u_int8_t forwarder[VLANS_ARRSIZE]; /* VLANs for which we are the forwarder */
  u_int16_t rx_tci; /* PCP, CFI, VID */
  u_int16_t tx_tci; /* PCP, CFI, VID */
  struct list *enabled_vlans; /* List of enabled vlans TLV data */
  struct list *appvlanfwders; /* Appointed VLAN forwarders */
  u_int32_t vlanfwdershash;   /* Hash to check change in VLAN forwarders */
  struct list *inhibit_vlans;	/* VLANs inhibited by foreign AF flags (rare) */
  time_t inhibit_all;		/* All inhibited by root bridge (common) */
  struct thread *inhibit_thread;
};

struct trill_adj_vlans
{
  u_int16_t designated;   /* Designated VLAN when adj is DR */
  u_int8_t forwarder[VLANS_ARRSIZE];  /* VLANs the adj forwards */
  u_int8_t enabled[VLANS_ARRSIZE]; /* VLANs the adj has enabled */
  u_int8_t seen[VLANS_ARRSIZE]; /* VLANs we send hellos to adj */
};

struct trill_vlan_bridge_roots
{
    int vlan_start;
    int vlan_end;
    int bridge_roots_count;
    struct ether_addr *bridge_roots;
};

#endif /* ISIS_VLANS_H */
