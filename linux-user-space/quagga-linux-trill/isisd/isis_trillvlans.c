/*
 * IS-IS Rout(e)ing protocol - isis_trillvlans.c
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

#include <zebra.h>
#include <command.h>
#include "isisd/isis_kernel_trill.h"

#include "linklist.h"
#include "vty.h"
#include "dict.h"
#include "memory.h"
#include "log.h"
#include "if.h"
#include "prefix.h"
#include "jhash.h"
#include "stream.h"

#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_vlans.h"
#include "isisd/isis_trill.h"
#include "isisd/isisd.h"
#include "isisd/isis_pdu.h"
#include "isisd/bool.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_adjacency.h"

static int
compute_vlan_ranges(uint8_t *vlans, int *vlan, int *start, int *end)
{
  int vlan_set;
  int vlan_start = 0;
  int prev_vlan = 0;

  EACH_VLAN_R(vlans, *vlan, vlan_set)
    {
       if (vlan_start != 0) 
         {
	   if (vlan_set) 
	     {
               prev_vlan++;
	       assert (prev_vlan == (*vlan));
	       continue;
	     }
	   *start = vlan_start;
	   *end = prev_vlan;
	   return TRUE;
         }
       if (!vlan_set)
         continue;
       vlan_start = *vlan;
       prev_vlan = *vlan;
    }
  return FALSE;
}

static void
trill_del_enabled_vlans_listnode(void *data)
{
  XFREE(MTYPE_ISIS_TRILL_ENABLEDVLANS, data); 
}

static void
trill_compute_enabled_vlans_subtlv(struct isis_circuit *circuit)
{
  unsigned int bytenum;
  int span = 0;
  int endspan = 0;
  int size;
  uint8_t byte;
  uint8_t *byteptr;
  unsigned int foundstartvlan = FALSE;
  struct list *tlvdatalist;
  struct trill_enabled_vlans_listnode *data;

  tlvdatalist = list_new();
  tlvdatalist->del = trill_del_enabled_vlans_listnode;

  for (bytenum=0; bytenum < VLANS_ARRSIZE; bytenum++)
    {
       byte = circuit->vlans->enabled[bytenum];
       if (byte == 0)
         { 
	   if (!foundstartvlan)
             continue;
	   /* Check for large span, efficient to use a new sub-TLV */
           if (bytenum != (VLANS_ARRSIZE-1) && ((bytenum - endspan)
              <= (TLFLDS_LEN + sizeof (struct trill_enabledvlans_subtlv))))
             continue;
	 }
       else if (!foundstartvlan)
         {
           foundstartvlan = TRUE;
	   span = endspan = bytenum;
	   /* continue checking until we reach end of vlan bit array */
	   if (bytenum != (VLANS_ARRSIZE-1))
	     continue;
         }
       else 
         {
           assert(foundstartvlan);
           endspan = bytenum;
	   /* span shouldn't exceed max subtlv length */
	   if (bytenum != (VLANS_ARRSIZE-1) && (endspan - span) < MAX_VLANS_SUBTLV_LEN)
             continue;
	 }

       assert(foundstartvlan);
       assert(endspan >= span);
       size = sizeof(struct trill_enabled_vlans_listnode) + endspan - span + 1;
       data = XMALLOC(MTYPE_ISIS_TRILL_ENABLEDVLANS, size);
       data->len = size - sizeof(data->len);
       data->tlvdata.start_vlan = htons(span*NBBY);
       byteptr = (uint8_t *)&data[1];
       while (endspan - span >= 0)
         {
            assert(byteptr <= (((uint8_t *)data) + size));
            *byteptr = REVERSE_BYTE(circuit->vlans->enabled[span]);
	    span++;
	    byteptr++;
	 }
       listnode_add(tlvdatalist, data);
       foundstartvlan = FALSE;
    }

  if (listcount(tlvdatalist) > 0)
    circuit->vlans->enabled_vlans = tlvdatalist;
  else
    list_delete(tlvdatalist);
}

static void
trill_del_appvlanfwders_listnode(void *data)
{
  XFREE(MTYPE_ISIS_TRILL_VLANFWDERS, data); 
}

static int
trill_cmp_appvlanfwders(void *data1, void *data2)
{
  int vlan1;
  int vlan2;

  vlan1 = ntohs(((struct appointed_vlanfwder_subtlv *)data1)->vlan_start);
  vlan2 = ntohs(((struct appointed_vlanfwder_subtlv *)data2)->vlan_start);
  return (vlan1 < vlan2 ? -1:(vlan1 == vlan2 ? 0:1));
}

static void
trill_add_vlanfwder(struct isis_circuit *circuit, int start, int end,
    int nick, u_int32_t *hash)
{
  struct appointed_vlanfwder_subtlv *vlanfwder;

  vlanfwder = XMALLOC (MTYPE_ISIS_TRILL_VLANFWDERS,
      sizeof (struct appointed_vlanfwder_subtlv)); 
  vlanfwder->appointee_nick = nick;
  vlanfwder->vlan_start = htons(start);
  vlanfwder->vlan_end = htons(end);
  listnode_add_sort(circuit->vlans->appvlanfwders, vlanfwder);
  *hash = jhash(vlanfwder, sizeof (struct appointed_vlanfwder_subtlv), *hash);
}

static void
trill_compute_vlanfwders(struct isis_circuit *circuit, int *refresh)
{
  int vlan = VLAN_MIN;
  int start;
  int end;
  int nick;
  struct isis_adjacency *adj;
  struct list *adjdb;
  struct listnode *node;
  struct listnode *nextnode;
  struct appointed_vlanfwder_subtlv *vlanfwder;
  struct appointed_vlanfwder_subtlv *prevvlanfwder;
  u_int32_t prevhash = circuit->vlans->vlanfwdershash;
  u_int32_t newhash = 0;

  if (circuit->vlans->appvlanfwders != NULL) 
    {
      list_delete(circuit->vlans->appvlanfwders);
      circuit->vlans->appvlanfwders = NULL;
    }

  if (circuit->area->trill->nick.name == RBRIDGE_NICKNAME_NONE)
    {
      *refresh = FALSE;
      return;
    }

  circuit->vlans->appvlanfwders = list_new();
  circuit->vlans->appvlanfwders->del = trill_del_appvlanfwders_listnode;
  circuit->vlans->appvlanfwders->cmp = trill_cmp_appvlanfwders;

  /*
   * From the assigned VLAN forwarders among the adjacencies compute
   * appointed VLAN forwarder sub-TLVs. We exclude VLANs assigned to
   * ourself (the DR).
   */
  adjdb = circuit->u.bc.adjdb[TRILL_ISIS_LEVEL - 1];
  for (ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
    {
      vlan = VLAN_MIN;
      while (compute_vlan_ranges(adj->vlans->forwarder, &vlan, &start, &end))
        { 
          nick = sysid_to_nick(circuit->area, adj->sysid);
	  if (nick != RBRIDGE_NICKNAME_NONE)
            trill_add_vlanfwder(circuit, start, end, nick, &newhash);
	}
    }

  circuit->vlans->vlanfwdershash = newhash;
  *refresh = (newhash == prevhash ? FALSE:TRUE);

  /*
   * Compress the VLAN forwarder sub-TLVs by including missing VLANs in
   * the ranges. We use the sorted appvlanfwders list to quickly determine
   * the missing VLANs.
   */
  nick = 0;
  prevvlanfwder = NULL;
  for (ALL_LIST_ELEMENTS(circuit->vlans->appvlanfwders, node,
      nextnode, vlanfwder))
    {
      if (nick != 0 && vlanfwder->appointee_nick == nick)
        {
          prevvlanfwder->vlan_end = vlanfwder->vlan_end;
          trill_del_appvlanfwders_listnode(vlanfwder);
          list_delete_node(circuit->vlans->appvlanfwders, node);
	  continue;
        }
       nick = vlanfwder->appointee_nick;
       prevvlanfwder = vlanfwder;
    }
}

/*
 * Clear all our info on VLAN forwarders. 
 */
static void
trill_clear_vlanfwderinfo(struct isis_circuit *circuit)
{
  struct listnode *node;
  struct isis_adjacency *adj;

  /* Clear existing VLAN forwarder information */
  memset (circuit->vlans->forwarder, 0, VLANS_ARRSIZE);

  for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[TRILL_ISIS_LEVEL-1], node, adj))
    memset (adj->vlans->forwarder, 0, VLANS_ARRSIZE);
}

/*
 * TRILL function called when sending a hello frame on a TRILL circuit.
 * Sends additional VLAN Hellos for TRILL based on VLANs we see Hellos on
 * and from VLANs reported by other adjacencies. If we are DR then VLAN 
 * forwarders are also computed. 
 */
void
send_trill_vlan_hellos(struct isis_circuit *circuit)
{
  struct listnode *node;
  struct list *adjdb;
  struct isis_adjacency *adj;
  u_int8_t txvlans[VLANS_ARRSIZE];
  u_int8_t fwdvlans[VLANS_ARRSIZE];
  u_int vlan_set;
  int vlan;
  printf("vlan 0\n");
  if (circuit->circ_type != CIRCUIT_T_BROADCAST)
    return;

	printf("vlan 1\n");

  if (circuit->u.bc.is_dr[TRILL_ISIS_LEVEL - 1])
    {
      int refresh_lsp;

      /* Update circuit's designated VLAN */
      circuit->vlans->designated = circuit->vlans->our_designated;

      trill_clear_vlanfwderinfo(circuit);

      /* Appoint ourselves the VLAN forwarder for all our enabled VLANs */
      memcpy(circuit->vlans->forwarder, circuit->vlans->enabled, VLANS_ARRSIZE);

      /* Initialize the list of VLANs already assigned VLAN forwarder */
      memcpy(fwdvlans, circuit->vlans->enabled, VLANS_ARRSIZE);

      adjdb = circuit->u.bc.adjdb[TRILL_ISIS_LEVEL - 1];
      for (ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
        {
          /* 
           * If DR then appoint VLAN forwarder if no RBridge
           * has been appointed yet to forward the particular VLAN.
           */
          EACH_VLAN_SET(adj->vlans->enabled, vlan, vlan_set)
	   {
              if (CHECK_VLAN(fwdvlans, vlan))
                continue;

	      /* 
	       * Delegate the VLAN forwarding to the adjacency
	       * as no other RBridge is forwarding the VLAN.
	       */
              SET_VLAN(adj->vlans->forwarder, vlan);
	      SET_VLAN(fwdvlans, vlan);
	   }
        }

      /*
       * Based on the above VLAN forwarder appointments compute the VLAN
       * forwarder TLVs. If VLAN forwarder info has changed then we also
       * generate new LSPs.
       */ 
      trill_compute_vlanfwders(circuit, &refresh_lsp);
      if (refresh_lsp)
        lsp_regenerate_schedule (circuit->area);

      /* DR sends hellos on all its enabled VLANs */
      memcpy(txvlans, circuit->vlans->enabled, VLANS_ARRSIZE);
      SET_VLAN(txvlans, circuit->vlans->designated);
    }
  else 
    {
      /*
       * Non-DR sends hellos on designated VLAN (if enabled)
       * and on all VLANs it is the appointed forwarder.
       */
      bzero(txvlans, VLANS_ARRSIZE);
      if (CHECK_VLAN(circuit->vlans->enabled, circuit->vlans->designated))
        SET_VLAN(txvlans, circuit->vlans->designated);
      MERGE_VLANS(txvlans, vlan, circuit->vlans->forwarder);
    }

  /* Send hellos */
  EACH_VLAN_SET(txvlans, vlan, vlan_set)
    {
      circuit->vlans->tx_tci = vlan;
      send_hello(circuit, TRILL_ISIS_LEVEL);
    }

  /* Re-set circuit to use the link's designated VLAN for all IS-IS frames */
  circuit->vlans->tx_tci = VLANTCI(circuit->vlans->designated);

  /* Compute enabled VLANs subtlvs (performed only once) */
  if (circuit->vlans->enabled_vlans == NULL)
    trill_compute_enabled_vlans_subtlv(circuit);
}

static void
trill_del_vlansreachablelist(void *obj)
{
  XFREE (MTYPE_ISIS_TRILL_VLANSREACHABLE, obj);
}

/*
 * Compute VLAN filter lists by recursively going over the nodes in the DT.
 * If rvertex is set then we stop at the matching node in the DT otherwise
 * we stop until all children nodes are covered.
 */
static void
trill_compute_vlanfilterlist(struct isis_area *area, struct isis_spftree *rdtree,
  struct isis_vertex *vertex, struct isis_vertex *rvertex, uint8_t *filtermap)
{
  nicknode_t *nicknode;
  struct isis_vertex *cvertex;
  struct listnode *node;
  int idx;

  if (!listnode_lookup (rdtree->paths, vertex))
    return;
  if (vertex->type != VTYPE_NONPSEUDO_IS &&
      vertex->type != VTYPE_NONPSEUDO_TE_IS)
    return;

  nicknode = trill_nicknode_lookup(area, sysid_to_nick(area, vertex->N.id));
  if (nicknode == NULL)
	  return;

  MERGE_VLANS(filtermap, idx, nicknode->info.vlans_forwarder);

  if (rvertex != NULL &&
      (memcmp(vertex->N.id, rvertex->N.id, ISIS_SYS_ID_LEN) == 0))
    return;

  if (vertex->children != NULL)
    {
       for (ALL_LIST_ELEMENTS_RO(vertex->children, node, cvertex))
         trill_compute_vlanfilterlist(area, rdtree, cvertex,
		 rvertex, filtermap);
    }
}

/*
 * Creates TRILL VLAN filter lists for each of our adjacencies on 
 * the given node's distribution tree (DT). A TRILL VLAN filter list
 * for an adjacency on a distribution tree is the set of all VLANs that
 * are reachable downstream via the adjacency.
 */
void
trill_create_vlanfilterlist(struct isis_area *area, nicknode_t *nicknode)
{
  struct listnode *node;
  struct listnode *lnode;
  struct list *adjlist;
  struct isis_vertex *vertex;
  struct isis_vertex *rbvertex;
  struct isis_vertex *adjvertex;
  struct isis_spftree *rdtree;
  void *listdata;
  u_int16_t adjnick;
  nicknode_t *adjnode;
  int adjishead;
  struct list *vlanfilterlist;
  uint8_t *vlanfiltermap;

  if (nicknode == NULL) 
   {
     adjlist = area->trill->adjnodes;
     rdtree = area->spftree[TRILL_ISIS_LEVEL-1];
     if (area->trill->vlans_reachable != NULL)
       {
         list_delete(area->trill->vlans_reachable);
	 area->trill->vlans_reachable = NULL;
       }
   }
  else
   {
     adjlist = nicknode->adjnodes;
     rdtree = nicknode->rdtree;
     if (nicknode->vlans_reachable != NULL)
       {
         list_delete(nicknode->vlans_reachable);
	 nicknode->vlans_reachable = NULL;
       }
   }
  
  if (adjlist == NULL)
    return;

  vlanfilterlist = list_new();
  vlanfilterlist->del = trill_del_vlansreachablelist;

  /*
   * For each of the adjacencies compute VLAN filter list
   * on the DT with nicknode as the root.
   */
  for (ALL_LIST_ELEMENTS_RO (adjlist, node, listdata))
    {
      adjnick = (u_int16_t)(u_long)listdata;
      adjnode = trill_nicknode_lookup(area, adjnick);
      if (adjnode == NULL)
        {
          zlog_warn("trill_create_vlanfilterlist: adjlist node lookup failed.");
          list_delete(vlanfilterlist);
	  return;
	}

      /*
       * Determine if the adjacency is towards the parent (adjishead is TRUE)
       * or if the adjacency is our child node on the DT with nicknode as root.
       * Computing this direction determines how we search for reachable VLANs.
       */
      adjishead = FALSE;
      rbvertex = adjvertex = NULL;
      for (ALL_LIST_ELEMENTS_RO (rdtree->paths, lnode, vertex))
        {
          if (vertex->type != VTYPE_NONPSEUDO_IS &&
	      vertex->type != VTYPE_NONPSEUDO_TE_IS)
	    continue;
	  /* We found the adjacency node in the tree */
	  if (memcmp (vertex->N.id, adjnode->info.sysid, ISIS_SYS_ID_LEN) == 0)
            adjvertex = vertex;
	  /* We found our node in the DT with nicknode as root */
	  else if (memcmp (vertex->N.id, area->isis->sysid,
	      ISIS_SYS_ID_LEN) == 0)
	    rbvertex = vertex;
	  else
            continue;
	  /* If we found adjacency node first then we set adjishead to TRUE */
	  if (!adjishead  && adjvertex != NULL && rbvertex == NULL)
             adjishead = TRUE;
        }

      if (rbvertex == NULL || adjvertex == NULL)
        {
          zlog_warn("trill_create_vlanfilterlist: rbvertex adjvertex lookup failed.");
          list_delete(vlanfilterlist);
	  return;
        }

      vlanfiltermap = XCALLOC(MTYPE_ISIS_TRILL_VLANSREACHABLE, VLANS_ARRSIZE);
      if (adjishead == TRUE)
        {
	  /*
	   * If adjacency is head then compute VLAN filter lists from the root
	   * node and cover all nodes except all the children of the adjacency
	   * node. This covers all nodes in the tree except the adjacency
	   * branch.
	   */
          trill_compute_vlanfilterlist(area, rdtree,
		listgetdata(listhead (rdtree->paths)), adjvertex, vlanfiltermap);
        }
      else
        {
	  /*
	   * Adjacency is a child node of ours in the DT so to compute all the VLANs
	   * reachable through the child we just go over all the children nodes.
	   */
          trill_compute_vlanfilterlist(area, rdtree, adjvertex, NULL, vlanfiltermap);
        }
      listnode_add(vlanfilterlist, vlanfiltermap);
    }

  /* Must compute a VLAN filter map per adjacency */
  if (listcount(vlanfilterlist) == listcount(adjlist))
    {
       if (nicknode == NULL)
         area->trill->vlans_reachable = vlanfilterlist;
       else
         nicknode->vlans_reachable = vlanfilterlist;
    }
}

static void
trill_parse_enabled_vlans_subtlv(struct isis_adjacency *adj, u_int8_t *ptr,
	u_int8_t len)
{
   u_int8_t *end;
   struct trill_enabledvlans_subtlv *vlanmap;
   int vlan;
   u_int8_t byte;
   int idx;

   end = ptr + len;
   vlanmap = (struct trill_enabledvlans_subtlv *)ptr;
   vlan = VLANTCI(ntohs(vlanmap->start_vlan));

   ptr += sizeof (struct trill_enabledvlans_subtlv);
   while (ptr < end)
     {
        byte = *ptr++;
	if (byte == 0)
	  {
            vlan += NBBY;
            continue;
	  }

	for (idx = NBBY-1; idx >= 0; idx--)
	  {
            if ((byte & (1<<idx)) != 0)
              SET_VLAN(adj->vlans->enabled, vlan);
            vlan++;
	  }
     }
}

static void
inhibit_free(void *arg)
{
  XFREE (MTYPE_ISIS_TRILL_INHIB, arg);
}

static void
remove_inhib(struct isis_circuit *circuit, u_int16_t rxvlan)
{
  struct trill_inhibit_vlan *inhib;
  struct listnode *node, *nextnode;
  struct trill_circuit_vlans *cvlans = circuit->vlans;

  for (ALL_LIST_ELEMENTS (cvlans->inhibit_vlans, node, nextnode, inhib))
    {
      if (inhib->vlan == rxvlan)
	{
	  list_delete_node (cvlans->inhibit_vlans, node);
	  inhibit_free (inhib);
	}
    }
  if (list_isempty (cvlans->inhibit_vlans) && cvlans->inhibit_all == 0 &&
      cvlans->inhibit_thread != NULL)
    {
      thread_cancel (cvlans->inhibit_thread);
      cvlans->inhibit_thread = NULL;
    }
}

/*
 * Update the previous and new lists of VLANs for which we're the appointed
 * forwarder, based on the inhibited VLAN list.
 *
 * If the VLAN is set in the new list, then the inhibiting entry is still
 * valid; clear it from that new list.
 *
 * If the VLAN is not set in the new list, then the DR has revoked our
 * appointment, so the entry must be removed from the inhibit list, and treated
 * as though it were previously enabled.
 */
static void
check_disabled_inhib (struct isis_circuit *circuit, u_int8_t *prevvlans,
    u_int8_t *newvlans)
{
  struct trill_inhibit_vlan *inhib;
  struct listnode *node, *nextnode;
  struct trill_circuit_vlans *cvlans = circuit->vlans;

  for (ALL_LIST_ELEMENTS (cvlans->inhibit_vlans, node, nextnode, inhib))
    {
      if (CHECK_VLAN (newvlans, inhib->vlan))
	{
	  CLEAR_VLAN (newvlans, inhib->vlan);
	}
      else
	{
	  SET_VLAN (prevvlans, inhib->vlan);
	  list_delete_node (cvlans->inhibit_vlans, node);
	  inhibit_free (inhib);
	}
    }
  if (list_isempty (cvlans->inhibit_vlans) && cvlans->inhibit_all == 0 &&
      cvlans->inhibit_thread != NULL)
    {
      thread_cancel (cvlans->inhibit_thread);
      cvlans->inhibit_thread = NULL;
    }
}

static int
uninhibit_vlan (struct thread *thread)
{
  struct isis_circuit *circuit;
  struct trill_circuit_vlans *cvlans;
  struct listnode *node = NULL;
  struct trill_inhibit_vlan *inhib = NULL;
  int mintime, alltime;
  char reenabled = FALSE;
  time_t now;

  circuit = THREAD_ARG (thread);
  cvlans = circuit->vlans;

  now = time (NULL);
  alltime = cvlans->inhibit_all - now;
  if (cvlans->inhibit_all != 0 && alltime <= 0)
    {
      cvlans->inhibit_all = 0;
      reenabled = TRUE;
    }

  if (cvlans->inhibit_vlans != NULL)
    {
      while ((node = listhead (cvlans->inhibit_vlans)) != NULL)
	{
	  inhib = listgetdata (node);
	  if ((int)(inhib->reenable - now) > 0)
	    break;
	  reenabled = TRUE;
	  SET_VLAN (cvlans->forwarder, inhib->vlan);
	  list_delete_node (cvlans->inhibit_vlans, node);
	  inhibit_free (inhib);
	}
    }

  /* If we've reenabled something, then tell the kernel */
  if (reenabled && cvlans->inhibit_all == 0)
    trill_set_vlan_forwarder (circuit, cvlans->forwarder);

  /* Set up the next expiry */
  if (node == NULL && cvlans->inhibit_all == 0)
    cvlans->inhibit_thread = NULL;
  else
    {
      mintime = node == NULL ? alltime : inhib->reenable - now;
      if (cvlans->inhibit_all != 0 && alltime < mintime)
	mintime = alltime;
      cvlans->inhibit_thread = thread_add_timer (master, uninhibit_vlan,
	  circuit, mintime);
    }
  return ISIS_OK;
}

void
trill_inhib_all(struct isis_circuit *circuit)
{
  u_int8_t nullvlans[VLANS_ARRSIZE];
  struct trill_circuit_vlans *cvlans = circuit->vlans;
  int interval;

  memset (nullvlans, 0, sizeof nullvlans);
  trill_set_vlan_forwarder (circuit, nullvlans);

  interval = 15;
  cvlans->inhibit_all = time (NULL) + interval;

  THREAD_TIMER_ON (master, cvlans->inhibit_thread, uninhibit_vlan, circuit,
      interval);
}

static void
add_inhib(struct isis_circuit *circuit, u_int16_t rxvlan)
{
  struct trill_circuit_vlans *cvlans = circuit->vlans;
  struct trill_inhibit_vlan *inhib;
  int interval;

  interval = 5 * circuit->hello_interval[0];

  inhib = XMALLOC (MTYPE_ISIS_TRILL_INHIB, sizeof (*inhib));
  inhib->vlan = rxvlan;
  inhib->reenable = time (NULL) + interval;
  listnode_add (cvlans->inhibit_vlans, inhib);

  CLEAR_VLAN (cvlans->forwarder, rxvlan);
  if (cvlans->inhibit_all == 0)
    trill_set_vlan_forwarder (circuit, cvlans->forwarder);

  THREAD_TIMER_ON (master, cvlans->inhibit_thread, uninhibit_vlan, circuit,
      interval);
}

/*
 * Process incoming hello packets and process port capability TLVs.
 */
void
trill_process_hello(struct isis_adjacency *adj, struct list *portcaps)
{
  u_int8_t subtlv;
  u_int8_t *ptr;
  int len;
  int subtlv_len;
  struct listnode *node;
  struct port_capability_tlv *pcap;
  struct trill_vlanflags_subtlv *vlanflags = NULL;
  struct isis_circuit *circuit = adj->circuit;
  struct trill_circuit_vlans *cvlans = circuit->vlans;
  struct list *vlanfwders = NULL;
  int vflags_stlv_found = FALSE;
  int adj_is_dr = FALSE;
  int dis_nick = RBRIDGE_NICKNAME_NONE;

  if (circuit->circ_type != CIRCUIT_T_BROADCAST)
    return;

  if ((!circuit->u.bc.is_dr[TRILL_ISIS_LEVEL - 1]) &&
        memcmp(circuit->u.bc.l1_desig_is, adj->sysid, ISIS_SYS_ID_LEN) == 0) {
    adj_is_dr = TRUE;
    dis_nick = sysid_to_nick(circuit->area, adj->sysid);
  }

  memset(adj->vlans->enabled, 0, VLANS_ARRSIZE);
  for (ALL_LIST_ELEMENTS_RO (portcaps, node, pcap))
    {
       len = pcap->len;
       ptr = pcap->value;
       while (len > TLFLDS_LEN)
         {
            subtlv = *ptr; ptr++; len--;
	    subtlv_len = *ptr; ptr++; len--;
	    if (subtlv_len > len)
	      break;

	    switch (subtlv)
	      {
	      case PCSTLV_VLANS:
	         if (vflags_stlv_found == TRUE)
                   {
		     zlog_warn("trill_process_hello: received more than"
			    " one VLANs and Flags sub-TLV");
		     vlanflags = NULL;
		   }
		 else if (subtlv_len == PCSTLV_VLANS_LEN && vlanflags == NULL)
		   vlanflags = (struct trill_vlanflags_subtlv *)ptr;
		 len -= subtlv_len;
		 ptr += subtlv_len;
		 vflags_stlv_found = TRUE;
	         break;

	      case PCSTLV_APPFORWARDERS:
		 if ((subtlv_len % sizeof (struct appointed_vlanfwder_subtlv))
		     != 0)
		   {
		     zlog_warn("trill_process_hello: received invalid length:%d"
			" appointed forwarders sub-TLV", subtlv_len);
		     len -= subtlv_len;
		     ptr += subtlv_len;
		     break;
		   }
		 if (vlanfwders == NULL)
		   vlanfwders = list_new();
		 while (subtlv_len > 0)
		   {
		      listnode_add (vlanfwders, ptr);
		      ptr += sizeof (struct appointed_vlanfwder_subtlv);
		      subtlv_len -= sizeof (struct appointed_vlanfwder_subtlv);
		      len -= sizeof (struct appointed_vlanfwder_subtlv);
		   }
		 break;

	      case PCSTLV_ENABLEDVLANS:
	        if (subtlv_len < PCSTLV_ENABLEDVLANS_MIN_LEN)	
		  zlog_warn("trill_process_hello:"
		     " received invalid length (too small):%d"
		     " enabled VLANS sub-TLV", subtlv_len);
		else
		  trill_parse_enabled_vlans_subtlv(adj, ptr, subtlv_len);
	        len -= subtlv_len;
	        ptr += subtlv_len;
		break;

              default:
		 len -= subtlv_len;
		 ptr += subtlv_len;
		 break;
	      }
	 }
   }

  /* Process appointed VLAN forwarders sub-TLV */
  if (adj_is_dr)
    {
      u_int8_t *fwdvlans;
      u_int8_t *enabledvlans;
      u_int8_t prevfwdvlans[VLANS_ARRSIZE];
      u_int8_t appvlans[VLANS_ARRSIZE];
      struct appointed_vlanfwder_subtlv *appvlanfwder;
      struct isis_adjacency *nadj;
      int vlan;
      int vbyte;
      int vlanstart;
      int vlanend;
      u_char *sysid;

      memcpy(prevfwdvlans, cvlans->forwarder, VLANS_ARRSIZE);
      bzero(appvlans, sizeof (appvlans));

      /* Clear existing VLAN forwarder information */
      trill_clear_vlanfwderinfo(circuit);

      if (vlanfwders != NULL)
	for (ALL_LIST_ELEMENTS_RO (vlanfwders, node, appvlanfwder))
        {
	   /* Disregard any appointed VLAN forwarders to the DR */
           if (appvlanfwder->appointee_nick == dis_nick)
             continue;

           if (appvlanfwder->appointee_nick == circuit->area->trill->nick.name)
             {
               sysid = circuit->area->isis->sysid;
	       fwdvlans = cvlans->forwarder;
	       enabledvlans = cvlans->enabled;
	     }
	   else
	     {
	       sysid = nick_to_sysid (circuit->area, appvlanfwder->appointee_nick);
	       if (!sysid)
                 continue;
	       if ((nadj = isis_adj_lookup (sysid,
	           circuit->u.bc.adjdb[TRILL_ISIS_LEVEL-1])) == NULL)
	         continue;
	       fwdvlans = nadj->vlans->forwarder;
	       enabledvlans = nadj->vlans->enabled;
	     }

	   vlanstart = VLANTCI(ntohs(appvlanfwder->vlan_start));
	   vlanend = VLANTCI(ntohs(appvlanfwder->vlan_end));

	   /* Only accept VLANs the RBridge has advertised as enabled */
	   for (vlan = vlanstart; vlan <= vlanend; vlan++)
             if (CHECK_VLAN(enabledvlans, vlan)) 
	       {
                 SET_VLAN (fwdvlans, vlan);
                 SET_VLAN (appvlans, vlan);
	       }
        }

      /*
       * Determine the VLANs forwarded by the adj that is the DR: they are
       * all the VLANs enabled in the DR minus the VLANs that have appointed
       * VLAN forwarders on the link.
       */
      for (vbyte = 0; vbyte < VLANS_ARRSIZE; vbyte++)
        adj->vlans->forwarder[vbyte] =
	    adj->vlans->enabled[vbyte] & ~appvlans[vbyte];

      /*
       * If there are any inhibited VLANs, then check whether we've lost AF
       * status for them.  If so, then remove the inhibiting entry; it's no
       * longer valid.  If not, then remove from new forwarder list.
       */
      if (cvlans->inhibit_vlans != NULL)
	check_disabled_inhib (circuit, prevfwdvlans, cvlans->forwarder);

      /*
       * If the set of VLANs for which we've been appointed as forwarder has
       * changed, then regenerate new LSPs with new AF bits and deal with AF
       * status changes.
       */
      if (memcmp (prevfwdvlans, cvlans->forwarder, VLANS_ARRSIZE))
	{
	  int lost_any, vbit;
	  u_int8_t vval;
	  struct isis_circuit *ocir;

	  /*
	   * Compute the set of VLANs for which we're forwarder for some other
	   * circuit.
	   */
	  bzero (appvlans, sizeof (appvlans));
	  for (ALL_LIST_ELEMENTS_RO (circuit->area->circuit_list, node, ocir))
	    {
	      if (ocir != circuit)
		{
		  for (vbyte = 0; vbyte < VLANS_ARRSIZE; vbyte++)
		    appvlans[vbyte] |= ocir->vlans->forwarder[vbyte];
		}
	    }

	  /*
	   * For all VLANs where we've lost AF status, increment the lost
	   * counter and flush bridge forwarding entries learned directly over
	   * this circuit for this VLAN.
	   */
	  lost_any = FALSE;
	  for (vbyte = 0; vbyte < VLANS_ARRSIZE; vbyte++)
	    {
	      vval = prevfwdvlans[vbyte] & ~cvlans->forwarder[vbyte];
	      if (vval != 0)
		{
		  lost_any = TRUE;
		  for (vbit = 0; vbit < 8; vbit++)
		    {
		      if (vval & (1 << vbit))
			{
			  vlan = vbyte * 8 + vbit;
			  trill_port_flush (circuit, vlan);
			  if (!CHECK_VLAN (appvlans, vlan))
			    trill_nick_flush (circuit, vlan);
			}
		    }
		}
	    }
	  if (lost_any)
	    {
	      /* XXX carlsonj bump lost counter here */
	      trill_send_tc_bpdus (circuit);
	    }
	  lsp_regenerate_schedule (circuit->area);
	}
    }

  if (vlanflags != NULL)
    {
      int outervlan, rxvlan;

      /*
       * First get the flags stored in outer_vlan.  Check for a conflict if
       * we've been set as the appointed forwarder.
       */
      outervlan = ntohs (vlanflags->outer_vlan);
      rxvlan = VLANTCI (cvlans->rx_tci);
      if ((outervlan & TVFFO_AF) && CHECK_VLAN (cvlans->forwarder, rxvlan))
	{
	  /* The inhibited VLANs list is created just once; it's rare */
	  if (cvlans->inhibit_vlans == NULL)
	    {
	      cvlans->inhibit_vlans = list_new ();
	      cvlans->inhibit_vlans->del = inhibit_free;
	    }
	  /* Remove any stale entries for this VLAN. */
	  remove_inhib (circuit, rxvlan);
	  /* Now add a new entry for the VLAN */
	  add_inhib (circuit, rxvlan);
	}

      adj->vlans->designated = VLANTCI(ntohs(vlanflags->desig_vlan));
      outervlan = VLANTCI(outervlan);
      SET_VLAN(adj->vlans->seen, outervlan);
      SET_VLAN(adj->vlans->seen, VLANTCI(cvlans->rx_tci));

      /* If Adj is DR set circuit's designated link */
      if (adj_is_dr)
        {
	  cvlans->designated = adj->vlans->designated;
	  cvlans->tx_tci = VLANTCI(cvlans->designated);
	}
    }
  if (vlanfwders != NULL)
    list_delete (vlanfwders);
}

/* Add TRILL VLAN TLVs in TRILL IS-IS hellos */
int
tlv_add_trill_vlans(struct isis_circuit *circuit)
{
  struct stream *stream = circuit->snd_stream;
  struct trill_vlanflags_subtlv vlanflags;
  uint16_t outervlan;
  struct listnode *node;
  size_t tlvstart;
  struct trill_enabled_vlans_listnode *evlans;
  struct appointed_vlanfwder_subtlv *vlanfwder;
  int rc;

  if (circuit->circ_type != CIRCUIT_T_BROADCAST)
    return ISIS_OK;

  tlvstart = stream_get_endp (stream);
  rc = add_tlv(PORT_CAPABILITY, 0, NULL, stream);
  if (rc != ISIS_OK)
    return rc;

  outervlan = VLANTCI(circuit->vlans->tx_tci);
  if (CHECK_VLAN(circuit->vlans->forwarder, outervlan))
    outervlan |= TVFFO_AF;
  vlanflags.outer_vlan = htons(outervlan);
  vlanflags.desig_vlan = htons(circuit->vlans->designated);
  rc = add_subtlv (PCSTLV_VLANS, sizeof (vlanflags), (u_char *)&vlanflags,
      tlvstart, stream);
  if (rc != ISIS_OK)
    return rc;

  if (circuit->vlans->enabled_vlans != NULL)
    {
       for (ALL_LIST_ELEMENTS_RO(circuit->vlans->enabled_vlans, node, evlans))
         {
            rc = add_subtlv(PCSTLV_ENABLEDVLANS, evlans->len,
               (u_char *)&evlans->tlvdata, tlvstart, stream);
	    if (rc == ISIS_ERROR)
               return rc;
	    if (rc == ISIS_WARNING)
	      {
                 tlvstart = stream_get_endp (stream);
                 rc = add_tlv(PORT_CAPABILITY, 0, NULL, stream);
                 if (rc != ISIS_OK)
                   return rc;
                 rc = add_subtlv(PCSTLV_ENABLEDVLANS, evlans->len,
                    (u_char *)&evlans->tlvdata, tlvstart, stream);
                 if (rc != ISIS_OK)
                   return rc;
	      }
         }
    }

  if (!circuit->u.bc.is_dr[TRILL_ISIS_LEVEL - 1] ||
       circuit->vlans->appvlanfwders == NULL)
      return rc;

  for (ALL_LIST_ELEMENTS_RO(circuit->vlans->appvlanfwders, node,
      vlanfwder))
    {
       rc = add_subtlv(PCSTLV_APPFORWARDERS, sizeof(*vlanfwder),
          (u_char *)vlanfwder, tlvstart, stream);
       if (rc == ISIS_ERROR)
          return rc;
       if (rc == ISIS_WARNING)
         {
           tlvstart = stream_get_endp (stream);
           rc = add_tlv(PORT_CAPABILITY, 0, NULL, stream);
           if (rc != ISIS_OK)
             return rc;
           rc = add_subtlv(PCSTLV_APPFORWARDERS, sizeof(*vlanfwder),
              (u_char *)vlanfwder, tlvstart, stream);
           if (rc != ISIS_OK)
             return rc;
	 }
    }
  return rc;
}

/*
 * show trill circuits command to display TRILL circuit information.
 */
void
trill_circuits_print_all (struct vty *vty, struct isis_area *area)
{
  struct listnode *node;
  struct isis_circuit *circuit;
  int vlan_count = 0;
  int vlan_set;
  int vlan;

  if (area->circuit_list == NULL)
    return;

  for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
    {

      vty_out (vty, "%sInterface %s:%s", VTY_NEWLINE, circuit->interface->name, VTY_NEWLINE);
      vty_out (vty, "PVID:%d  Our Designated VLAN:%d Designated VLAN:%d%s",
	 circuit->vlans->pvid, circuit->vlans->designated, circuit->vlans->our_designated,
	 VTY_NEWLINE);

      vty_out (vty, "VLAN Forwarder: ");
      EACH_VLAN_SET(circuit->vlans->forwarder, vlan, vlan_set)
        {
	   vlan_count++;
	   if (vlan_count % 8 == 0)
             vty_out(vty, "%s               ", VTY_NEWLINE);
           vty_out (vty, "%d ", vlan); 
        }
      vty_out (vty, "%sEnabled VLANs: ", VTY_NEWLINE);
      vlan_count = 0;
      EACH_VLAN_SET(circuit->vlans->enabled, vlan, vlan_set)
        {
	   vlan_count++;
	   if (vlan_count % 8 == 0)
             vty_out(vty, "%s               ", VTY_NEWLINE);
           vty_out (vty, "%d ", vlan); 
        }
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

DEFUN (trill_isis_vlan,
       trill_isis_vlan_cmd,
       "trill isis vlan <1-4094>",
       "TRILL IS-IS commands\n"
       "Set TRILL IS-IS VLAN\n"
       "VLAN ID\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  SET_VLAN(circuit->vlans->enabled, atoi(argv[0]));
  return CMD_SUCCESS;
}

DEFUN (trill_isis_no_vlan,
       trill_isis_no_vlan_cmd,
       "trill isis no vlan <1-4094>",
       "TRILL IS-IS commands\n"
       "Clear TRILL IS-IS VLAN\n"
       "VLAN ID\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  CLEAR_VLAN(circuit->vlans->enabled, atoi(argv[0]));
  return CMD_SUCCESS;
}

DEFUN (trill_isis_pvid,
       trill_isis_pvid_cmd,
       "trill isis pvid <1-4094>",
       "TRILL IS-IS commands\n"
       "Set TRILL IS-IS Native VLAN (PVID) \n"
       "PVID\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->vlans->pvid = atoi(argv[0]);
  return CMD_SUCCESS;
}

void
install_trill_vlan_elements ()
{
	//vty_out(vty, "%s MOHSIN KAZMI              ", VTY_NEWLINE);
  install_element (INTERFACE_NODE, &trill_isis_vlan_cmd);
  install_element (INTERFACE_NODE, &trill_isis_no_vlan_cmd);
  install_element (INTERFACE_NODE, &trill_isis_pvid_cmd);
}
