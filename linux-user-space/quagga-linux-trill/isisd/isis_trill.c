/*
 * IS-IS Rout(e)ing protocol - isis_trill.c
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
//#include <libdladm.h>
//#include <libdllink.h>
//#include <libdlbridge.h>
//#include <libdlvlan.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>	/* the L2 protocols */
#include <netpacket/packet.h>
#include <libbridge.h>
#include <libmnl/libmnl.h>
#include "isisd/isis_kernel_trill.h"

#include "thread.h"
#include "linklist.h"
#include "stream.h"
#include "vty.h"
#include "log.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "if.h"
#include "table.h"
#include "privs.h"

#include "isisd/dict.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_vlans.h"
#include "isisd/isis_trill.h"
#include "isisd/isisd.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_events.h"
#include "isisd/bool.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_csm.h"


#define AF_TRILL 7
#define PF_TRILL AF_TRILL

extern struct zebra_privs_t isisd_privs;

/* Number of available (randomly-assigned) nicknames, not counting reserved */
static int nickavailcnt;

/* Vector with bits set to indicate nicknames in use */
static u_char nickbitvector[NICKNAMES_BITARRAY_SIZE];
#define	NICK_IS_USED(n)		(nickbitvector[(n)/8] & (1<<((n)%8)))
#define	NICK_SET_USED(n)	(nickbitvector[(n)/8] |= (1<<((n)%8)))
#define	NICK_CLR_USED(n)	(nickbitvector[(n)/8] &= ~(1<<((n)%8)))

/* Number of zero bits in each word of vector */
static u_char clear_bit_count[CLEAR_BITARRAY_SIZE];

//static dladm_handle_t dlhandle;
static char cfile_present = TRUE;

static nickdb_search_result trill_search_rbridge (struct isis_area *, nickinfo_t *, dnode_t **);
static void trill_dict_delete_nodes (dict_t *, dict_t *, void *, int);
static int trill_nick_conflict(nickinfo_t *, nickinfo_t *);
static int trill_parse_lsp (struct isis_lsp *, nickinfo_t *);

/* Test and mark a nickname in host byte order as allocated or free */
static int
trill_nickname_nickbitmap_op(u_int16_t nick, int update, int val)
{
  if (nick == RBRIDGE_NICKNAME_NONE || nick == RBRIDGE_NICKNAME_UNUSED)
    return FALSE;
  if (val)
    {
      if (NICK_IS_USED(nick))
	return TRUE;
      if (!update)
	return FALSE;
      NICK_SET_USED(nick);
      if (nick < RBRIDGE_NICKNAME_MINRES)
	nickavailcnt--;
      clear_bit_count[nick / CLEAR_BITARRAY_ENTRYLENBITS]--;
    }
  else
    {
      if (!NICK_IS_USED(nick))
	return TRUE;
      if (!update)
	return FALSE;
      NICK_CLR_USED(nick);
      if (nick < RBRIDGE_NICKNAME_MINRES)
	nickavailcnt++;
      clear_bit_count[nick / CLEAR_BITARRAY_ENTRYLENBITS]++;
    }
  return FALSE;
}

/*
 * trill_nickname_gen calls this function to randomly allocate a new nickname
 * in host byte order. We also keep track of allocated and in-use nicks.
 */
static u_int16_t
trill_nickname_alloc(void)
{
  u_int i, j, k;
  u_int16_t nick;
  u_int nicknum;
  u_int freenickcnt = 0;

  if (nickavailcnt < 1)
    return RBRIDGE_NICKNAME_NONE;
 
  /*
   * Note that rand() usually returns 15 bits, so we overlap two values to make
   * sure we're getting at least 16 bits (as long as rand() returns 8 bits or
   * more).  Using random() instead would be better, but isis_main.c uses
   * srand.
   */
  nicknum = ((rand() << 8) | rand()) % nickavailcnt;
  for ( i = 0; i < sizeof (clear_bit_count); i++ )
    {
      freenickcnt += clear_bit_count[i];
      if (freenickcnt <= nicknum)
        continue;
      nicknum -= freenickcnt - clear_bit_count[i];
      nick = i * CLEAR_BITARRAY_ENTRYLEN * 8;
      for ( j = 0; j < CLEAR_BITARRAY_ENTRYLEN; j++)
	{
	   for (k = 0; k < 8; k++, nick++)
	     {
		if (!NICK_IS_USED(nick) && nicknum-- == 0)
		  {
		    trill_nickname_nickbitmap_op (nick, TRUE, TRUE);
		    return nick;
		  }
	     }
	}
      break;
    }
  assert (0);
  return 0;
}

static void trill_nickname_reserve(u_int16_t nick_nbo)
{
  trill_nickname_nickbitmap_op(ntohs(nick_nbo), TRUE, TRUE);
}

static int is_nickname_used(u_int16_t nick_nbo)
{
  return trill_nickname_nickbitmap_op(ntohs(nick_nbo), FALSE, TRUE);
}

static void trill_nickname_free(u_int16_t nick_nbo)
{
  trill_nickname_nickbitmap_op(ntohs(nick_nbo), TRUE, FALSE);
}

static void
trill_nickname_gen(struct isis_area *area)
{
  u_int16_t nick;

  nick = trill_nickname_alloc();
  if (nick == RBRIDGE_NICKNAME_NONE)
    {
      zlog_err("RBridge nickname allocation failed.  No nicknames available.");
      abort();
    }
  else
    {
      area->trill->nick.name = htons(nick);
      //dladm_bridge_set_nick(area->trill->name, nick);
      if (isis->debugs & DEBUG_TRILL_EVENTS)
	zlog_debug("ISIS TRILL generated nick:%u", nick);
    }
}

static int
nick_cmp(const void *key1, const void *key2)
{
  return (memcmp(key1, key2, sizeof(u_int16_t)));
}

static int
sysid_cmp(const void *key1, const void *key2)
{
  return (memcmp(key1, key2, ISIS_SYS_ID_LEN));
}

void
trill_area_init(struct isis_area *area)
{
  u_int i;

  area->trill->status = 0;
  area->trill->nick.priority = DFLT_NICK_PRIORITY;
  area->trill->root_priority = TRILL_DFLT_ROOT_PRIORITY;
  area->trill->nickdb = dict_create(MAX_RBRIDGE_NODES, nick_cmp);
  area->trill->sysidtonickdb = dict_create(MAX_RBRIDGE_NODES, sysid_cmp);

  nickavailcnt = RBRIDGE_NICKNAME_MINRES - RBRIDGE_NICKNAME_NONE - 1;
  memset(nickbitvector, 0, sizeof(nickbitvector));
  for (i = 0; i < sizeof (clear_bit_count); i++)
    clear_bit_count[i] = CLEAR_BITARRAY_ENTRYLENBITS;

  /* These two are always reserved */
  NICK_SET_USED(RBRIDGE_NICKNAME_NONE);
  NICK_SET_USED(RBRIDGE_NICKNAME_UNUSED);
  clear_bit_count[RBRIDGE_NICKNAME_NONE / CLEAR_BITARRAY_ENTRYLENBITS]--;
  clear_bit_count[RBRIDGE_NICKNAME_UNUSED / CLEAR_BITARRAY_ENTRYLENBITS]--;

  isis_event_system_type_change (area, TRILL_ISIS_LEVEL);
  memset (area->trill->lspdb_acq_reqs, 0, sizeof(area->trill->lspdb_acq_reqs));
}

/*
 * Called from isisd to handle trill nickname command.
 * Nickname is user configured and in host byte order
 */
int
trill_area_nickname(struct isis_area *area, u_int16_t nickname)
{
  int savednick;

  if (nickname == RBRIDGE_NICKNAME_NONE)
    {
      /* Called from "no trill nickname" command */
      trill_nickname_gen (area);
      SET_FLAG (area->trill->status, TRILL_NICK_SET);
      SET_FLAG (area->trill->status, TRILL_AUTONICK);
      lsp_regenerate_schedule (area);
      return TRUE;
    }

  nickname = htons(nickname);
  savednick = area->trill->nick.name;
  area->trill->nick.name = nickname;
  area->trill->nick.priority |= CONFIGURED_NICK_PRIORITY;

  /*
   * Check if we know of another RBridge already using this nickname.
   * If yes check if it conflicts with the nickname in the database.
   */
  if (is_nickname_used(nickname))
    {
      nickinfo_t ni;
      dnode_t *dnode;
      nicknode_t *tnode;

      ni.nick = area->trill->nick;
      memcpy(ni.sysid, isis->sysid, ISIS_SYS_ID_LEN);
      if (trill_search_rbridge (area, &ni, &dnode) == FOUND)
        {
          assert (dnode);
          tnode = dnode_get (dnode);
          if (trill_nick_conflict (&(tnode->info), &ni))
            {
              trill_dict_delete_nodes (area->trill->nickdb,
		     area->trill->sysidtonickdb, &nickname, FALSE);
	    }
	  else
	    {
              /* 
	       * The other nick in our nickdb has greater priority so return
	       * fail, restore nick and let user configure another nick.
	       */
               area->trill->nick.name = savednick; 
	       area->trill->nick.priority &= ~CONFIGURED_NICK_PRIORITY;
               return FALSE;
	    }
	}
    }

  trill_nickname_reserve(nickname);
  SET_FLAG(area->trill->status, TRILL_NICK_SET);
  UNSET_FLAG(area->trill->status, TRILL_AUTONICK);
  lsp_regenerate_schedule (area);
  return TRUE;
}

static void
trill_nickname_priority_update(struct isis_area *area, u_int8_t priority)
{
  if (priority)
    {
      area->trill->nick.priority = priority;
      SET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
    }
  else
    {
      /* Called from "no trill nickname priority" command */
      area->trill->nick.priority = DFLT_NICK_PRIORITY;
      UNSET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
    }

  /*
   * Set the configured nickname priority bit if the
   * nickname was not automatically generated. 
   */
  if (!CHECK_FLAG(area->trill->status, TRILL_AUTONICK))
     area->trill->nick.priority |= CONFIGURED_NICK_PRIORITY;
  lsp_regenerate_schedule (area);
} 

static void
trill_nickinfo_del(nickinfo_t *ni)
{
  if (ni->dt_roots != NULL)
    list_delete (ni->dt_roots);
  if (ni->broots != NULL)
    list_delete (ni->broots);
}

static void
trill_dict_remnode ( dict_t *dict, dnode_t *dnode)
{
  nicknode_t *tnode;

  assert (dnode);
  tnode = dnode_get (dnode);
  assert(tnode->refcnt);
  tnode->refcnt--;
  if (tnode->refcnt == 0)
    {
      isis_spftree_del (tnode->rdtree);
      trill_nickinfo_del (&tnode->info);
      if (tnode->adjnodes)
        list_delete (tnode->adjnodes);
      if (tnode->vlans_reachable)
        list_delete (tnode->vlans_reachable);
      XFREE (MTYPE_ISIS_TRILL_NICKDB_NODE, tnode);
    }
  dict_delete_free (dict, dnode);
}

static void
trill_dict_free (dict_t *dict)
{
  dnode_t *dnode, *next;

  dnode = dict_first (dict);
  while (dnode)
    {
      next = dict_next (dict, dnode);
      trill_dict_remnode (dict, dnode);
      dnode = next;
    }
  dict_free_nodes (dict);
  dict_destroy (dict);
}

void
trill_area_free(struct isis_area *area)
{
  area->trill->status = 0;
  trill_dict_free (area->trill->nickdb);
  trill_dict_free (area->trill->sysidtonickdb);
  if (area->trill->fwdtbl)
    list_delete (area->trill->fwdtbl);
  if (area->trill->adjnodes)
    list_delete (area->trill->adjnodes);
  if (area->trill->dt_roots)
    list_delete (area->trill->dt_roots);
  if (area->trill->vlans_reachable)
    list_delete (area->trill->vlans_reachable);
}

/* 
 * Delete nickname node in both databases. First a lookup
 * of the node in first db by key1 and using the found node
 * a lookup of the node in second db is done. Asserts the
 * node if exists in one also exist in the second db.
 */
static void
trill_dict_delete_nodes (dict_t *dict1, dict_t *dict2,
		void *key1, int key2isnick)
{
  dnode_t *dnode1;
  dnode_t *dnode2;
  nicknode_t *tnode;
  int nickname;

  dnode1 = dict_lookup (dict1, key1);
  if (dnode1)
    {
      tnode = (nicknode_t *) dnode_get(dnode1);
      if (tnode)
        {
          if (key2isnick)
	    {
              dnode2 = dict_lookup (dict2, &(tnode->info.nick.name));
              nickname = tnode->info.nick.name;
	    }
          else 
            {
              dnode2 = dict_lookup (dict2, tnode->info.sysid);
	      nickname = *(int *)key1;
	    }
	  assert (dnode2);
          trill_dict_remnode (dict2, dnode2);

	  /* Mark the nickname as available */
	  trill_nickname_free(nickname);
	}
      trill_dict_remnode (dict1, dnode1);
    }
}

static void
trill_update_nickinfo (nicknode_t *tnode, nickinfo_t *recvd_nick)
{
  trill_nickinfo_del(&tnode->info);
  tnode->info = *recvd_nick;
  /* clear copied nick */
  memset(recvd_nick, 0, sizeof (*recvd_nick));
}

static void
trill_dict_create_nodes (struct isis_area *area, nickinfo_t *nick)
{
  nicknode_t *tnode;

  tnode = XCALLOC (MTYPE_ISIS_TRILL_NICKDB_NODE, sizeof(nicknode_t));
  tnode->info = *nick;
  dict_alloc_insert (area->trill->nickdb, &(tnode->info.nick.name), tnode);
  tnode->refcnt = 1;
  dict_alloc_insert (area->trill->sysidtonickdb, tnode->info.sysid, tnode);
  tnode->refcnt++;
  /* Mark the nickname as reserved */
  trill_nickname_reserve(nick->nick.name);
  tnode->rdtree = isis_spftree_new();
  /* clear copied nick */
  memset(nick, 0, sizeof (*nick));
}

/*
 * Update nickname information in the dictionary objects.
 */
static void
trill_nickdb_update ( struct isis_area *area, nickinfo_t *newnick)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  nickdb_search_result res;

  res = trill_search_rbridge (area, newnick, &dnode);
  if (res == NOTFOUND) 
    {
      trill_dict_create_nodes (area, newnick);
      return;
    }

  assert (dnode);
  tnode = dnode_get (dnode);

  /* If nickname & system ID of the node in our database match
   * the nick received then we don't have to change any dictionary
   * nodes. Update only the node information. Otherwise we update
   * the dictionary nodes.
   */
  if (res == DUPLICATE || res == PRIORITY_CHANGE_ONLY)
    {
      trill_update_nickinfo (tnode, newnick);
      return;
    }

  /*
   * If the RBridge has a new nick then update its nick only.
   */
  if (res == NICK_CHANGED) 
    {
      if (isis->debugs & DEBUG_TRILL_EVENTS)
        zlog_debug("ISIS TRILL storing new nick:%d from sysID:%s",
	   ntohs(tnode->info.nick.name), sysid_print(tnode->info.sysid));

      /* Delete the current nick in from our database */
      trill_dict_delete_nodes (area->trill->sysidtonickdb,
	      area->trill->nickdb, tnode->info.sysid, TRUE);
      /* Store the new nick entry */
      trill_dict_create_nodes (area, newnick);
    }
  else
    {
      /*
       * There is another RBridge using the same nick.
       * Determine which of the two RBridges should use the nick.
       * But first we should delete any prev nick associated
       * with system ID sending the newnick as it has just
       * announced a new nick.
       */
      trill_dict_delete_nodes (area->trill->sysidtonickdb,
	      area->trill->nickdb, newnick->sysid, TRUE);

      if (trill_nick_conflict (&(tnode->info), newnick))
        {
          /* 
	   * RBridge in tnode should choose another nick.
	   * Delete tnode from our nickdb and store newnick.
	   */
          if (isis->debugs & DEBUG_TRILL_EVENTS)
	    {
              zlog_debug("ISIS TRILL replacing conflict nick:%d of sysID:%s",
	        ntohs(tnode->info.nick.name), sysid_print(tnode->info.sysid));
	      zlog_debug("ISIS TRILL .....with nick:%d of sysID:%s", 
		ntohs(newnick->nick.name), sysid_print(newnick->sysid));
	    }

           trill_dict_delete_nodes (area->trill->sysidtonickdb,
	      area->trill->nickdb, tnode->info.sysid, TRUE);
           trill_dict_create_nodes (area, newnick);
        }
      else if (isis->debugs & DEBUG_TRILL_EVENTS)
        {
          zlog_debug("ISIS TRILL updated nick:%d of sysID:%s not accepted",
		ntohs(newnick->nick.name), sysid_print(newnick->sysid));
          zlog_debug("ISIS TRILL because of conflict with existing nick:%d of sysID:%s",
		ntohs(tnode->info.nick.name), sysid_print(tnode->info.sysid));
        }
    }
}

/* 
 * Search the nickname database and the sysidtonick database
 * to see if we know a rbridge that matches either the passed nickname 
 * or system ID or both. 
 */
static nickdb_search_result
trill_search_rbridge ( struct isis_area *area, nickinfo_t *ni,
		dnode_t **fndnode)
{
  dnode_t *dnode;
  nicknode_t *tnode;

  dnode = dict_lookup (area->trill->nickdb, &(ni->nick.name));
  if (dnode == NULL) 
    dnode = dict_lookup(area->trill->sysidtonickdb, ni->sysid);
  if (dnode == NULL)
    return NOTFOUND;

  tnode = (nicknode_t *) dnode_get (dnode);
  assert (tnode != NULL);
  assert (tnode->refcnt);

  if (fndnode)
    *fndnode = dnode;
  if ( memcmp(&(tnode->info.sysid), ni->sysid, ISIS_SYS_ID_LEN) != 0)
    return FOUND;
  if (tnode->info.nick.name != ni->nick.name)
    return NICK_CHANGED;
  if (tnode->info.nick.priority != ni->nick.priority)
    return PRIORITY_CHANGE_ONLY;
  /* Exact nick and sysid match */
  return DUPLICATE; 
}

/*
 * trill_nick_conflict: nickname conflict resolution fn
 * Returns FALSE when nick1 has greater priority and
 * returns TRUE when nick1 has lower priority and 
 * must be changed.
 */
static int
trill_nick_conflict(nickinfo_t *nick1, nickinfo_t *nick2)
{
  assert (nick1->nick.name == nick2->nick.name);

  /* If nick1 priority is greater (or) 
   * If priorities match & nick1 sysid is greater 
   * then nick1 has higher priority
   */
  if ((nick1->nick.priority > nick2->nick.priority) ||
      (nick1->nick.priority == nick2->nick.priority && 
       (sysid_cmp (nick1->sysid, nick2->sysid) > 0)))
    return FALSE;

  return TRUE;
}

/*
 * Remove nickname from the database.
 * Called from lsp_destroy or when lsp is missing a nickname TLV.
 */
void
trill_nick_destroy(struct isis_lsp *lsp)
{
  u_char *lsp_id;
  nickinfo_t ni;
  struct isis_area *area;
  int delnick;

  if (!isis->trill_active)
    return;

  area = listgetdata(listhead (isis->area_list));
  lsp_id = lsp->lsp_header->lsp_id;

  /* 
   * If LSP is our own or is a Pseudonode LSP (and we do not
   * learn nicks from Pseudonode LSPs) then no action is needed.
   */
  if ((memcmp (lsp_id, isis->sysid, ISIS_SYS_ID_LEN) == 0)
       || (LSP_PSEUDO_ID(lsp_id) != 0))
    return;

  if (!trill_parse_lsp (lsp, &ni) ||
	  (ni.nick.name == RBRIDGE_NICKNAME_NONE))
    {
      /* Delete the nickname associated with the LSP system ID
       * (if any) that did not include router capability TLV or
       * TRILL flags or the nickname in the LSP is unknown. This
       * happens when we recv a LSP from RBridge that just re-started
       * and we have to delete the prev nick associated with it.
       */
      trill_dict_delete_nodes (area->trill->sysidtonickdb,
	      area->trill->nickdb, lsp_id, TRUE);
      if (isis->debugs & DEBUG_TRILL_EVENTS)
        zlog_debug("ISIS TRILL removed any nickname associated"
	      " with sysID:%s LSP seqnum:0x%08x pseudonode:%x",
	      sysid_print(lsp_id), ntohl (lsp->lsp_header->seq_num),
	      LSP_PSEUDO_ID(lsp_id) );
      trill_nickinfo_del (&ni);
      return;
    }
      
  memcpy(ni.sysid, lsp_id, ISIS_SYS_ID_LEN);
  delnick = ntohs(ni.nick.name);
  if (delnick != RBRIDGE_NICKNAME_NONE &&
      delnick != RBRIDGE_NICKNAME_UNUSED &&
      ni.nick.priority >= MIN_RBRIDGE_PRIORITY)
    {
      /* Only delete if the nickname was learned
       * from the LSP by ensuring both system ID
       * and nickname in the LSP match with a node
       * in our nick database.
       */
      if (trill_search_rbridge (area, &ni, NULL) == DUPLICATE)
        {
           trill_dict_delete_nodes (area->trill->sysidtonickdb,
	      area->trill->nickdb, ni.sysid, TRUE);
           if (isis->debugs & DEBUG_TRILL_EVENTS)
              zlog_debug("ISIS TRILL removed nickname:%d associated"
		" with sysID:%s LSP ID:0x%08x pseudonode:%x",
		delnick, sysid_print(lsp_id),
		ntohl (lsp->lsp_header->seq_num),
	        LSP_PSEUDO_ID(lsp_id) );
	}
    }
  else if (isis->debugs & DEBUG_TRILL_EVENTS)
    zlog_debug("ISIS TRILL nick destroy invalid nickname:%d"
        " from sysID:%s", delnick, sysid_print(lsp_id) );
  trill_nickinfo_del (&ni);
}

static void
trill_nick_recv(struct isis_area *area, nickinfo_t *other_nick)
{
  nickinfo_t ournick;
  int nickchange = FALSE;

  ournick.nick = area->trill->nick;
  memcpy (ournick.sysid, area->isis->sysid, ISIS_SYS_ID_LEN);

  if (isis->debugs & DEBUG_TRILL_EVENTS)
    zlog_debug("ISIS TRILL nick recv:%d from sysID:%s",
      ntohs (other_nick->nick.name), sysid_print(other_nick->sysid) );

  /* Check for reserved TRILL nicknames that are not valid for use */
  if ((other_nick->nick.name == RBRIDGE_NICKNAME_NONE) ||
	  (other_nick->nick.name == RBRIDGE_NICKNAME_UNUSED)) 
    {
       zlog_warn("ISIS TRILL received reserved nickname:%d from sysID:%s",
          ntohs (other_nick->nick.name), sysid_print(other_nick->sysid) );
       return;
    }

  if (!(other_nick->flags & TRILL_FLAGS_V0))
    {
      zlog_info ("ISIS TRILL nick %d doesn't support V0 headers; flags %02X",
	  ntohs (other_nick->nick.name), other_nick->flags);
      return;
    }

  /* Check for conflict with our own nickname */
  if (other_nick->nick.name == area->trill->nick.name)
    {
       /* Check if our nickname has lower priority or our
	* system ID is lower, if not we keep our nickname.
	*/
       if (!(nickchange = trill_nick_conflict (&ournick, other_nick)))
          return;
    }

  /* Update our nick database */
  trill_nickdb_update (area, other_nick);

  if (nickchange)
     {
       /* We choose another nickname */
        trill_nickname_gen (area);
        SET_FLAG(area->trill->status, TRILL_AUTONICK);

	/* If previous nick was configured remove the bit 
	 * indicating nickname was configured  (0x80) */
	area->trill->nick.priority &= ~CONFIGURED_NICK_PRIORITY;

	/* Regenerate our LSP to advertise the new nickname */
	lsp_regenerate_schedule (area);

        if (isis->debugs & DEBUG_TRILL_EVENTS)
          zlog_debug("ISIS TRILL our nick changed to:%d",
	    ntohs (area->trill->nick.name));
     }
}

void
trill_lspdb_acquire_event(struct isis_circuit *circuit, lspdbacq_state caller)
{
  struct isis_area *area;
  u_int8_t cid;
  struct listnode *cnode;
  int done = TRUE;

  area = circuit->area;
  cid = circuit->circuit_id;

  if (!isis->trill_active)
    return;
  if (CHECK_FLAG (area->trill->status, (TRILL_LSPDB_ACQUIRED | TRILL_NICK_SET)))
    return;
 
  switch(caller)
    {
    case CSNPRCV:
    case CSNPSND:
      LSPDB_ACQTRYINC (area, cid);
      break;
    case PSNPSNDTRY:
      if (circuit->circ_type != CIRCUIT_T_BROADCAST)
        LSPDB_ACQTRYINC (area, cid);
      break;
    default:
      break;
    }

  for (ALL_LIST_ELEMENTS_RO (area->circuit_list, cnode, circuit))
    {
      cid = circuit->circuit_id;

      /* 
       * If on any circuit we have reached max tries
       * we consider LSP DB acquisition as done and
       * assign ourselves a nickname
       */
      if (LSPDB_ACQTRYVAL (area, cid) > MAX_LSPDB_ACQTRIES)
        {
          done = TRUE;
	  break;
        }

      /* 
       * If on any circuits we haven't received min LSPDB update
       * packets then we wait until we hit max tries above
       * on any circuit. If not it can only mean there is no other
       * IS-IS instance on any of our circuits and so we wait.
       */
      if (LSPDB_ACQTRYVAL (area, cid) < MIN_LSPDB_ACQTRIES)
        done = FALSE;
    }

  if (isis->debugs & DEBUG_TRILL_EVENTS)
    zlog_debug("ISIS TRILL LSPDB acquire event:%d cid:%d, done:%d",
	    caller, cid, done);

  if (done)
    {
      /* 
       * LSP DB acquired state, sufficient to start
       * advertising our nickname. Set flags, pick a
       * new nick if necessary and trigger new LSPs with the nick.
       */
      SET_FLAG (area->trill->status, TRILL_LSPDB_ACQUIRED);
      if (ntohs(area->trill->nick.name) == RBRIDGE_NICKNAME_NONE)
	{
	  trill_nickname_gen (area);
	  SET_FLAG (area->trill->status, TRILL_NICK_SET);
	  SET_FLAG (area->trill->status, TRILL_AUTONICK);
	  lsp_regenerate_schedule (area);
	}
    }
}

static void
trill_del_broot_node(void *data)
{
  struct trill_vlan_bridge_roots *broot = data;
  if (broot->bridge_roots != NULL)
    XFREE (MTYPE_ISIS_TRILL_BRIDGE_ROOTIDS, broot->bridge_roots);
  XFREE (MTYPE_ISIS_TRILL_VLANBRIDGE_ROOTS, broot);
}

/*
 * Returns TRUE if a nickname was received in the parsed LSP
 */
static int
trill_parse_lsp (struct isis_lsp *lsp, nickinfo_t *recvd_nick)
{
  struct listnode *node;
  struct router_capability *rtr_cap;
  struct trill_vlan_bridge_roots *broot;
  struct trill_vlan_bridge_roots_subtlv *brootstlv;
  u_int8_t subtlvs_len;
  u_int8_t subtlv;
  u_int8_t subtlv_len;
  u_int8_t stlvlen;
  u_int16_t dtroot_nick;
  int nick_recvd = FALSE;
  int flags_recvd = FALSE;
  int broots_recvd = FALSE;
  u_char *pnt;
  int idx;

  memset(recvd_nick, 0, sizeof(nickinfo_t));
  if (lsp->tlv_data.router_capabilities == NULL)
    return FALSE;

  memcpy (recvd_nick->sysid, lsp->lsp_header->lsp_id, ISIS_SYS_ID_LEN);
  recvd_nick->root_priority = TRILL_DFLT_ROOT_PRIORITY;

  for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.router_capabilities, node, rtr_cap))
    {
       if (rtr_cap->len < ROUTER_CAPABILITY_MIN_LEN)
         continue;

       subtlvs_len = rtr_cap->len - ROUTER_CAPABILITY_MIN_LEN;
       pnt = ((u_char *)rtr_cap) + sizeof(struct router_capability);
       while (subtlvs_len >= TLFLDS_LEN)
         {
           subtlv = *(u_int8_t *)pnt++; subtlvs_len--;
	   subtlv_len = *(u_int8_t *)pnt++; subtlvs_len--;
	   if (subtlv_len > subtlvs_len)
	     {
               zlog_warn("ISIS trill_parse_lsp received invalid router"
	         " capability subtlvs_len:%d subtlv_len:%d", 
		 subtlvs_len, subtlv_len);
               break;
	     }

	   switch (subtlv)
	     {
	     case RCSTLV_TRILL_FLAGS:
	       /* var. len with min. one octet and must be included in each link state PDU */
	       if (!flags_recvd && subtlv_len >= TRILL_FLAGS_SUBTLV_MIN_LEN)
                 {
	           recvd_nick->flags = *(u_int8_t *)pnt;
	           flags_recvd = TRUE;
		 }
	       else
	         { 
		   if (flags_recvd)
                     zlog_warn("ISIS trill_parse_lsp multiple TRILL"
				    " flags sub-TLVs received");
		   else
                     zlog_warn("ISIS trill_parse_lsp invalid len:%d"
				    " of TRILL flags sub-TLV", subtlv_len);
		 }
	       pnt += subtlv_len;
	       subtlvs_len -= subtlv_len;
	       break;

	     case RCSTLV_TRILL_NICKNAME:
	       stlvlen = subtlv_len;
	       if (!nick_recvd && subtlv_len >= TRILL_NICKNAME_SUBTLV_MIN_LEN)
                 {
		   struct trill_nickname_subtlv *tn;

		   tn = (struct trill_nickname_subtlv *)pnt;
                   recvd_nick->nick.priority = tn->tn_priority;
	           recvd_nick->nick.name = tn->tn_nickname;
		   recvd_nick->root_priority = ntohs(tn->tn_trootpri);
		   recvd_nick->root_count = ntohs(tn->tn_treecount);
	           nick_recvd = TRUE;
		 }
	       else
	         { 
		   if (nick_recvd)
                     zlog_warn("ISIS trill_parse_lsp multiple TRILL"
				    " nick sub-TLVs received");
		   else
                     zlog_warn("ISIS trill_parse_lsp invalid len:%d"
				    " of TRILL nick sub-TLV", subtlv_len);
		 }
               pnt += stlvlen;
               subtlvs_len -= subtlv_len;
	       break;

	     case RCSTLV_TRILL_TREE_ROOTS:
               if (subtlv_len % TRILL_NICKNAME_LEN)
                 {
                   pnt += subtlv_len;
		   subtlvs_len -= subtlv_len;
                   zlog_warn("ISIS trill_parse_lsp received invalid"
		     " distribution tree roots subtlv_len:%d", subtlv_len);
		   break;
		 }
	       if (recvd_nick->dt_roots == NULL)
                 recvd_nick->dt_roots = list_new();
	       stlvlen = subtlv_len;  /* zero len possible */
	       while (stlvlen > 0)
	         {
                   dtroot_nick = *(u_int16_t *)pnt;
		   pnt += TRILL_NICKNAME_LEN;
		   subtlvs_len -= TRILL_NICKNAME_LEN;
		   stlvlen -= TRILL_NICKNAME_LEN;

                   if (dtroot_nick == RBRIDGE_NICKNAME_NONE ||
		       dtroot_nick == RBRIDGE_NICKNAME_UNUSED)
		     {
                       zlog_warn("ISIS trill_parse_lsp received invalid"
			 " distribution tree root nick:%d.", dtroot_nick);
                       continue;
		     }
		   listnode_add (recvd_nick->dt_roots, (void *)(u_long)*(u_int16_t *)pnt);
	         }
	       break;

	     case RCSTLV_TRILL_VLANSROOTS:
	       if (subtlv_len < TRILL_VLANSNBRIROOTS_SUBTLV_MIN_LEN)
                 {
                   pnt += subtlv_len;
		   subtlvs_len -= subtlv_len;
                   zlog_warn("ISIS trill_parse_lsp received invalid"
		     " vlans and bridge roots subtlv_len:%d", subtlv_len);
		   break;
		 }

	       if (recvd_nick->broots == NULL)
                 {
                   recvd_nick->broots = list_new();
		   recvd_nick->broots->del = trill_del_broot_node;
		 }

	       broot = XCALLOC (MTYPE_ISIS_TRILL_VLANBRIDGE_ROOTS,
		       sizeof(struct trill_vlan_bridge_roots));
	       brootstlv = (struct trill_vlan_bridge_roots_subtlv *)pnt;
	       broot->vlan_start = VLANTCI(ntohs(brootstlv->vlan_start));
	       broot->vlan_end = VLANTCI(ntohs(brootstlv->vlan_end));
	       pnt += TRILL_VLANSNBRIROOTS_SUBTLV_MIN_LEN;
	       subtlvs_len -= TRILL_VLANSNBRIROOTS_SUBTLV_MIN_LEN;
	       subtlv_len -= TRILL_VLANSNBRIROOTS_SUBTLV_MIN_LEN;
	       if (subtlv_len % ETH_ALEN)
                 {
                   pnt += subtlv_len;
		   subtlvs_len -= subtlv_len;
                   zlog_warn("ISIS trill_parse_lsp received invalid"
		     " vlans and bridge roots subtlv_len:%d", subtlv_len);
		   XFREE (MTYPE_ISIS_TRILL_VLANBRIDGE_ROOTS, broot);
		   break;
		 }

	       if (subtlv_len > 0)
                 {
	            broot->bridge_roots_count = subtlv_len / ETH_ALEN;
	            broot->bridge_roots = XMALLOC (MTYPE_ISIS_TRILL_BRIDGE_ROOTIDS, subtlv_len);
	            memcpy(broot->bridge_roots, pnt, subtlv_len);
	            pnt += subtlv_len;
		 }
	       subtlvs_len -= subtlv_len;
	       listnode_add (recvd_nick->broots, broot);
	       broots_recvd = TRUE;
	       break;

	     default:
	       pnt += subtlv_len;
	       subtlvs_len -= subtlv_len;
	       break;
	     }
         }
    }

  if (recvd_nick->broots != NULL && broots_recvd == TRUE)
    {
      for (ALL_LIST_ELEMENTS_RO(recvd_nick->broots, node, broot))
        {
           for (idx=broot->vlan_start; idx <=broot->vlan_end; idx++)
	      SET_VLAN(recvd_nick->vlans_forwarder, idx);
        }
    }
  return (nick_recvd);
}

void
trill_parse_router_capability_tlvs (struct isis_area *area,
		struct isis_lsp *lsp)
{
  nickinfo_t recvd_nick;

  /* Return if LSP is our own or is a pseudonode LSP */
  if ((memcmp (lsp->lsp_header->lsp_id, isis->sysid, ISIS_SYS_ID_LEN) == 0)
       || (LSP_PSEUDO_ID(lsp->lsp_header->lsp_id) != 0))
    return;

  if (trill_parse_lsp (lsp, &recvd_nick))
    {
      /* Parsed LSP correctly but process only if nick is not unknown */
      if (recvd_nick.nick.name != RBRIDGE_NICKNAME_NONE)
         trill_nick_recv (area, &recvd_nick);
    }
  else 
    {
       /* if we have a nickname stored from this RBridge we remove it as this 
	* LSP without a nickname likely indicates the RBridge has re-started 
	* and hasn't chosen a new nick.
        */
       trill_nick_destroy (lsp);
    }

  trill_nickinfo_del (&recvd_nick);
}

/* Lookup nickname when given a system ID */
u_int16_t
sysid_to_nick(struct isis_area *area, u_char *sysid)
{
  dnode_t *dnode;
  nicknode_t *tnode;

  dnode = dict_lookup (area->trill->sysidtonickdb, sysid);
  if (dnode == NULL)
    return 0;
  tnode = (nicknode_t *) dnode_get (dnode);
  return tnode->info.nick.name;
}

nicknode_t *
trill_nicknode_lookup(struct isis_area *area, uint16_t nick)
{
  dnode_t *dnode;
  nicknode_t *tnode;

  dnode = dict_lookup (area->trill->nickdb, &nick);
  if (dnode == NULL) 
    return (NULL);
  tnode = (nicknode_t *) dnode_get (dnode);
  return (tnode);
}

/* Lookup system ID when given a nickname */
u_char *
nick_to_sysid(struct isis_area *area, u_int16_t nick) 
{
  nicknode_t *tnode;

  tnode = trill_nicknode_lookup(area, nick);
  if (tnode == NULL)
    return (NULL);
  return tnode->info.sysid;
}

static void
trill_destroy_nickfwdtable(void *obj)
{
  XFREE (MTYPE_ISIS_TRILL_FWDTBL_NODE, obj);
}

/*
 * Creates a nickname forwarding table for TRILL. 
 * Forwarding table is stored in the per-area fwdtbl list. 
 */
static void
trill_create_nickfwdtable(struct isis_area *area)
{
  struct listnode *node;
  struct isis_vertex *vertex;
  struct isis_adjacency *adj;
  struct list *fwdlist = NULL;
  nickfwdtblnode_t *fwdnode;
  struct isis_spftree *rdtree;
  int firstnode = TRUE; 

  rdtree = area->spftree [TRILL_ISIS_LEVEL-1];
  if (area->trill->fwdtbl)
    list_delete (area->trill->fwdtbl);
  area->trill->fwdtbl = NULL;

  for (ALL_LIST_ELEMENTS_RO (rdtree->paths, node, vertex))
    {
      if (firstnode)
        {
          /* first node in path list is us */
          fwdlist = list_new();
	  fwdlist->del = trill_destroy_nickfwdtable;
	  firstnode = FALSE;
	  continue;
        }
      if (vertex->type != VTYPE_NONPSEUDO_IS &&
	  vertex->type != VTYPE_NONPSEUDO_TE_IS)
	continue;

      if (listhead (vertex->Adj_N) && 
           (adj = listgetdata (listhead (vertex->Adj_N))))
        {
          fwdnode = XCALLOC (MTYPE_ISIS_TRILL_FWDTBL_NODE, sizeof(nickfwdtblnode_t));
          fwdnode->dest_nick = sysid_to_nick (area, vertex->N.id);
          memcpy(fwdnode->adj_snpa, adj->snpa, sizeof(fwdnode->adj_snpa));
	  fwdnode->interface = adj->circuit->interface;
          listnode_add (fwdlist, fwdnode);
        }
      else
        {
          list_delete (fwdlist);
	  fwdlist = NULL;
	  return;
	}
    }

  area->trill->fwdtbl = fwdlist;
}

static void
trill_fwdtbl_print (struct vty *vty, struct isis_area *area)
{ 
  struct listnode *node;
  nickfwdtblnode_t *fwdnode;

  if (area->trill->fwdtbl == NULL)
    return;

  vty_out(vty, "RBridge        nickname   interface  nexthop MAC%s", VTY_NEWLINE); 
  for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, node, fwdnode))
    {
      vty_out (vty, "%-15s   %-5d      %-5s  %-15s%s",
               print_sys_hostname (nick_to_sysid (area, fwdnode->dest_nick)),
	       ntohs (fwdnode->dest_nick), fwdnode->interface->name,
	       snpa_print (fwdnode->adj_snpa), VTY_NEWLINE);
    }
}

static void
trill_add_nickadjlist(struct isis_area *area, struct list *adjlist,
		 struct isis_vertex *vertex)
{
  u_int16_t nick;

  nick = sysid_to_nick (area, vertex->N.id);
  if (!nick)
    return;
  if (listnode_lookup (adjlist, (void *)(u_long)nick) != NULL)
    return;
  listnode_add (adjlist, (void *)(u_long)nick);
}

/*
 * Creates TRILL nickname adjacency lists for each distribution tree (DT).
 * An adjacency list consists of our (this RBridge) adjacent nodes in the 
 * campus that are present on the DT paths. It is a subset of our adjacent 
 * nodes. The adjacency list for a distribution tree is stored inside the 
 * root dict node of the distribution tree in our nickname database.
 */
static void
trill_create_nickadjlist(struct isis_area *area, nicknode_t *nicknode)
{
  struct listnode *node;
  struct listnode *cnode;
  struct isis_vertex *vertex;
  struct isis_vertex *cvertex;
  struct isis_vertex *rbvertex = NULL;
  struct list *adjlist;
  struct list *childlist;
  struct isis_spftree *rdtree;

  if (nicknode == NULL) 
   {
     rdtree = area->spftree[TRILL_ISIS_LEVEL-1];
     if (area->trill->adjnodes)
        list_delete (area->trill->adjnodes);
     area->trill->adjnodes = NULL;
   }
  else
   {
     rdtree = nicknode->rdtree;
     if (nicknode->adjnodes)
       list_delete (nicknode->adjnodes);
     nicknode->adjnodes = NULL;
   }

  /* Find our node in the distribution tree first */
  for (ALL_LIST_ELEMENTS_RO (rdtree->paths, node, vertex))
    {
      if (vertex->type != VTYPE_NONPSEUDO_IS &&
	  vertex->type != VTYPE_NONPSEUDO_TE_IS)
	continue;
      if (memcmp (vertex->N.id, area->isis->sysid, ISIS_SYS_ID_LEN) == 0)
        {
          rbvertex = vertex;
	  break;
	}
    }

  /* Determine adjacencies by looking up the parent & child nodes */
  if (rbvertex)
    {
      adjlist = list_new();

      if (rbvertex->parent)
        {
	  /* 
	   * Find adjacent parent node: check parent is not another vertex 
	   * with our system ID and the parent node is on SPF paths 
	   */
	  vertex = rbvertex->parent;
	  while (vertex != NULL)
	    {
              if (memcmp (vertex->N.id, area->isis->sysid, ISIS_SYS_ID_LEN)
		  && (listnode_lookup (rdtree->paths, vertex)))
		break;
	      vertex = vertex->parent;
	    }
	  if (vertex != NULL)
            trill_add_nickadjlist (area, adjlist, vertex);
	}

      if (rbvertex->children && listhead (rbvertex->children)) 
        {
	   childlist = list_new();
           for (ALL_LIST_ELEMENTS_RO (rbvertex->children, node, vertex))
	     {
               if (memcmp (vertex->N.id, area->isis->sysid, ISIS_SYS_ID_LEN) == 0)
                 listnode_add(childlist, vertex);
	       else if (listnode_lookup (rdtree->paths, vertex))
                 trill_add_nickadjlist (area, adjlist, vertex);
	     }

	   /* 
	    * If we find child vertices above with our system ID then we search
	    * their descendants and any that are found are added as our adjacencies.
	    */
	   for (node = listhead(childlist); node != NULL; node = listnextnode(node))
             {
               if ((vertex = listgetdata(node)) == NULL)
	         break;

               for (ALL_LIST_ELEMENTS_RO (vertex->children, cnode, cvertex))
	         {
                   if ((memcmp (cvertex->N.id, area->isis->sysid, ISIS_SYS_ID_LEN) == 0) &&
                           listnode_lookup(childlist, cvertex) == NULL)
                     listnode_add(childlist, cvertex);

		   if (listnode_lookup(rdtree->paths, cvertex))
                     trill_add_nickadjlist (area, adjlist, cvertex);
	         }
	     }
	   list_delete(childlist);
	}

      if (nicknode != NULL)
        nicknode->adjnodes = adjlist;
      else
	area->trill->adjnodes = adjlist;
    }
  trill_create_vlanfilterlist(area, nicknode);
}
 
static nickfwdtblnode_t *
trill_fwdtbl_lookup (struct isis_area *area, u_int16_t nick)
{
  struct listnode *node;
  nickfwdtblnode_t *fwdnode;

  if (area->trill->fwdtbl == NULL)
    return NULL;

  for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, node, fwdnode))
    if (fwdnode->dest_nick == nick)
      return fwdnode;

  return NULL;
}

static void
trill_adjtbl_print (struct vty *vty, struct isis_area *area, nicknode_t *nicknode)
{
  struct listnode *node;
  nickfwdtblnode_t *fwdnode;
  void *listdata;
  u_int16_t nick;
  int idx = 0;
  u_int8_t *vlans;
  int vlan_set;
  int vlan;
  struct list *adjnodes;
  struct listnode *vnode = NULL;
  struct list  *vlans_reachable;

  if (nicknode != NULL)
    {
      adjnodes = nicknode->adjnodes;
      vlans_reachable = nicknode->vlans_reachable;
    }
  else
    {
      adjnodes = area->trill->adjnodes;
      vlans_reachable = area->trill->vlans_reachable;
    }

  if (adjnodes == NULL)
    return;

  if ((vlans_reachable != NULL) &&
      listcount(adjnodes) == listcount(vlans_reachable))
    vnode = listhead (vlans_reachable);

  for (ALL_LIST_ELEMENTS_RO (adjnodes, node, listdata))
    {
      nick = (u_int16_t)(u_long)listdata;
      fwdnode = trill_fwdtbl_lookup (area, nick);
      if (!fwdnode)
        continue;

      vty_out (vty, "%-15s   %-5d      %-5s  %-15s%s",
               print_sys_hostname (nick_to_sysid(area, nick)),
	       ntohs (nick), fwdnode->interface->name,
	       snpa_print (fwdnode->adj_snpa), VTY_NEWLINE);

      if (vlans_reachable == NULL || vnode == NULL)
        continue;

      vty_out (vty, "    VLAN filter list:");
      vlans = listgetdata (vnode);
      if (vlans == NULL)
        {
          vty_out (vty, "%s", VTY_NEWLINE);
          continue;
        }

      EACH_VLAN_SET(vlans, vlan, vlan_set)
       {
          idx++;
          if (idx % 8 == 0)
              vty_out (vty, "%s            ", VTY_NEWLINE);
          vty_out (vty, "%d ", vlan);
       }
      vnode = listnextnode (vnode);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

static void
trill_adjtbl_print_all (struct vty *vty, struct isis_area *area)
{
  dnode_t *dnode;
  nicknode_t *tnode;

  vty_out(vty, "Adjacencies on our RBridge distribution tree:%s", VTY_NEWLINE);
  trill_adjtbl_print (vty, area, NULL);

  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode))
    {
      vty_out(vty, "Adjacencies on RBridge %s distribution tree:%s",
	      print_sys_hostname (tnode->info.sysid), VTY_NEWLINE);
      trill_adjtbl_print (vty, area, tnode);
    }
}

static void
trill_ioctl(int fd, unsigned type, void *data)
{
  if (isisd_privs.change (ZPRIVS_RAISE))
    zlog_err ("%s: could not raise privs, %s", __func__, safe_strerror (errno));

  if (ioctl(fd, type, data) != 0) {
      zlog_warn ("trill_ioctl() type:%X failed: %s", type, safe_strerror (errno));
  }

  if (isisd_privs.change (ZPRIVS_LOWER))
    zlog_err ("%s: could not lower privs, %s", __func__, safe_strerror (errno));
}

static void print_nickname_database(struct trill_nickinfo *ni){
	int idx = 0;

	printf("\n\n\t\t\tTRILL NICK INFO\n\n");
	printf("Nickname: %d\n",ntohs(ni->tni_nick));
	printf("Mac_addr: %02X:%02X:%02X:%02X:%02X:%02X\n", \
	(unsigned char)ni->tni_adjsnpa[0], \
	(unsigned char)ni->tni_adjsnpa[1], \
	(unsigned char)ni->tni_adjsnpa[2], \
	(unsigned char)ni->tni_adjsnpa[3], \
	(unsigned char)ni->tni_adjsnpa[4], \
	(unsigned char)ni->tni_adjsnpa[5] );
	printf("Link on our system: %d\n",ni->tni_linkid);
	printf("Num of *our* adjacencies: %d\n",ni->tni_adjcount);
	printf("Num of distribution tree: %d\n",ni->tni_dtrootcount);
	for (idx = 0; idx < ni->tni_adjcount; idx++)
	printf("Adj_Nickname%d: %d\n",idx,ntohs(TNI_ADJNICK(ni,idx)));
		
}

static void
trill_publish_nick(struct isis_area *area, int fd,int port_id, u_int16_t nick,
    nickfwdtblnode_t *fwdnode)
{
  nicknode_t *nick_node;
  int adjcount = 0;
  int dtrootcount = 0;
  int idx;
  int size;
  struct listnode *node;
  void *listdata;
  struct list *adjnodes;
  struct list *dtrootnodes;
  struct trill_nickinfo *ni;
  struct list *vlans_reachable;
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct mnl_socket *nl1;
  struct nlmsghdr *nlh;
	struct rtgenmsg *rt;
	int ret;
	unsigned int seq, portid;
	int err;

  /* If this is a forwarding entry (not us), then get node data */
  if (fwdnode != NULL)
    {
      nick_node = trill_nicknode_lookup (area, fwdnode->dest_nick);
      if (nick_node == NULL)
	 return;
      adjnodes = nick_node->adjnodes;
      dtrootnodes = nick_node->info.dt_roots;
      vlans_reachable = nick_node->vlans_reachable;
    }
  else
    {
      adjnodes = area->trill->adjnodes;
      dtrootnodes = area->trill->dt_roots;
      vlans_reachable = area->trill->vlans_reachable;
    }

  if (adjnodes != NULL)
    adjcount = listcount(adjnodes);
  if (dtrootnodes != NULL)
    dtrootcount = listcount(dtrootnodes); 

  size = sizeof(struct trill_nickinfo) + (adjcount * sizeof (u_int16_t)) + 
	  (dtrootcount * sizeof (u_int16_t)) + 
	  (adjcount * VLANS_ARRSIZE);
  ni = (struct trill_nickinfo *)calloc(1, size);
  ni->tni_adjcount = adjcount;
  ni->tni_dtrootcount = dtrootcount;
  ni->tni_nick = nick;

  if (fwdnode != NULL)
    {
      memcpy(&ni->tni_adjsnpa, fwdnode->adj_snpa,
	     sizeof(fwdnode->adj_snpa));
      ni->tni_linkid = fwdnode->interface->ifindex;
    }

  if (adjcount > 0)
    {
      idx = 0;
      for (ALL_LIST_ELEMENTS_RO (adjnodes, node, listdata))
        {
          TNI_ADJNICK(ni, idx) = (u_int16_t)(u_long)listdata;
	  idx++;
        }
    }

  if (dtrootcount > 0)
    {
      idx = 0;
      for (ALL_LIST_ELEMENTS_RO (dtrootnodes, node, listdata))
        {
          TNI_DTROOTNICK(ni, idx) = (u_int16_t)(u_long)listdata;
	  idx++;
        }
    }

  if (vlans_reachable != NULL)
    {
      idx = 0;
      for (ALL_LIST_ELEMENTS_RO (vlans_reachable, node, listdata))
        {
	  memcpy (TNI_VLANFILTERMAP(ni, idx), listdata, VLANS_ARRSIZE);
	  idx++;
        }
    }
    
    	print_nickname_database(ni);
    	
    	printf("*****ID**** %d",fd);
    	//memset(nl,0,sizeof(struct mnl_socket));
      //nl1->fd = fd;
      
      nlh = mnl_nlmsg_put_header(buf);
      //int len = MNL_ALIGN(sizeof(struct nlmsghdr));
      //memcpy(nlh,0,len);
      //memset(buf, 0, len);
	//nlh->nlmsg_len = len;
      
	nlh->nlmsg_type	= RTM_SETNICK;
//	nlh->nlmsg_type	= RTM_ADDNICK;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	//nlh->nlmsg_seq = seq = time(NULL);
	//nlh->nlmsg_pid = port_id;
	
	rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
	rt->rtgen_family = PF_TRILL;
	if(fwdnode == NULL)
	mnl_attr_put(nlh, 1, size, ni);
	else
	mnl_attr_put(nlh, 2, size, ni);
	err = mnl_socket_sendto(fd, nlh, nlh->nlmsg_len);
	if(err < 0)
	printf("\t\t\tERROR1\n");
	else
	printf("SENT BYTES1  %d\n",err);
	
  free(ni);
}

static void
trill_publish (struct isis_area *area, struct isis_circuit *trill_circuit)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  struct listnode *node;
  nickfwdtblnode_t *fwdnode;
  u_char *lsysid;
  u_int16_t lpriority;
  u_int16_t root_nick;
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct mnl_socket *nl;
  struct nlmsghdr *nlh;
  struct rtgenmsg *rt;
  unsigned int seq, portid;
  int err;

  //trill_ioctl(trill_circuit->fd, TRILL_DELALL, NULL);

  if (area->trill->fwdtbl != NULL)
    {
      for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, node, fwdnode))
        {
	  trill_publish_nick(area, trill_circuit->fd_netlink, trill_circuit->port_id, fwdnode->dest_nick,
	    fwdnode);
        }
    }
   printf("ID************ %d",trill_circuit->fd_netlink);
  trill_publish_nick(area, trill_circuit->fd_netlink, trill_circuit->port_id, area->trill->nick.name, NULL);

  /* Compute the highest priority root tree node  */
  lpriority = area->trill->root_priority;
  lsysid = area->isis->sysid;
  root_nick = area->trill->nick.name;

  /*
   * Highest priority tree root is determined by the numerically lowest
   * priority field or if priorities are equal then by lowest system ID. 
   */
  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode))
    {
      if (tnode->info.root_priority > lpriority)
        continue;
      if (tnode->info.root_priority == lpriority &&
          memcmp(tnode->info.sysid, lsysid, ISIS_SYS_ID_LEN) > 0)
        continue;
      lpriority = tnode->info.root_priority;
      lsysid = tnode->info.sysid;
      root_nick = tnode->info.nick.name;
    }
	printf("ROOT_NICK %d\n",ntohs(root_nick));
      
      //nl = calloc(1,sizeof(struct mnl_socket));
  	//nl->fd = trill_circuit->fd_netlink;
      nlh = mnl_nlmsg_put_header(buf);
      //int len = MNL_ALIGN(sizeof(struct nlmsghdr));
      //memcpy(nlh,0,len);
      //memset(buf, 0, len);
	//nlh->nlmsg_len = len;
      //if(fwdnode == NULL)
	nlh->nlmsg_type	= RTM_TREEROOT;
//	nlh->nlmsg_type	= RTM_ADDNICK;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	//nlh->nlmsg_pid = trill_circuit->port_id;
	//nlh->nlmsg_seq = seq = time(NULL);
	
	rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
	rt->rtgen_family = PF_TRILL;
	mnl_attr_put_u16(nlh, 1, root_nick);
	
	err = mnl_socket_sendto(trill_circuit->fd_netlink, nlh, nlh->nlmsg_len);
	if(err < 0)
	printf("\t\t\tERROR \n");
	else
	printf("SENT BYTES %d\n",err);
  //trill_ioctl(trill_circuit->fd, TRILL_TREEROOT, &root_nick); 
}

void
trill_set_vlan_forwarder (struct isis_circuit *circuit, u_int8_t *forwarder)
{
  //trill_ioctl(circuit->fd, TRILL_VLANFWDER, forwarder);
  printf("NO VLANS in basic trill\n");
}

void
trill_port_flush (struct isis_circuit *circuit, u_int16_t vlan)
{
  //trill_ioctl(circuit->fd, TRILL_PORTFLUSH, (void *)(unsigned long)vlan);
  printf("NO VLANS in basic trill\n");
}

void
trill_nick_flush (struct isis_circuit *circuit, u_int16_t vlan)
{
  //trill_ioctl(circuit->fd, TRILL_NICKFLUSH, (void *)(unsigned long)vlan);
  printf("NO VLANS in basic trill\n");
}

/*
 * Called upon computing the SPF trees to create the forwarding
 * and adjacency lists for TRILL.
 */
void
trill_process_spf (struct isis_area *area)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  struct listnode *node;
  struct isis_circuit *trill_circuit = NULL;

  /* Nothing to do if we don't have a nick yet */
  if (area->trill->nick.name == RBRIDGE_NICKNAME_NONE)
	  return;

  if (area->circuit_list && listhead(area->circuit_list))
    trill_circuit = listgetdata(listhead(area->circuit_list));
  if (trill_circuit == NULL)
    return;

  trill_create_nickfwdtable(area);
  trill_create_nickadjlist(area, NULL);
  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode))
    trill_create_nickadjlist(area, tnode);

  trill_publish(area, trill_circuit);

  for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, trill_circuit))
    {
      //trill_ioctl(trill_circuit->netlink_fd, TRILL_DESIGVLAN,
	//&trill_circuit->vlans->designated);
      if (trill_circuit->vlans->inhibit_all == 0)
	trill_set_vlan_forwarder (trill_circuit,
	    trill_circuit->vlans->forwarder);
    }
}

void
trill_nickdb_print (struct vty *vty, struct isis_area *area)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  const char *sysid;
  int vlan_count = 0;
  int vlan_set;
  int vlan;

  vty_out(vty, "    System ID          Hostname     Nickname" 
	 "   Priority%s", VTY_NEWLINE); 
  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode))
    {
      sysid = sysid_print (tnode->info.sysid);
      vty_out (vty, "%-21s %-10s  %8d  %8d%s", sysid,
               print_sys_hostname (tnode->info.sysid),
	       ntohs (tnode->info.nick.name),
	       tnode->info.nick.priority, VTY_NEWLINE);

      vty_out (vty, "    VLAN Forwarder: ");
      EACH_VLAN_SET(tnode->info.vlans_forwarder, vlan, vlan_set)
        {
	   vlan_count++;
	   if (vlan_count % 8 == 0)
             vty_out(vty, "%s               ", VTY_NEWLINE);
           vty_out (vty, "%d ", vlan); 
        }
      vty_out (vty, "%s", VTY_NEWLINE); 
    }
}

static int
ethercmp(const void *e1, const void *e2)
{
  return memcmp (e1, e2, ETH_ALEN);
}

static int
gather_bridge_ids(struct isis_area *area,
    struct trill_vlan_bridge_roots_subtlv *vlantlv, int vlan)
{
  time_t now;
  int circnt;
  struct listnode *node;
  struct isis_circuit *circuit;
  char *bptr, *obptr;
  ptrdiff_t numbytes;

  now = time (NULL);
  circnt = 0;
  bptr = (char *)(vlantlv + 1);
  for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
    {
      if (CHECK_VLAN(circuit->vlans->forwarder, vlan))
	{
	  circnt++;
	  /*
	   * Note that it's ok for circuits to lack a root bridge ID.  There
	   * may just not be a bridge out there.  (Ultimately, in the future,
	   * that's where we'd like to be.)
	   */
	  if (circuit->root_expire != 0 && now - circuit->root_expire <= 0)
	    {
	      /* ignore bridge priority; only the MAC ID is wanted */
	      memcpy (bptr, circuit->root_bridge + 2, ETH_ALEN);
	      bptr += ETH_ALEN;
	    }
	}
    }

  /* Sort the bridge IDs for ease of comparison, and then remove dups */
  obptr = (char *)(vlantlv + 1);
  numbytes = bptr - obptr;
  if (numbytes > ETH_ALEN)
    {
      qsort(obptr, numbytes / ETH_ALEN, ETH_ALEN, ethercmp);
      while (obptr < bptr - ETH_ALEN)
	{
	  if (memcmp (obptr, obptr + ETH_ALEN, ETH_ALEN) == 0)
	    {
	      memmove (obptr, obptr + ETH_ALEN, (bptr - obptr) - ETH_ALEN);
	      bptr -= ETH_ALEN;
	      numbytes -= ETH_ALEN;
	    }
	  else
	    {
	      obptr += ETH_ALEN;
	    }
	}
    }

  /* Store the root bridge byte count here for the caller */
  vlantlv->vlan_end = numbytes;
  return circnt;
}

/* 
 * Add TLVs necessary to advertise TRILL nickname using router capabilities TLV
 */
int
tlv_add_trill_nickname(struct trill_nickname *nick_info,
  struct stream *stream, struct  isis_area *area)
{
  size_t tlvstart;
  struct router_capability_tlv rtcap;
  u_char tflags;
  struct trill_nickname_subtlv tn;
  int rc;
  int vlan;
  int circnt;
  int nbytes;
  struct trill_vlan_bridge_roots_subtlv *lastvlantlv, *nextvlantlv;

  tlvstart = stream_get_endp (stream);

  (void) memset(&rtcap, 0, sizeof (rtcap));
  rc = add_tlv(ROUTER_CAPABILITY, sizeof (rtcap), (u_char *)&rtcap, stream);
  if (rc != ISIS_OK)
    return rc;

  tflags = TRILL_FLAGS_V0;
  rc = add_subtlv (RCSTLV_TRILL_FLAGS, sizeof (tflags), (u_char *)&tflags,
      tlvstart, stream);
  if (rc != ISIS_OK)
    return rc;

  tn.tn_priority = nick_info->priority;
  tn.tn_nickname = nick_info->name;
  tn.tn_trootpri = htons(area->trill->root_priority);
  tn.tn_treecount = htons(0);
  rc = add_subtlv (RCSTLV_TRILL_NICKNAME, sizeof (tn), (u_char *)&tn, tlvstart,
      stream);
  if (rc != ISIS_OK)
    return rc;

  /*
   * The algorithm below is designed to find the set of VLANs for which we are
   * appointed forwarder for at least one circuit, and organize them into lists
   * (each with a separate sub-TLV) based on root 802.1D bridge ID.  The lists
   * must be contiguous and must have exactly the same set of root IDs, but
   * need not have the same set of circuits involved.
   *
   * We currently don't support multicast snooping, so the complexities of the
   * M4/M6/OM bits are spared here.
   */
  circnt = listcount(area->circuit_list);
  if (circnt == 0)
    return rc;

  /* Aligned: Ethernet addresses are 6 bytes, and the subTLV uses uint16_t */
  lastvlantlv = XMALLOC (MTYPE_ISIS_TRILL_VLANSUBTLV,
      2 * (sizeof (*lastvlantlv) + circnt * ETH_ALEN));
  nextvlantlv = (struct trill_vlan_bridge_roots_subtlv *)
      ((char *)(lastvlantlv + 1) + circnt * ETH_ALEN);

  vlan = circnt = 0;
  while (vlan <= VLAN_MAX)
    {
      /*
       * If this is the first VLAN or if the last pass ended on an unused VLAN,
       * then scan ahead to find the start of the next range that's in use.
       * Otherwise, copy down the last one found.
       */
      if (circnt == 0)
	{
	  for (vlan++; vlan <= VLAN_MAX; vlan++)
	  {
	    circnt = gather_bridge_ids (area, lastvlantlv, vlan);
	    if (circnt != 0)
	      break;
	  }
	  if (circnt == 0)
	    break;
	}
      else
	{
	  memcpy (lastvlantlv, nextvlantlv,
	      nextvlantlv->vlan_end + sizeof (*nextvlantlv));
	}

      /*
       * Set the multicast bits, because we don't support IGMP/MLD
       * snooping, and we thus need to see all multicast frames.
       */
      lastvlantlv->vlan_start = htons (vlan | TVRFS_M4 |  TVRFS_M6 |  TVRFS_OM);
      nbytes = lastvlantlv->vlan_end;

      /*
       * Now locate the end of the compatible set of VLANs: these are the ones
       * where we're appointed forwarder on at least one circuit, and the list
       * of root bridge IDs is identical to the current one.
       */
      for (vlan++; vlan <= VLAN_MAX; vlan++)
	{
	  circnt = gather_bridge_ids (area, nextvlantlv, vlan);
	  if (circnt == 0 || nbytes != nextvlantlv->vlan_end ||
	      memcmp (lastvlantlv + 1, nextvlantlv + 1, nbytes != 0))
	    break;
	}

      lastvlantlv->vlan_end = htons (vlan - 1);

      /*
       * Insert the subTLV into the list, starting a new TLV if it won't fit in
       * the current one.
       */
      nbytes += sizeof (*lastvlantlv);
      rc = add_subtlv (RCSTLV_TRILL_VLANSROOTS, nbytes, (u_char *)lastvlantlv,
	  tlvstart, stream);
      if (rc == ISIS_WARNING)
      {
	tlvstart = stream_get_endp (stream);
	rc = add_tlv(ROUTER_CAPABILITY, sizeof (rtcap), (u_char *)&rtcap,
	    stream);
	if (rc != ISIS_OK)
	  break;
	rc = add_subtlv (RCSTLV_TRILL_VLANSROOTS, nbytes,
	    (u_char *)lastvlantlv, tlvstart, stream);
	if (rc != ISIS_OK)
	  break;
      }
    }

  XFREE (MTYPE_ISIS_TRILL_VLANSUBTLV, lastvlantlv);

  return rc;
}

DEFUN (debug_trill_events,
       debug_trill_events_cmd,
       "debug trill events",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS TRILL Events\n")
{
  isis->debugs |= DEBUG_TRILL_EVENTS;
  print_debug (vty, DEBUG_TRILL_EVENTS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_trill_events,
       no_debug_trill_events_cmd,
       "no debug trill events",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS TRILL Events\n")
{
  isis->debugs &= ~DEBUG_TRILL_EVENTS;
  print_debug (vty, DEBUG_TRILL_EVENTS, 0);

  return CMD_SUCCESS;
}

DEFUN (show_trill_nickdatabase,
       show_trill_nickdatabase_cmd,
       "show trill nickname database",
       SHOW_STR TRILL_STR "TRILL IS-IS nickname information\n"
       "IS-IS TRILL nickname database\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (!isis->trill_active || (isis->area_list->count == 0))
    return CMD_SUCCESS;

  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "Area %s nickname:%d priority:%d%s%s",
          area->area_tag ? area->area_tag : "null", 
          ntohs(area->trill->nick.name), area->trill->nick.priority,
          VTY_NEWLINE, VTY_NEWLINE);
      vty_out (vty, "IS-IS TRILL nickname database:%s", VTY_NEWLINE);
          trill_nickdb_print (vty, area);
    }

  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (show_trill_fwdtable,
       show_trill_fwdtable_cmd,
       "show trill forwarding",
       SHOW_STR TRILL_STR
       "IS-IS TRILL forwarding table\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (!isis->trill_active || (isis->area_list->count == 0))
    return CMD_SUCCESS;

  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "IS-IS TRILL forwarding table:%s", VTY_NEWLINE);
      trill_fwdtbl_print (vty, area);
    }

  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (show_trill_circuits,
       show_trill_circuits_cmd,
       "show trill circuits",
       SHOW_STR TRILL_STR
       "IS-IS TRILL circuits\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (!isis->trill_active || (isis->area_list->count == 0))
    return CMD_SUCCESS;

  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "IS-IS TRILL circuits:%s%s",
		      VTY_NEWLINE, VTY_NEWLINE);
      trill_circuits_print_all (vty, area);
    }

  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (show_trill_adjtable,
       show_trill_adjtable_cmd,
       "show trill adjacencies",
       SHOW_STR TRILL_STR
       "IS-IS TRILL adjacency lists\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (!isis->trill_active || (isis->area_list->count == 0))
    return CMD_SUCCESS;

  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "IS-IS TRILL adjacencies in all distribution trees:%s%s",
		      VTY_NEWLINE, VTY_NEWLINE);
          trill_adjtbl_print_all (vty, area);
    }

  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}

/*
 * Enable TRILL support in IS-IS command, only one IS-IS area allowed.
 */
DEFUN (isis_trill,
       isis_trill_cmd,
       "isis trill",
       "Enable use of IS-IS as routing protocol for TRILL\n")
{
  if (!isis->trill_active && isis->area_list->count > 0)
    {
      vty_out (vty, "Cannot enable TRILL. IS-IS area already configured%s",
		      VTY_NEWLINE);
      return CMD_WARNING;
    }

  isis->trill_active = TRUE;
  return CMD_SUCCESS;
}

/*
 * Disable TRILL support in IS-IS command
 */
DEFUN (no_isis_trill,
       no_isis_trill_cmd,
       "no isis trill",
       "Disable use of IS-IS as routing protocol for TRILL\n")
{
  isis->trill_active = FALSE;
  return CMD_SUCCESS;
}

DEFUN (trill_nickname,
       trill_nickname_cmd,
       "trill nickname WORD",
       TRILL_STR
       TRILL_NICK_STR
       "<1-65534>\n")
{
  struct isis_area *area;
  u_int16_t nickname;

  area = vty->index;
  assert (area);
  assert (area->isis);
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  VTY_GET_INTEGER_RANGE ("TRILL nickname", nickname, argv[0], 
		  RBRIDGE_NICKNAME_MIN + 1, RBRIDGE_NICKNAME_MAX);
  if (!trill_area_nickname (area, nickname))
    {
      vty_out (vty, "TRILL nickname conflicts with another RBridge nickname,"
		    " must select another.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_trill_nickname,
       no_trill_nickname_cmd,
       "no trill nickname",
       TRILL_STR
       TRILL_NICK_STR)
{
  struct isis_area *area;

  area = vty->index;
  assert (area);
  assert (area->isis);
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  trill_area_nickname (area, 0);
  return CMD_SUCCESS;
}

DEFUN (trill_nickname_priority,
       trill_nickname_priority_cmd,
       "trill nickname priority WORD",
       TRILL_STR
       TRILL_NICK_STR
       "priority of use field\n"
       "<1-127>\n")
{
  struct isis_area *area;
  u_int8_t priority;

  area = vty->index;
  assert (area);
  assert (area->isis);
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  VTY_GET_INTEGER_RANGE ("TRILL nickname priority", priority, argv[0],
		  MIN_RBRIDGE_PRIORITY, MAX_RBRIDGE_PRIORITY);
  trill_nickname_priority_update (area, priority);
  return CMD_SUCCESS;
}

DEFUN (no_trill_nickname_priority,
       no_trill_nickname_priority_cmd,
       "no trill nickname priority WORD",
       TRILL_STR
       TRILL_NICK_STR
       "priority of use field\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);
  assert (area->isis);
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  trill_nickname_priority_update (area, 0);
  return CMD_SUCCESS;
}

DEFUN (trill_instance,
       trill_instance_cmd,
       "trill instance WORD",
       TRILL_STR
       "TRILL instance\n"
       "instance name\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);
  assert (area->isis);
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  (void) strlcpy(area->trill->name, argv[0], MAXLINKNAMELEN);
  return CMD_SUCCESS;
}

void
install_trill_elements ()
{
	//vty_out(vty, "%s  1             ", VTY_NEWLINE);
  install_element (VIEW_NODE, &show_trill_nickdatabase_cmd);
  install_element (VIEW_NODE, &show_trill_fwdtable_cmd);
  install_element (VIEW_NODE, &show_trill_adjtable_cmd);
  install_element (VIEW_NODE, &show_trill_circuits_cmd);

  install_element (ENABLE_NODE, &debug_trill_events_cmd);
  install_element (ENABLE_NODE, &no_debug_trill_events_cmd);
  install_element (ENABLE_NODE, &show_trill_nickdatabase_cmd);
  install_element (ENABLE_NODE, &show_trill_fwdtable_cmd);
  install_element (ENABLE_NODE, &show_trill_adjtable_cmd);
  install_element (ENABLE_NODE, &show_trill_circuits_cmd);

  install_element (CONFIG_NODE, &debug_trill_events_cmd);
  install_element (CONFIG_NODE, &no_debug_trill_events_cmd);
  install_element (CONFIG_NODE, &isis_trill_cmd);
  install_element (CONFIG_NODE, &no_isis_trill_cmd);

  install_element (ISIS_NODE, &trill_nickname_cmd);
  install_element (ISIS_NODE, &no_trill_nickname_cmd);
  install_element (ISIS_NODE, &trill_nickname_priority_cmd);
  install_element (ISIS_NODE, &no_trill_nickname_priority_cmd);
  install_element (ISIS_NODE, &trill_instance_cmd);

  install_trill_vlan_elements ();
}

/*
static int
update_link(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
  struct isis_area *area = arg;
  dladm_status_t status;
  dladm_conf_t conf;
  char bridge[MAXLINKNAMELEN], linkname[MAXLINKNAMELEN];
  char pointless[DLADM_STRSIZE];
  datalink_class_t class;
  struct interface *ifp;
  struct isis_circuit *circ;
  uint_t propval, valcnt;

  status = dladm_bridge_getlink (handle, linkid, bridge, sizeof (bridge));
  if (status != DLADM_STATUS_OK || strcmp (bridge, area->trill->name) != 0)
    return DLADM_WALK_CONTINUE;

  status = dladm_read_conf (handle, linkid, &conf);
  if (status != DLADM_STATUS_OK)
    {
      zlog_debug ("can't get status on link ID %u: %s", linkid,
	dladm_status2str (status, pointless));
      return DLADM_WALK_CONTINUE;
    }

  status = dladm_datalink_id2info (handle, linkid, NULL, &class, NULL,
      linkname, sizeof (linkname));
  if (status == DLADM_STATUS_OK)
    {
      ifp = if_get_by_name (linkname);
      ifp->ifindex = linkid;
      ifp->flags |= IFF_UP | IFF_RUNNING;

      /*
       * This value is arbitrary.  The real interface MTU will be read out of
       * the kernel when isis_circuit_up calls the TRILL socket interface.
       //
      if (ifp->mtu == 0)
	ifp->mtu = 1500;
      *(datalink_id_t *)ifp->sdl.sdl_data = linkid;
      ifp->sdl.sdl_nlen = sizeof (datalink_id_t);
      if ((circ = ifp->info) == NULL)
	{
	  circ = isis_csm_state_change (IF_UP_FROM_Z, NULL, ifp);
	  circ = isis_csm_state_change (ISIS_ENABLE, circ, area);
	}
      /*
       * The second state change has caused us to open up the socket for this
       * link and read the Ethernet address.  Copy that into place for the
       * interface structure.
       //
      ifp->sdl.sdl_alen = ETH_ALEN;
      memcpy (LLADDR (&ifp->sdl), circ->u.bc.snpa, ETH_ALEN);
      valcnt = 1;
      status = dladm_get_linkprop_values (dlhandle, linkid,
	  DLADM_PROP_VAL_PERSISTENT, "default_tag", &propval, &valcnt);
      if (status == DLADM_STATUS_OK)
	circ->vlans->pvid = propval;
      memset (circ->vlans->enabled, 0, VLANS_ARRSIZE);
      if (circ->vlans->pvid != 0)
	SET_VLAN (circ->vlans->enabled, circ->vlans->pvid);
    }
  else
    {
      zlog_err ("unable to get link info for ID %u: %s", linkid,
	  dladm_status2str (status, pointless));
    }
  dladm_destroy_conf (handle, conf);
  return DLADM_WALK_CONTINUE;
}

static int
set_vlan(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
  dladm_status_t status;
  dladm_vlan_attr_t vinfo;
  char pointless[DLADM_STRSIZE];
  struct interface *ifp;
  struct isis_circuit *circuit;

  status = dladm_vlan_info (handle, linkid, &vinfo, DLADM_OPT_ACTIVE);
  if (status != DLADM_STATUS_OK)
  {
    zlog_debug ("can't get VLAN info on link ID %u: %s",
	linkid, dladm_status2str (status, pointless));
    return DLADM_WALK_CONTINUE;
  }

  ifp = if_lookup_by_index (vinfo.dv_linkid);
  if (ifp != NULL)
  {
    circuit = ifp->info;
    SET_VLAN (circuit->vlans->enabled, vinfo.dv_vid);
  }
  return DLADM_WALK_CONTINUE;
}
*/

static int
update_link(const char *br, const char *port, void *arg)
{
  struct isis_area *area = arg;
  //dladm_status_t status;
  //dladm_conf_t conf;
  //char bridge[MAXLINKNAMELEN], linkname[MAXLINKNAMELEN];
  //char pointless[DLADM_STRSIZE];
  //datalink_class_t class;
  struct interface *ifp;
  struct isis_circuit *circ;
  //uint_t propval, valcnt;

  //status = dladm_bridge_getlink (handle, linkid, bridge, sizeof (bridge));
  //if (status != DLADM_STATUS_OK || strcmp (bridge, area->trill->name) != 0)
    //return DLADM_WALK_CONTINUE;

  //status = dladm_read_conf (handle, linkid, &conf);
  //if (status != DLADM_STATUS_OK)
    //{
      //zlog_debug ("can't get status on link ID %u: %s", linkid,
	//dladm_status2str (status, pointless));
      //return DLADM_WALK_CONTINUE;
    //}

  //status = dladm_datalink_id2info (handle, linkid, NULL, &class, NULL,
    //  linkname, sizeof (linkname));
  //if (status == DLADM_STATUS_OK)
    //{
      ifp = if_get_by_name (port);
      ifp->ifindex = if_nametoindex(port);
      ifp->flags |= IFF_UP | IFF_RUNNING;

      /*
       * This value is arbitrary.  The real interface MTU will be read out of
       * the kernel when isis_circuit_up calls the TRILL socket interface.
       */
      if (ifp->mtu == 0)
	ifp->mtu = 1500;
      //*(unsigned int *)ifp->sdl.sll_ifindex = ifp->ifindex;
      //ifp->sdl.sdl_nlen = sizeof (unsigned int);
      //printf("AFRO1\n");
      if ((circ = ifp->info) == NULL)
	{
	  circ = isis_csm_state_change (IF_UP_FROM_Z, NULL, ifp);
	  circ = isis_csm_state_change (ISIS_ENABLE, circ, area);
	}
      /*
       * The second state change has caused us to open up the socket for this
       * link and read the Ethernet address.  Copy that into place for the
       * interface structure.
       */
      ifp->hw_addr_len = ETH_ALEN;
      memcpy (ifp->hw_addr, circ->u.bc.snpa, ETH_ALEN);
     /* valcnt = 1;
      status = dladm_get_linkprop_values (dlhandle, linkid,
	  DLADM_PROP_VAL_PERSISTENT, "default_tag", &propval, &valcnt);
      if (status == DLADM_STATUS_OK)*/
     
	/* as trill required atleast 1 vlan for its working,
	 * so temporarily the value is hard coded 
	 */	
	circ->vlans->pvid = 1; 
      memset (circ->vlans->enabled, 0, VLANS_ARRSIZE);
      if (circ->vlans->pvid != 0)
	SET_VLAN (circ->vlans->enabled, circ->vlans->pvid);
	//printf("AFRO2\n");
    //}
  //else
    //{
      //zlog_err ("unable to get link info for ID %u: %s", linkid,
	  //dladm_status2str (status, pointless));
    //}
  //dladm_destroy_conf (handle, conf);
  //return DLADM_WALK_CONTINUE;
  return 0;
}

static char
trill_internal_reload(struct isis_area *area)
{
  struct interface *ifp;
  struct listnode *node, *nnode;
  struct isis_circuit *circ;

  //if (dladm_open (&dlhandle) != DLADM_STATUS_OK)
    //{
      //zlog_err ("%s: unable to open datalink control", area->trill->name);
      //return FALSE;
    //}

  /*
   * Turn off the IFF_UP bit for every link.  Any links left over at the end
   * without that flag must have been removed.
   */
  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    ifp->flags &= ~IFF_UP;
  //printf("Mohsin1\n");
  /* Get all of the links configured on this bridge */
  //dladm_walk_datalink_id (update_link, dlhandle, area, DATALINK_CLASS_ALL,
    //  DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);

    br_foreach_port(area->trill->name,
		    update_link,
		    area);
  //printf("Mohsin2\n");
  /* Disable ones that have been removed */
  for (ALL_LIST_ELEMENTS (iflist, node, nnode, ifp))
    {
      if (!(ifp->flags & IFF_UP) && (circ = ifp->info) != NULL)
	{ //printf("Mohsin3\n");
	  isis_csm_state_change (ISIS_DISABLE, circ, area);
	  isis_csm_state_change (IF_DOWN_FROM_Z, circ, area);
	}
    }

  /* Now get the VLANs //
  dladm_walk_datalink_id (set_vlan, dlhandle, area, DATALINK_CLASS_VLAN,
      DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);

  dladm_close (dlhandle);*/
  return TRUE;
}

/*
 * This is run synchronously by the interrupt handling logic when SIGHUP
 * occurs.  We use this to signal a "refresh" from SMF.  If the user has
 * specified an explicit configuration file, or if the update fails, then we
 * just fall through to the normal reload (by way of exec) mechanism.
 */
char
trill_reload(void)
{
  if (cfile_present)
    return FALSE;
  else
    //return TRUE;
    return trill_internal_reload (listgetdata (listhead (isis->area_list)));
}

/*
 * This function runs before the regular configuration file (if any) is read,
 * and simulates a configuration read by setting up internal information based
 * on data stored in dladm.  The user may override this configuration (for
 * debugging purposes) by specifying a configuration file on the command line.
 * Otherwise, we force the caller to read /dev/null.
 */
void
trill_read_config (char **cfilep, int argc, char **argv)
{
  const char *instname;
  u_int16_t nickname;
  struct isis_area *area;
  struct listnode *ifnode;
  struct interface *ifp;
  struct area_addr *addr;

  zlog_set_level (NULL, ZLOG_DEST_SYSLOG, LOG_WARNING);

  if (optind != argc - 1)
  {
    zlog_err ("instance name is required for TRILL");
    exit (1);
  }
  instname = argv[optind];
  	//printf("honey\n");
	//vty_out(vty, "%s     2          ", VTY_NEWLINE);
  isis->trill_active = TRUE;
  area = isis_area_create (instname);
  (void) strlcpy (area->trill->name, instname, MAXLINKNAMELEN);

  /* Set up to use new (extended) metrics only. */
  area->newmetric = 1;
  area->oldmetric = 0;

  /* IS-IS for TRILL is different from the standard; it uses one area address */
  isis->max_area_addrs = 1;
  //printf("honey1\n");
  if (!trill_internal_reload (area))
    exit(1);
  //printf("honey2\n");
  /* Recover a previous nickname, if any. */
  //nickname = dladm_bridge_get_nick(instname);
  nickname = 123567;
  if (nickname != RBRIDGE_NICKNAME_NONE && is_nickname_used (nickname))
  {
    zlog_warn ("%s: unable to use previous nickname %u", instname, nickname);
    nickname = RBRIDGE_NICKNAME_NONE;
  }
  if (nickname != RBRIDGE_NICKNAME_NONE)
  {
    area->trill->nick.name = htons (nickname);
    SET_FLAG (area->trill->status, TRILL_NICK_SET);
    SET_FLAG (area->trill->status, TRILL_AUTONICK);
  }

  /* Set up the area and system ID */
  ifnode = listhead (iflist);
  if (ifnode != NULL)
    {
      ifp = listgetdata (ifnode);
      addr = XMALLOC (MTYPE_ISIS_AREA_ADDR, sizeof (struct area_addr));
      addr->addr_len = 8;
      addr->area_addr[0] = 0;
      memcpy (addr->area_addr + 1, ifp->hw_addr, ifp->hw_addr_len);
      addr->area_addr[7] = 0;
      memcpy (isis->sysid, GETSYSID (addr, ISIS_SYS_ID_LEN), ISIS_SYS_ID_LEN);
      isis->sysid_set = 1;
      /* Forget the systemID part of the address */
      addr->addr_len -= (ISIS_SYS_ID_LEN + 1);
      listnode_add (area->area_addrs, addr);
      lsp_l1_generate (area);
      lsp_l2_generate (area);
      //printf("123456\n");
    }

  if (*cfilep == NULL)
    {
      *(const char **)cfilep = "/dev/null";
      cfile_present = FALSE;
    }
}

