/*
 *     Linux TRILL support
 *
 *     Authors:
 *              Syed M. Mohsin Kazmi    <08beesmmkazmi@seecs.edu.pk>
 *
 *     This program is free software; you can redistribute it and/or
 *     modify it under the terms of the GNU General Public License
 *     as published by the Free Software Foundation; either version
 *     2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include "br_private.h"
#include "trill.h"


#define VALID_NICK(n)	((n) != RBRIDGE_NICKNAME_NONE && \
				(n) != RBRIDGE_NICKNAME_UNUSED)
				
const u8 broadcast_addr1[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

struct sk_buff *decapsulate_trill_header(struct sk_buff *skb); 

struct sk_buff *
create_trill_header(struct sk_buff *skb,struct trill_node *nick_entry,
					bool trill_header_ok,
					size_t msglen,
					bool multidest,
					unsigned short ingess_nick,
					unsigned short egress_nick,
					const unsigned char *source_addr);
					
struct sk_buff *create_trill_header1(struct sk_buff *skb,bool trill_header_ok,size_t msglen);


         

static struct trill_inst *trill_inst;
     
void trill_testing(struct sk_buff *skb)
{
    unsigned int data_len = skb->data_len;
    unsigned int mac_len = skb->mac_len;
    unsigned int hdr_len = skb->hdr_len;
    unsigned char *data = skb->data;
    unsigned int i=0;
    
    printk("length of buffer is %u\n", skb->len );
    printk("length of data in buffer is %u\n", data_len );
    printk("length of mac_len is %hu\t and hdr_len is %hu\n",mac_len,hdr_len );
    printk("TRUE SIZE %u\n",skb->truesize);
    printk("headroom %d\n",skb_headroom(skb));
    printk("source: %02X:%02X:%02X:%02X:%02X:%02X\t",eth_hdr(skb)->h_source[0],
	eth_hdr(skb)->h_source[1],eth_hdr(skb)->h_source[2],
	eth_hdr(skb)->h_source[3],eth_hdr(skb)->h_source[4],
	eth_hdr(skb)->h_source[5] );
    
    printk("destination: %02X:%02X:%02X:%02X:%02X:%02X\t",
	eth_hdr(skb)->h_dest[0],eth_hdr(skb)->h_dest[1],eth_hdr(skb)->h_dest[2],
	eth_hdr(skb)->h_dest[3],eth_hdr(skb)->h_dest[4],eth_hdr(skb)->h_dest[5] );
    
    printk("ether_type %hx \n",htons(eth_hdr(skb)->h_proto));
    printk("\t\t\tDATA\n");
    for(i = 0; i < skb->len ; i++)
        printk("%2hx\t", *(data + i));
    printk("\n\t\t\tDONE\n");
   
}

void print_nickname_database(struct trill_nickinfo *ni){

	printk("\n\n\t\t\tTRILL NICK INFO\n\n");
	printk("Nickname: %d\n",ntohs(ni->tni_nick));
	printk("Mac_addr: %02X:%02X:%02X:%02X:%02X:%02X\n", \
	(unsigned char)ni->tni_adjsnpa[0], \
	(unsigned char)ni->tni_adjsnpa[1], \
	(unsigned char)ni->tni_adjsnpa[2], \
	(unsigned char)ni->tni_adjsnpa[3], \
	(unsigned char)ni->tni_adjsnpa[4], \
	(unsigned char)ni->tni_adjsnpa[5] );
	printk("Link on our system: %d\n",ni->tni_ifindex);
	printk("Num of *our* adjacencies: %d\n",ni->tni_adjcount);
	printk("Num of distribution tree: %d\n",ni->tni_dtrootcount);
}

static inline void 
trill_node_free(struct trill_node *nick_entry){
	
	kfree(nick_entry->tn_ni);
	kfree(nick_entry);
}

static inline void 
trill_node_unref(struct trill_node *nick_entry){

	if(--nick_entry->tn_refs == 0){
		trill_node_free(nick_entry);
		trill_inst->ti_nodecount--;
	}

}

static struct trill_node *
trill_node_lookup(unsigned short nick)
{
	struct trill_node *nick_entry;
	
	if(!VALID_NICK(nick))
		return NULL;
	
	read_lock(&trill_inst->ti_rwlock);
	nick_entry = trill_inst->ti_nodes[nick];
	read_unlock(&trill_inst->ti_rwlock);
	
	if(nick_entry != NULL){
	write_lock(&trill_inst->ti_rwlock);
	nick_entry->tn_refs++;
	write_unlock(&trill_inst->ti_rwlock);
	}
	return nick_entry;
}


int 
trill_del_nick(struct trill_inst *trill_inst1, uint16_t nick, bool lockheld){

	struct trill_node *nick_entry;
	int rc = ENOENT;

	if(!lockheld)
		write_lock(&trill_inst1->ti_rwlock);
		
	if(VALID_NICK(nick)){
		nick_entry = trill_inst1->ti_nodes[nick];
		if(nick_entry != NULL){
			trill_node_unref(nick_entry);
			trill_inst1->ti_nodes[nick] = NULL;
			rc = 0;
		}
	}
	
	if(!lockheld)
		write_unlock(&trill_inst1->ti_rwlock);
	return -rc;
}

int 
trill_add_nick(struct trill_nickinfo *ni,bool self){
	
	uint16_t nick;
	int size;
	struct trill_node *tnode;
	
	//print_nickname_database(ni);


	nick = ni->tni_nick;
	if(!VALID_NICK(nick))
		return -EINVAL;
	
	size = TNI_TOTALSIZE(ni);
	if(size > TNI_MAXSIZE)
		return -EINVAL;
		
	tnode = (struct trill_node *) kmalloc (sizeof (struct trill_node), GFP_KERNEL | __GFP_ZERO);
	tnode->tn_ni = (struct trill_nickinfo *) kmalloc (size, GFP_KERNEL | __GFP_ZERO);
	memcpy(tnode->tn_ni,ni,size);
	tnode->tn_refs++;
	
	write_lock(&trill_inst->ti_rwlock);
	
	if( trill_inst->ti_nodes[nick] != NULL)
	    (void) trill_del_nick(trill_inst,nick,TRUE);
	
	if(self)
		trill_inst->ti_nick = nick;
 	
 	trill_inst->ti_nodes[nick] = tnode;
 	trill_inst->ti_nodecount++;
 	
 	write_unlock(&trill_inst->ti_rwlock);
	
	return 0;
}

int
trill_set_treeroot(uint16_t treeroot){

	if(!VALID_NICK(treeroot))
		return -EFAULT;
	
	write_lock(&trill_inst->ti_rwlock);
	trill_inst->ti_treeroot = treeroot;
	write_unlock(&trill_inst->ti_rwlock);
	
	return 0;
}



struct sk_buff *
create_trill_header(struct sk_buff *skb,struct trill_node *nick_entry,
					bool trill_header_ok,
					size_t msglen,
					bool multidest,
					unsigned short ingress_nick,
					unsigned short egress_nick,
					const unsigned char *source_addr)
{ 

	unsigned int extra_header_length;
	uint16_t ether_type; 
	struct trill_header *thdr; 
	struct ethhdr *out_eth_hdr;
     struct ethhdr *mac_header;

	ether_type = msglen > 0 ? (uint16_t)msglen : ETHERTYPE_TRILL;
	extra_header_length = sizeof (struct trill_header);
     skb_push(skb,ETH_HLEN);
    if( !pskb_expand_head(skb,20,0,GFP_ATOMIC)){    
        printk("\t\t\tAfter Expansion of the Buffer\n");
	    trill_testing(skb);
    }
    skb_reset_mac_header(skb);
    skb_pull(skb,ETH_HLEN);
    mac_header = eth_hdr(skb);

	if (mac_header == NULL){
		printk("mac_header Error\n");
	}
	skb_push(skb,ETH_HLEN);
	
	thdr = (struct trill_header *)skb_push(skb,extra_header_length);
	thdr->th_version =  TRILL_PROTOCOL_VERSION;
	thdr->th_reserved = TRILL_RESERVED_BITS;
	thdr->th_multidest =  (multidest ? 1:0);
	thdr->th_optslen_hi = 0;
	thdr->th_optslen_lo = 0;
	thdr->th_hopcount = TRILL_DEFAULT_HOPCOUNT;
	thdr->th_egressnick = egress_nick;
	thdr->th_ingressnick = ingress_nick;
	
	out_eth_hdr = (struct ethhdr *)skb_push(skb,ETH_HLEN);
	memcpy(out_eth_hdr->h_dest,nick_entry->tn_ni->tni_adjsnpa,ETH_ALEN);
	memcpy(out_eth_hdr->h_source,source_addr,ETH_ALEN);
	out_eth_hdr->h_proto = htons(ether_type); // ether_type Trill
	
	if(skb->data == out_eth_hdr){
		skb_set_mac_header(skb,0);
		skb_pull(skb,ETH_HLEN);
		mac_header = eth_hdr(skb);
	}
	printk("\t\t\tencapsulated Buffer\n");
	trill_testing(skb);
	
	return skb;
}

static void
trill_dest_fwd(struct sk_buff *skb, unsigned short adj_nick, 
			bool has_trill_header, bool multidest, unsigned short dtnick)
{
	struct trill_node *adj;
	unsigned short ingress_nick;
	struct net_device	*outdev;
	struct net *net = sock_net(skb->sk);
	
	printk("\t\t\ttrill_dest_fwd\n");
	
	adj = trill_node_lookup(adj_nick);
	if (adj == NULL)
		goto drop;
		
	read_lock(&trill_inst->ti_rwlock);
	ingress_nick = trill_inst->ti_nick;
	read_unlock(&trill_inst->ti_rwlock);
	
	if(!VALID_NICK(ingress_nick))
		goto drop;
		
	if(net == NULL){
		printk("\t\t\tnet is NULL\n");
		goto drop;
	}
	
	outdev = dev_get_by_index(net,adj->tn_ni->tni_ifindex);
		skb->dev = outdev;
	if(!has_trill_header)
		skb = create_trill_header( skb, adj, has_trill_header, 0, multidest, 
				ingress_nick, (multidest ? dtnick:adj_nick),
				 outdev->dev_addr);
	else 
		goto drop;
	/*else {
		thdr = (struct trill_header *)skb_pull(skb,extra_header_length);
		if (thdr->th_version !=  TRILL_PROTOCOL_VERSION)
			goto drop;
		if (thdr->th_reserved != TRILL_RESERVED_BITS)
			goto drop;
		if (thdr->th_multidest){
			thdr->th_hopcount--;
			if (thdr->th_hopcount == 0)
				goto drop;
		}
		
		thdr->th_egressnick = multidest ? dtnick:adj_nick;
		thdr->th_ingressnick = ingress_nick;
	
		out_eth_hdr = (struct ethhdr *)skb_push(skb,ETH_HLEN);
		memcpy(out_eth_hdr->h_dest,nick_entry->tn_ni->tni_adjsnpa,ETH_ALEN);
		memcpy(out_eth_hdr->h_source,source_addr,ETH_ALEN);
		out_eth_hdr->h_proto = htons(ether_type); // ether_type Trill
	
		if(skb->data == out_eth_hdr){
			skb_set_mac_header(skb,0);
			skb_pull(skb,ETH_HLEN);
			mac_header = eth_hdr(skb);
	}
	}*/
	if(skb == NULL)
		goto drop;
	
	
	if (skb_warn_if_lro(skb)) {
		goto drop;
	}
	
	skb_forward_csum(skb);
			
	br_dev_queue_push_xmit(skb);
	
	trill_node_unref(adj);
	return;
	
drop:
	kfree_skb(skb);
}

static void
trill_multidest_forward(struct sk_buff *skb,unsigned short egressnick,
					unsigned short ingressnick,bool is_trill_pkt,
					const unsigned char *source_addr,bool free_skb)
{
	int idx;
	unsigned short adjnick;
	struct trill_node *dest;
	struct trill_node *adj;
	struct sk_buff *skb1;
	bool nicksaved = FALSE;
	unsigned short adjnicksaved;
	
	    printk("\n\ntrill_multidest_forward\n");
	
	if ((dest = trill_node_lookup(egressnick)) == NULL)
		goto drop;
		
	for (idx = 0; idx < dest->tn_ni->tni_adjcount; idx++){
	
		adjnick = TNI_ADJNICK(dest->tn_ni,idx);
		if(!VALID_NICK(adjnick)  || ingressnick == adjnick ||
			((adj = trill_node_lookup(adjnick)) == NULL))
			continue;
			
		if ((source_addr != NULL) && 
			(memcmp(adj->tn_ni->tni_adjsnpa, source_addr, ETH_ALEN) == 0)){
			trill_node_unref(adj);
			continue;
		}
		
		//trill_node_unref(adj);
		
		if (free_skb && !nicksaved) {
			adjnicksaved = adjnick;
			nicksaved = TRUE;
			continue;
		}
		
		skb1 = skb_copy(skb,GFP_KERNEL);
		if(skb1 == NULL)
			break;
		trill_dest_fwd(skb1, adjnick, is_trill_pkt, FALSE, egressnick);
	}
	trill_node_unref(dest);
	
	if (nicksaved){
		trill_dest_fwd(skb, adjnicksaved, is_trill_pkt, TRUE, egressnick);
		return;
	}
	
drop:
	if(free_skb)
		kfree_skb(skb);
}

void
trill_broadcast_pkt(struct sk_buff *skb)
{
	struct sk_buff *skb1;
	unsigned short egressnick;
	unsigned short ingressnick;
	
	read_lock(&trill_inst->ti_rwlock);
	ingressnick = trill_inst->ti_nick;
	egressnick = trill_inst->ti_treeroot;
	read_unlock(&trill_inst->ti_rwlock);
	
	skb1 = skb_copy(skb,GFP_KERNEL);
	printk("\n\nTRILL_broadcast_pkt\n");

	    
	/*if(eth_hdr(skb)->h_proto == htons(ETHERTYPE_TRILL)){
		struct trill_header *thdr;
			
		thdr = (struct trill_header *)skb_pull(skb1,
							sizeof(struct trill_header));
		egressnick = thdr->th_egressnick;
		ingressnick = thdr->th_ingressnick;
		skb_push(skb1,sizeof(struct trill_header));
		//trill_multidest_forward(skb1,egressnick,ingressnick,TRUE,
			//		NULL,TRUE);
		skb = decapsulate_trill_header(skb);
	}	*/
	br_handle_frame_finish(skb);
	
	if( VALID_NICK(egressnick) && VALID_NICK(ingressnick))
	    trill_multidest_forward(skb1,egressnick,ingressnick,eth_hdr(skb1)->h_proto == htons(ETHERTYPE_TRILL) ? TRUE : FALSE,
						NULL,TRUE);
}


void
trill_recv_pkt(struct sk_buff *skb)
{
	const unsigned char *inner_dest;
	struct trill_header *thdr;
	struct ethhdr *mac_header;
	struct net_bridge_fdb_entry *dst;
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	unsigned short nick;
	
	printk("\n\ntrill_recv_pkt\n");
	
	

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return;
			
	if(eth_hdr(skb)->h_proto == htons(ETHERTYPE_TRILL)){
	
		thdr = (struct trill_header *)skb_pull(skb,sizeof(struct trill_header));
		
		if(!VALID_NICK(thdr->th_ingressnick) || !VALID_NICK(thdr->th_egressnick))
			goto drop;
	
		mac_header = (struct ethhdr *)skb_pull(skb,ETH_HLEN);

		if (!is_valid_ether_addr(mac_header->h_source))
			goto drop;

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (!skb)
			return;
		/*if (eth_hdr(skb)->h_source[5] == 0x4b){
	        decapsulate_trill_header(skb);
	        br_handle_frame_finish(skb);
	        return;
	    }*/
	    
		br_fdb_update(p->br, p, mac_header->h_source,thdr->th_ingressnick);
		inner_dest = mac_header->h_dest;
		if (!compare_ether_addr(inner_dest, broadcast_addr1)){
			skb_push(skb,ETH_HLEN);
			skb_push(skb,sizeof(struct trill_header));
			//trill_broadcast_pkt(skb);
			decapsulate_trill_header(skb);
			br_handle_frame_finish(skb);
			return;
		}
		
		read_lock(&trill_inst->ti_rwlock);
		nick = trill_inst->ti_nick;
		read_unlock(&trill_inst->ti_rwlock);
		
		dst = __br_fdb_get(p->br, inner_dest,nick);
		if(!dst && thdr->th_egressnick == nick){
			skb_push(skb,ETH_HLEN);
			skb_push(skb,sizeof(struct trill_header));
			skb = decapsulate_trill_header(skb);
			br_flood_forward(p->br, skb, NULL);
		
		} /* If true then, packet is destined to us */
		else if(!VALID_NICK(dst->vlan_id) && 
					thdr->th_egressnick == nick){ 
			skb_push(skb,ETH_HLEN);
			skb_push(skb,sizeof(struct trill_header));
			skb = decapsulate_trill_header(skb);
			if (skb) 
					br_forward(dst->dst, skb, NULL);
		}
		else if(VALID_NICK(dst->vlan_id) && 
			dst->vlan_id == thdr->th_egressnick &&
			thdr->th_hopcount > 0){
			struct trill_node *nick_entry;
			struct net_device	*outdev;
			struct net *net = sock_net(skb->sk);

			nick_entry = trill_node_lookup(thdr->th_egressnick);
			if(nick_entry == NULL)
				goto drop;
				
			skb_push(skb,ETH_HLEN);
			skb_push(skb,sizeof(struct trill_header));
			
			memcpy(eth_hdr(skb)->h_dest,nick_entry->tn_ni->tni_adjsnpa,ETH_ALEN);
			
			outdev = dev_get_by_index(net,nick_entry->tn_ni->tni_ifindex);
			
			memcpy(eth_hdr(skb)->h_source,outdev->dev_addr,ETH_ALEN);
			
			if (skb_warn_if_lro(skb)) {
				goto drop;
			}
			
			skb->dev = outdev;
			skb_forward_csum(skb);
			
			br_dev_queue_push_xmit(skb);
				
 		}
		else 
			goto drop;	
	}
	
out:
	return;	

drop:
	kfree_skb(skb);
	goto out;

}


void
trill_encap_pkt(struct sk_buff *skb){

	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	struct net_bridge *br;
	struct net_bridge_fdb_entry *dst;
	
	
	printk("\n\ntrill_encap_pkt\n");
	

	if (!p || p->state == BR_STATE_DISABLED)
		goto drop;

		printk("\n\ntrill_encap_pkt1\n");

	/* insert into forwarding database after filtering to avoid spoofing */
	br = p->br;
	
	BR_INPUT_SKB_CB(skb)->brdev = br->dev;
	
	printk("\n\ntrill_encap_pkt2\n");
	
	br_fdb_update(p->br, p, eth_hdr(skb)->h_source,RBRIDGE_NICKNAME_NONE);
	printk("\n\ntrill_encap_pkt3\n");
	
	/*if (!compare_ether_addr(dest, broadcast_addr1)){
		printk("\t\t\tMOHSIN 2\n");
		trill_broadcast_pkt(skb);
		return;
	}*/
		printk("\n\ntrill_encap_pkt4\n");

    if (is_multicast_ether_addr(dest)){
	    printk("\t\t\tMOHSIN 1\n");
		br_handle_frame_finish(skb);
		return;
	}
	
		printk("\n\ntrill_encap_pkt5\n");

	
	/*if (eth_hdr(skb)->h_dest[5] == 0x4b){
	    skb = create_trill_header1(skb,FALSE,0);
	    br_handle_frame_finish(skb);
	    return;
	}
	
	if(eth_hdr(skb)->h_proto == htons(0x806)){
	    br_handle_frame_finish(skb);
	    return;
	}*/
	
//	dst = __br_fdb_get(br, dest,dst->vlan_id);
	dst = __br_fdb_get(br, dest,0);

//	dst = __br_fdb_get(br, dest);

	printk("\n\ntrill_encap_pkt5.5\n");
	//printk("\n\ntrill_encap_pkt5.6: %u\n",dst->vlan_id);
	printk("\n\ntrill_encap_pkt5.7: %u\n",dst->trill_nickname);
	
	printk("\n\ntrill_encap_pkt6\n");
	 
	if(!VALID_NICK(dst->vlan_id)){
	    printk("\t\t\tMOHSIN 3\n");
		br_handle_frame_finish(skb);
		return;
	}
    else if (VALID_NICK(dst->vlan_id) && is_unicast_ether_addr(dest)){
        printk("\t\t\tMOHSIN 4\n");
	    trill_dest_fwd(skb, dst->vlan_id, FALSE, FALSE, 0);
	}
	return;
		
drop:
	printk("\n\ntrill_encap_pkt7\n");
	kfree_skb(skb);	
}

struct sk_buff *
decapsulate_trill_header(struct sk_buff *skb)
{  
     trill_testing(skb);
	skb_pull(skb,sizeof(struct trill_header));
	skb_set_mac_header(skb,0);
	skb_pull(skb,ETH_HLEN);
	printk("\t\t\tdecapsulated Buffer\n");
	trill_testing(skb);

	return skb;
}

void space_check(struct sk_buff *skb)
{

    int mtu;
    unsigned int max_headroom;
    
    mtu = skb_dst(skb) ? dst_mtu(skb_dst(skb)) : skb->dev->mtu;
	
	printk("mtu\t%d\n",mtu);
    
	//othmen Modif
  // if (skb_dst(skb))
  //		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), mtu);
		
	max_headroom = LL_RESERVED_SPACE(skb->dev) + 6 + 14;

    printk("needed_headroom %u\n",skb->dev->needed_headroom);
    printk("needed_tailroom %u\n",skb->dev->needed_tailroom);
    //printk("no. of snd bytes %d\n",skb->sk->sk_sndbuf);
    
    printk("mem_start %ld\n",skb->dev->mem_start);
    
	printk("mem_end %ld\n",skb->dev->mem_end);
 
		if (max_headroom > skb->dev->needed_headroom)
			skb->dev->needed_headroom = max_headroom;
	
	printk("needed_headroom %u\n",skb->dev->needed_headroom);

	skb_reset_mac_header(skb);

}

int __init trill_init(void)
{
	
	trill_inst = (struct trill_inst *)kmalloc(sizeof(struct trill_inst),GFP_ATOMIC | __GFP_ZERO);
	
	if (!trill_inst)
		return -ENOMEM;
	rwlock_init(&trill_inst->ti_rwlock);
	
	printk("\t\t TRILL INSTANCE INIT\n");

	return 0;
}

void __exit trill_fini(void)
{
	kfree(trill_inst);
}

//module_init(trill_init)
//module_exit(trill_fini)
//MODULE_LICENSE("GPL");
//MODULE_VERSION(BR_VERSION);
/*#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include "br_private.h"

#define TRILL_PROTOCOL_VERSION 0

#define TRILL_RESERVED_BITS 0

#define TRILL_UNICAST 0

#define DEFAULT_HOPCOUNT 10

#define ETHERTYPE_TRILL 0x22f3



struct sk_buff *decapsulate_trill_header(struct sk_buff *skb); 

struct sk_buff *create_trill_header(struct sk_buff *skb,bool trill_header_ok,size_t msglen);

struct trill_header {

	uint8_t th_version : 2;  // Version of the protocol
	
	uint8_t th_reserved : 2;   //Reserved field
	
	uint8_t th_multidest : 1;  // Unicast vs. Multidestination frame
	
	uint8_t th_optslen_hi : 3;   // Options length high

	uint8_t th_optslen_lo : 2;  // Options length low
	
	uint8_t th_hopcount : 6;   // Hop count

	uint16_t th_egressnick;   // Egress nick
	
	uint16_t th_ingressnick;  // Ingress nick
};
         
         
         
void trill_testing(struct sk_buff *skb)
{
    unsigned int len = skb->len;
    unsigned int data_len = skb->data_len;
    unsigned int mac_len = skb->mac_len;
    unsigned int hdr_len = skb->hdr_len;
    unsigned char *data = skb->data;
    //unsigned char *tail = skb->tail;
    unsigned int i=0;
    
    
    printk("length of buffer is %u\n", len );
    
    printk("length of data in buffer is %u\n", data_len );
    
    printk("length of mac_len is %hu\t and hdr_len is %hu\n", mac_len,hdr_len );
    
    printk("TRUE SIZE %u\n",skb->truesize);
    
    printk("headroom %d\n",skb_headroom(skb));
    
    printk("source %lx \t dest %lx \t ether_type %hx \n",*(eth_hdr(skb)->h_source),*(eth_hdr(skb)->h_dest),htons(eth_hdr(skb)->h_proto));
    
    printk("\t\t\tDATA\n");
    
    for(i = 0; i < len ; i++)
        printk("%2hx\t", *(data + i));
    
    printk("\n\t\t\tDONE\n");
   
}


//
struct sk_buff *create_trill_header1(struct sk_buff *skb,bool trill_header_ok,size_t msglen)
{ 

	unsigned int extra_header_length;
	uint16_t ether_type; 
	struct trill_header *push1;
	struct ethhdr *push2; 
	struct ethhdr *push3;
    struct ethhdr *mac_header;
    int     mtu;
    unsigned int max_headroom;
	
	
	ether_type = msglen > 0 ? (uint16_t)msglen : ETHERTYPE_TRILL;

	extra_header_length = trill_header_ok ? 0 : sizeof (struct trill_header); 

	
	
    printk("\t\t\tOriginal Buffer\n");
	
	trill_testing(skb);
    
    skb_push(skb,ETH_HLEN);
    
    //skb2 = skb_copy_expand(skb,20 + skb_headroom(skb),20,GFP_ATOMIC);
    if( !pskb_expand_head(skb,20,0,GFP_ATOMIC) )
    {    
        printk("\t\t\tAfter Expansion of the Buffer\n");
	    trill_testing(skb);
    }
    
    skb_reset_mac_header(skb);
    
    skb_pull(skb,ETH_HLEN);
    
    mac_header = eth_hdr(skb);
   
	//struct trill_header trill_header_data = {0x00,0x15,0x1500,0x1600}; // for testing purpose, it is hardcoded

	if (mac_header == NULL)
	{
		// error handling
		printk("mac_header Error\n");
	}
	
	//printk("\t\t\tAfter headroom allocation Buffer\n");
	
	//trill_testing(skb);

	/*if ( skb_headroom(skb) < 2*sizeof(struct ethhdr ) + sizeof(struct trill_header) )
	{
		skb = skb_realloc_headroom(skb,34);
		printk("\t\t\tHEADROOM ALLOCATION\n");
	}//
	
	push2 = (struct ethhdr *)skb_push(skb,ETH_HLEN);
	
	//push2->h_dest = mac_header->h_dest;
	
	//push2->h_source = mac_header->h_source;
	memcpy(push2->h_dest,mac_header->h_dest,ETH_ALEN);
	
	memcpy(push2->h_source,mac_header->h_source,ETH_ALEN);
	
	push2->h_proto = htons(0x0800); // ether_type IP
	
	push1 = (struct trill_header *)skb_push(skb,extra_header_length);
	
	push1->th_version =  TRILL_PROTOCOL_VERSION;
	
	push1->th_reserved = TRILL_RESERVED_BITS;
	
	push1->th_multidest =  TRILL_UNICAST;
	
	push1->th_optslen_hi = 0;

	push1->th_optslen_lo = 0;
	
	push1->th_hopcount = TRILL_DEFAULT_HOPCOUNT;
	
	push1->th_egressnick = htons(0x1600);
	
	push1->th_ingressnick = htons(0x1500);
	
	//memcpy(push1,&trill_header_data,extra_header_length);
	
	push3 = (struct ethhdr *)skb_push(skb,ETH_HLEN);
	
	//push2->h_dest = mac_header->h_dest;
	
	//push2->h_source = mac_header->h_source;
	memcpy(push3->h_dest,mac_header->h_dest,ETH_ALEN);
	
	memcpy(push3->h_source,mac_header->h_source,ETH_ALEN);
	
	push3->h_proto = htons(0x22f3); // ether_type Trill
	
	if(skb->data == push3)
	{
	skb_set_mac_header(skb,0);
	
	skb_pull(skb,ETH_HLEN);
	
	mac_header = eth_hdr(skb);
	
	}
	
	
	//printk("rmeme_end %ld\n",skb->dev->rmem_end);
	
	//printk("rmeme_start %ld\n",skb->dev->rmem_start);
	
	//skb->dev->mem_end += 20;
	
	//printk("meme_end %ld",skb->dev->mem_end);
	
	//skb->truesize += 20;
	//mac_header->h_proto = htons(ETHERTYPE_TRILL);
	
	//memcpy(push2,mac_header,ETH_HLEN);
	/*if (skb2 == NULL)
	{
	    //error handling
	    printk("skb2 is NULL");
	}
	else 
	{
	    printk("\t\t\tencapsulated Buffer 2\n");
	    
	    kfree_skb(skb);
	    
	    trill_testing(skb2);
	    
	    return skb2;
	}//
	printk("\t\t\tencapsulated Buffer\n");
	
	trill_testing(skb);
	
	return skb;
	
}
*/
/*
struct sk_buff *decapsulate_trill_header(struct sk_buff *skb)
{

	struct ethhdr *eth = eth_hdr(skb);
   
    trill_testing(skb);
	
	//eth->h_proto = htons(0x0800);
	//if(skb->data == eth)
	skb_pull(skb,6);
	//else
	//skb_pull(skb,6);
	printk("eth_hdr  %lx\n",eth);
	printk("skb->head  %lx\n",skb->head);
	printk("skb->data  %lx\n",skb->data);
	
	skb_set_mac_header(skb,0);
	
	skb_pull(skb,ETH_HLEN);

    //if(skb->protocol == htons(0x22f3)){
    //skb->protocol = htons(0x0800);	
    //printk("skb->protocol change\n");}
	//skb_pull(skb,14);
	
	printk("\t\t\tdecapsulated Buffer\n");
	
	trill_testing(skb);


	return skb;
}


void space_check(struct sk_buff *skb)
{

    int mtu;
    unsigned int max_headroom;
    
    mtu = skb_dst(skb) ? dst_mtu(skb_dst(skb)) : skb->dev->mtu;
	
	printk("mtu\t%d\n",mtu);
    
   if (skb_dst(skb))
		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), mtu);
		
	max_headroom = LL_RESERVED_SPACE(skb->dev) + 6 + 14;

    printk("needed_headroom %u\n",skb->dev->needed_headroom);
    printk("needed_tailroom %u\n",skb->dev->needed_tailroom);
    //printk("no. of snd bytes %d\n",skb->sk->sk_sndbuf);
    
    printk("mem_start %ld\n",skb->dev->mem_start);
    
	printk("mem_end %ld\n",skb->dev->mem_end);
 
		//struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
		if (max_headroom > skb->dev->needed_headroom)
			skb->dev->needed_headroom = max_headroom;
	
	printk("needed_headroom %u\n",skb->dev->needed_headroom);

	skb_reset_mac_header(skb);

}*/
