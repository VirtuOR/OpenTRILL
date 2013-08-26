/*
 *	Bridge netlink control interface
 *
 *	Authors:
 *	Stephen Hemminger		<shemminger@osdl.org>
 *  	Syed M. Mohsin Kazmi    	<08beesmmkazmi@seecs.edu.pk>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/rtnetlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include "br_private.h"
#include "trill.h"

static inline size_t br_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ifinfomsg))
	       + nla_total_size(IFNAMSIZ) // IFLA_IFNAME */
	       + nla_total_size(MAX_ADDR_LEN) // IFLA_ADDRESS 
	       + nla_total_size(4) // IFLA_MASTER 
	       + nla_total_size(4) // IFLA_MTU 
	       + nla_total_size(4) // IFLA_LINK */
	       + nla_total_size(1) // IFLA_OPERSTATE */
	       + nla_total_size(1); // IFLA_PROTINFO */
}

/*
 * Create one netlink message for one interface
 * Contains port and master info as well as carrier and bridge state.
 */
static int br_fill_ifinfo(struct sk_buff *skb, const struct net_bridge_port *port,
			  u32 pid, u32 seq, int event, unsigned int flags)
{
	const struct net_bridge *br = port->br;
	const struct net_device *dev = port->dev;
	struct ifinfomsg *hdr;
	struct nlmsghdr *nlh;
	u8 operstate = netif_running(dev) ? dev->operstate : IF_OPER_DOWN;

	br_debug(br, "br_fill_info event %d port %s master %s\n",
		     event, dev->name, br->dev->name);

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*hdr), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	hdr = nlmsg_data(nlh);
	hdr->ifi_family = AF_TRILL;
	hdr->__ifi_pad = 0;
	hdr->ifi_type = dev->type;
	hdr->ifi_index = dev->ifindex;
	hdr->ifi_flags = dev_get_flags(dev);
	hdr->ifi_change = 0;

	nla_put_string(skb, IFLA_IFNAME, dev->name);
	nla_put_u32(skb, IFLA_MASTER, br->dev->ifindex);
	nla_put_u32(skb, IFLA_MTU, dev->mtu);
	nla_put_u8(skb, IFLA_OPERSTATE, operstate);

	if (dev->addr_len)
		nla_put(skb, IFLA_ADDRESS, dev->addr_len, dev->dev_addr);

	if (dev->ifindex != dev->iflink)
		nla_put_u32(skb, IFLA_LINK, dev->iflink);

	if (event == RTM_NEWLINK)
		nla_put_u8(skb, IFLA_PROTINFO, port->state);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/*
 * Notify listeners of a change in port information
 */
void br_ifinfo_notify(int event, struct net_bridge_port *port)
{
	struct net *net = dev_net(port->dev);
	struct sk_buff *skb;
	int err = -ENOBUFS;

	br_debug(port->br, "port %u(%s) event %d\n",
		 (unsigned)port->port_no, port->dev->name, event);

	skb = nlmsg_new(br_nlmsg_size(), GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	err = br_fill_ifinfo(skb, port, 0, 0, event, 0);
	if (err < 0) {
		// -EMSGSIZE implies BUG in br_nlmsg_size() 
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	rtnl_notify(skb, net, 0, RTNLGRP_LINK, NULL, GFP_ATOMIC);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_LINK, err);
}

/*
 * Dump information about all ports, in response to GETLINK
 */
static int trill_dump_ifinfo(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct net_device *dev;
	int idx;

	idx = 0;
	for_each_netdev(net, dev) {
		struct net_bridge_port *port = br_port_get_rtnl(dev);

		// not a bridge port 
		if (!port || idx < cb->args[0])
			goto skip;

		if (br_fill_ifinfo(skb, port,
				   NETLINK_CB(cb->skb).portid,
				   cb->nlh->nlmsg_seq, RTM_NEWLINK,
				   NLM_F_MULTI) < 0)
			break;
skip:
		++idx;
	}

	cb->args[0] = idx;

	return skb->len;
}

/*
 * Change state of port (ie from forwarding to blocking etc)
 * Used by spanning tree in user space.
 */
static int trill_rtm_setlink(struct sk_buff *skb,  struct nlmsghdr *nlh, void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct ifinfomsg *ifm;
	struct nlattr *protinfo;
	struct net_device *dev;
	struct net_bridge_port *p;
	u8 new_state;

	if (nlmsg_len(nlh) < sizeof(*ifm))
		return -EINVAL;

	ifm = nlmsg_data(nlh);
	if (ifm->ifi_family != AF_TRILL)
		return -EPFNOSUPPORT;

	protinfo = nlmsg_find_attr(nlh, sizeof(*ifm), IFLA_PROTINFO);
	if (!protinfo || nla_len(protinfo) < sizeof(u8))
		return -EINVAL;

	new_state = nla_get_u8(protinfo);
	if (new_state > BR_STATE_BLOCKING)
		return -EINVAL;

	dev = __dev_get_by_index(net, ifm->ifi_index);
	if (!dev)
		return -ENODEV;

	p = br_port_get_rtnl(dev);
	if (!p)
		return -EINVAL;

	// if kernel STP is running, don't allow changes 
	if (p->br->stp_enabled == BR_KERNEL_STP)
		return -EBUSY;

	if (!netif_running(dev) ||
	    (!netif_carrier_ok(dev) && new_state != BR_STATE_DISABLED))
		return -ENETDOWN;

	p->state = new_state;
	br_log_state(p);
	return 0;
}


/*
 * set trill nick from user space deamon
 */
static int trill_rtm_setnick(struct sk_buff *skb,  struct nlmsghdr *nlh, void *arg)
{
	//struct net *net = sock_net(skb->sk);
	struct trill_nickinfo *ni;
	struct nlattr *attrptr;
	struct rtgenmsg *rtgenmsg;
	
	printk("\n\n\t\ttrill_rtm_setnick\n\n");
	//goto drop;

	if (nlmsg_len(nlh) < sizeof(struct rtgenmsg) + sizeof(struct trill_nickinfo))
		return -EINVAL;

	rtgenmsg = nlmsg_data(nlh);
	if (rtgenmsg->rtgen_family != AF_TRILL)
		return -EPFNOSUPPORT;
		
	attrptr = nlmsg_attrdata(nlh,sizeof(struct rtgenmsg));
	
	if (!attrptr || nla_len(attrptr) < sizeof(struct trill_nickinfo))
		return -EINVAL;
	
	ni = (struct trill_nickinfo *) nla_data(attrptr);
	//ni = nlmsg_data(nlh);
	//if (!ni )
		//return -EINVAL;
    
    if (attrptr->nla_type == 1)
    	trill_add_nick(ni,TRUE);
    if (attrptr->nla_type == 2)
    	trill_add_nick(ni,FALSE);
	
	return 0;
}


/*
 * get trill nick and send it to user space deamon
 */
/*static int trill_dump_getnick(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct net_device *dev;
	//int idx;

	//idx = 0;
	//for_each_netdev(net, dev) {
		struct net_bridge_port *port = br_port_get_rtnl(dev);

		/* not a bridge port //
		//if (!port)
			//goto skip;

		if (br_fill_ifinfo(skb, port,
				   NETLINK_CB(cb->skb).pid,
				   cb->nlh->nlmsg_seq, RTM_NEWLINK,
				   NLM_F_MULTI) < 0)
			//break;
//skip:
	//	++idx;
	}

	cb->args[0] = idx;

	return skb->len;
}
*/

/*
 * set trill tree root from user space deamon
 */
static int trill_rtm_set_treeroot(struct sk_buff *skb,  struct nlmsghdr *nlh, void *arg)
{
	struct nlattr *treeroot;
	struct rtgenmsg *rtgenmsg;
	//struct net *net = sock_net(skb->sk);
	uint16_t tree_root;
	
	printk("\t\ttrill_rtm_set_treeroot\n");
	//goto drop;
	
	if (nlmsg_len(nlh) < sizeof(struct rtgenmsg) + sizeof(uint16_t))
		return -EINVAL;
	
	rtgenmsg = nlmsg_data(nlh);
	if (rtgenmsg->rtgen_family != AF_TRILL)
		return -EPFNOSUPPORT;

	treeroot = nlmsg_attrdata(nlh,sizeof(struct rtgenmsg));
	if (!treeroot || nla_len(treeroot) < sizeof(u16))
		return -EINVAL;
	
	if(treeroot->nla_type != 1)
		return -EINVAL;
	tree_root = nla_get_u16(treeroot);
	printk("\t\t TREE ROOT = %x\n",tree_root);
	
	return trill_set_treeroot(tree_root);

}


/*
 * list trill nicks and send it to user space deamon
 */
/*static int trill_rtm_lisknick(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct net_device *dev;
	//int idx;

	//idx = 0;
	//for_each_netdev(net, dev) {
		struct net_bridge_port *port = br_port_get_rtnl(dev);

		/* not a bridge port //
		//if (!port)
			//goto skip;

		if (br_fill_ifinfo(skb, port,
				   NETLINK_CB(cb->skb).pid,
				   cb->nlh->nlmsg_seq, RTM_NEWLINK,
				   NLM_F_MULTI) < 0)
			//break;
//skip:
	//	++idx;
	}

	cb->args[0] = idx;

	return skb->len;
}
*/

int __init trill_netlink_init(void)
{
	if (__rtnl_register(PF_TRILL, RTM_GETLINK, NULL, trill_dump_ifinfo, NULL))
		return -ENOBUFS;

	// Only the first call to __rtnl_register can fail 
	if (__rtnl_register(PF_TRILL, RTM_SETLINK, trill_rtm_setlink, NULL, NULL) < 0)
		printk("\t\ttrill_rtm_setlink error\n");


	if (__rtnl_register(PF_TRILL, RTM_SETNICK, trill_rtm_setnick, NULL, NULL))
		printk("\t\ttrill_rtm_setnick error\n");
	
	//if (__rtnl_register(PF_TRILL, RTM_NEWROUTE, trill_rtm_setnick, NULL))
		//printk("\t\ttrill_rtm_setnick 2 error\n");
	
	//__rtnl_register(PF_TRILL, RTM_GETNICK, NULL, trill_dump_getnick);
	
	if (__rtnl_register(PF_TRILL, RTM_TREEROOT, trill_rtm_set_treeroot, NULL, NULL) < 0)
		printk("\t\ttrill_rtm_set_treerooot error\n");
	
	//__rtnl_register(PF_TRILL, RTM_LISTNICK, NULL, trill_rtm_lisknick);
	
	return 0;
}

void __exit trill_netlink_fini(void)
{
	rtnl_unregister_all(PF_TRILL);
}


