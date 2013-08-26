/*
 * IS-IS Rout(e)ing protocol - isis_trillio.c
 *
 * Copyright (C) 2001,2002    Sampo Saaristo
 *                            Tampere University of Technology      
 *                            Institute of Communications Engineering
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
#include <net/ethernet.h>	/* the L2 protocols */
#include <netpacket/packet.h>
//#include <net/if_dl.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <libmnl/libmnl.h>
//#include <sys/ethernet.h>
//#include <net/trill.h>
//#include <net/bridge.h>

#include "log.h"
#include "stream.h"
#include "network.h"
#include "if.h"
#include "vty.h"

#include "isisd/dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isisd.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_network.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_vlans.h"
#include "isisd/isis_trill.h"
#include "isisd/isis_kernel_trill.h"

#include "privs.h"

extern struct zebra_privs_t isisd_privs;

#define AF_TRILL 7
#define PF_TRILL AF_TRILL

#define NETLINK_NITRO 17

static u_char sock_buff[32000];

static const uint8_t all_isis_rbridges[] = ALL_ISIS_RBRIDGES;
static const uint8_t bridge_group_address[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

static int data_attr_cb(const struct nlattr *attr, struct isis_circuit *circuit)
{

unsigned char addr[6];
	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	switch(mnl_attr_get_type(attr)) {
	case IFLA_MTU:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		//printf("mtu=%d ", mnl_attr_get_u32(attr));
		circuit->interface->mtu = mnl_attr_get_u32(attr);
		printf("mtu=%d ", circuit->interface->mtu);
		break;
	case IFLA_IFNAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate2");
			return MNL_CB_ERROR;
		}
		printf("name=%s ", mnl_attr_get_str(attr));
		break;
	case IFLA_ADDRESS:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,ETH_ALEN) < 0) {
			perror("mnl_attr_validate2");
			return MNL_CB_ERROR;
		}
		memcpy(addr,(unsigned char *)mnl_attr_get_payload(attr),ETH_ALEN);
		printf("HW address of interface is: %02X:%02X:%02X:%02X:%02X:%02X\n",
    addr[0],addr[1],addr[2],addr[3],addr[4],addr[5] );
    memcpy(&circuit->u.bc.snpa,addr,ETH_ALEN);
		break;
	}
	return MNL_CB_OK;
}


static int data_cb(const struct nlmsghdr *nlh, struct isis_circuit *circuit)
{
	struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
     
     if(circuit->interface->ifindex != ifm->ifi_index)
     return MNL_CB_OK;
     
	printf("index=%d type=%d flags=%d family=%d ", 
		ifm->ifi_index, ifm->ifi_type,
		ifm->ifi_flags, ifm->ifi_family);

	if (ifm->ifi_flags & IFF_RUNNING)
		printf("[RUNNING] ");
	else
		printf("[NOT RUNNING] ");

	mnl_attr_parse(nlh, sizeof(*ifm), data_attr_cb, circuit);
	printf("\n");
	return MNL_CB_OK;
}

static struct sock_filter trill_filter[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x25, 3, 0, 0x000005dc },
	{ 0x30, 0, 0, 0x0000000e },
	{ 0x15, 0, 1, 0x00000042 },
	{ 0x6, 0, 0, 0x00000060 },
	{ 0x6, 0, 0, 0x00000000 },
	{ 0x6, 0, 0, 0x0000ffff },
};

static int
open_trill_socket (struct isis_circuit *circuit)
{
  struct sockaddr_ll s_addr;
  struct ifreq interface;
  int fd;
  //unsigned int mtu;
  
  struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct rtgenmsg *rt;
	int ret;
	unsigned int seq, portid;
	
	circuit->fd = -1;
	circuit->fd_netlink = -1;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl->fd < 0)
    {
      zlog_warn ("open_trill_socket(): socket() failed %s",
		 safe_strerror (errno));
      return ISIS_ERROR;
    }
  
if (set_nonblocking (nl->fd) < 0)
    {
      zlog_warn ("open_trill_socket(): set_nonblocking() failed: %s",
	  safe_strerror (errno));
      mnl_socket_close(nl);
      return ISIS_ERROR;
    }
    
    struct sock_fprog prog = {
		.len = sizeof(trill_filter) / sizeof(trill_filter[0]),
		.filter = trill_filter,
	};

  fd = socket (PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
  if (fd < 0)
    {
      zlog_warn ("open_trill_socket(): socket() failed %s",
		 safe_strerror (errno));
      return ISIS_ERROR;
    }
    
  /*if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
  {
	zlog_warn ("setsockopt packet filter failed: %s",
	safe_strerror (errno));
      return ISIS_ERROR;
  }*/
  if (set_nonblocking (fd) < 0)
    {
      zlog_warn ("open_trill_socket(): set_nonblocking() failed: %s",
	  safe_strerror (errno));
      close (fd);
      return ISIS_ERROR;
    }

  /*if (ioctl (fd, TRILL_NEWBRIDGE, &circuit->area->trill->name) < 0)
    {
    	printf("mohsin 1\n");
      zlog_warn ("open_trill_socket(): TRILL_NEWBRIDGE ioctl failed: %s",
	  safe_strerror (errno));
      close (fd);
      return ISIS_ERROR;
    }
  */
  /*
   * Bind to the physical interface that must be one of the 
   * links in the bridge instance.
   */
   
   if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    	printf("mohsin 2\n");
      zlog_warn ("open_trill_socket(): bind() failed: %s",
	  safe_strerror (errno));
      mnl_socket_close(nl);
      return ISIS_ERROR;
    }
	portid = mnl_socket_get_portid(nl);
	
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);
	rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
	rt->rtgen_family = PF_TRILL;
	
	if (mnl_socket_sendto(nl->fd, nlh, nlh->nlmsg_len) < 0) {
    	printf("mohsin 3\n");
      zlog_warn ("open_trill_socket(): TRILL_HWADDR failed: %s",
	  safe_strerror (errno));
      mnl_socket_close(nl);
      return ISIS_ERROR;
    }
    
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, data_cb, circuit);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
	
		printf("ERROR\n");
		perror("error");
		exit(EXIT_FAILURE);
	}
    
  memset (&s_addr, 0, sizeof (struct sockaddr_ll));
  s_addr.sll_family = AF_PACKET;
  s_addr.sll_protocol = htons (ETH_P_ALL);
  s_addr.sll_ifindex = circuit->interface->ifindex;

  if (bind (fd, (struct sockaddr *) (&s_addr), sizeof (struct sockaddr_ll)) < 0)
    {
    	printf("mohsin 2\n");
      zlog_warn ("open_trill_socket(): bind() failed: %s",
	  safe_strerror (errno));
      close (fd);
      return ISIS_ERROR;
    }

	/*memcpy(interface.ifr_name,circuit->interface->name,IFNAMSIZ);

  if (ioctl (fd, SIOCGIFHWADDR, (char *)&interface) < 0)
    {
    	printf("mohsin 3\n");
      zlog_warn ("open_trill_socket(): TRILL_HWADDR ioctl failed: %s",
	  safe_strerror (errno));
      close (fd);
      return ISIS_ERROR;
    }
    
     printf("fetched HW address with ioctl on sockfd.\n");
  printf("HW address of interface is: %02X:%02X:%02X:%02X:%02X:%02X\n",
    (unsigned char)interface.ifr_ifru.ifru_hwaddr.sa_data[0],
    (unsigned char)interface.ifr_ifru.ifru_hwaddr.sa_data[1],
    (unsigned char)interface.ifr_ifru.ifru_hwaddr.sa_data[2],
    (unsigned char)interface.ifr_ifru.ifru_hwaddr.sa_data[3],
    (unsigned char)interface.ifr_ifru.ifru_hwaddr.sa_data[4],
    (unsigned char)interface.ifr_ifru.ifru_hwaddr.sa_data[5]
  );

	memcpy(&circuit->u.bc.snpa,interface.ifr_ifru.ifru_hwaddr.sa_data,ETH_ALEN);

  if (ioctl (fd, SIOCGIFMTU, &interface) < 0)
    zlog_warn ("open_trill_socket(): TRILL_GETMTU ioctl failed: %s",
	safe_strerror (errno));
  else {
  printf("fetched mtu with ioctl on sockfd.\n");
  printf("mtu of interface is: %d\n",interface.ifr_mtu);
    circuit->interface->mtu = interface.ifr_mtu;
  }

  if (interface.ifr_mtu > sizeof (sock_buff))
    zlog_err ("open_trill_socket(): interface mtu:%d is greater than "
        " sock_buff size:%d", interface.ifr_mtu, sizeof (sock_buff));
*/
//printf("####################################\n");

  circuit->fd_netlink = nl->fd;
  circuit->port_id = portid;
  printf("ID************ %d\nPort Id ************** %d\n",nl->fd,circuit->port_id);
  circuit->fd = fd;
  return ISIS_OK;
}

/*
 * Create the socket and set the tx/rx funcs
 */
int
isis_sock_init (struct isis_circuit *circuit)
{
  int retval;

  if (isisd_privs.change (ZPRIVS_RAISE))
    zlog_err ("%s: could not raise privs, %s", __func__, safe_strerror (errno));

  circuit->tx = isis_send_pdu_bcast;
  circuit->rx = isis_recv_pdu_bcast;

  retval = open_trill_socket (circuit);

  if (retval != ISIS_OK)
    {
    	printf("mohsin 4\n");
      zlog_warn ("%s: could not initialize the socket", __func__);
      goto end;
    }

  if (circuit->circ_type == CIRCUIT_T_P2P)
    {
    	printf(" mohsin 5\n");
      retval = ISIS_ERROR;
      zlog_err ("%s: do not support P2P link ", __func__);
    }
  else if (circuit->circ_type != CIRCUIT_T_BROADCAST)
    {
    	printf("mohsin 6\n");
      zlog_warn ("%s: unknown circuit type", __func__);
      retval = ISIS_WARNING;
    }

end:
  if (isisd_privs.change (ZPRIVS_LOWER))
    zlog_err ("%s: could not lower privs, %s", __func__, safe_strerror (errno));

  return retval;
}

int
isis_recv_pdu_bcast (struct isis_circuit *circuit, u_char * ssnpa)
{
  int bytesread, addr_len;
  struct sockaddr_ll d_addr;
  char *llsaddr;
  uint16_t tci;
  uint8_t sap; 
  static int p = 0;
//printf("**********************RECEIVED************************\n");
  if (circuit->fd == -1)
    return ISIS_ERROR;

  /* we have to read to the static buff first */
  addr_len = sizeof (struct sockaddr_ll);
  bytesread = recvfrom (circuit->fd, sock_buff, sizeof (sock_buff),
			MSG_DONTWAIT, (struct sockaddr *) &d_addr,
			(socklen_t *) &addr_len);

  if (bytesread < 0 && errno == EWOULDBLOCK){
  
    return ISIS_WARNING;
}
  //if (d_addr.sdl_slen != sizeof (tci) || d_addr.sdl_alen != ETHERADDRL)
    //return ISIS_ERROR;

  if (bytesread < LLC_LEN)
    return ISIS_WARNING;

  //llsaddr = LLADDR(&s_addr);
  memcpy (ssnpa, &d_addr.sll_addr, d_addr.sll_halen);
  /*printf("HW address of received packet is: %02X:%02X:%02X:%02X:%02X:%02X\n",
    *ssnpa,*(ssnpa+1),*(ssnpa+2),*(ssnpa+3),*(ssnpa+4),*(ssnpa+5));*/
    
  tci = *(uint16_t *)(d_addr.sll_addr + d_addr.sll_halen);
  
 /* printf("HW address of received tx_tci is: %02X%02X\n",
    (unsigned char )d_addr.sll_addr[ETH_ALEN],(unsigned char )d_addr.sll_addr[ETH_ALEN + 1]
  );
printf("HW address of received tx_tci is: %04X\n",
    tci);*/
 sap = tci == TRILL_TCI_BPDU ? ISO_BPDU : ISO_SAP;

  if (sock_buff[0] != sap || sock_buff[1] != sap || sock_buff[2] != 0x03){
  p++;
  printf("Received %d\n",p);
    return ISIS_WARNING;
}
  circuit->vlans->rx_tci = 1;
  stream_write (circuit->rcv_stream, sock_buff + LLC_LEN, bytesread - LLC_LEN);

//printf("Received %d\n",p);

  return ISIS_OK;
}

int
isis_send_pdu_bcast (struct isis_circuit *circuit, int level)
{
  ssize_t written;
  size_t msglen;
  struct sockaddr_ll s_addr;
  char *dp;
  unsigned char *i;

  if (circuit->fd == -1)
    return ISIS_ERROR;

  stream_set_getp (circuit->snd_stream, 0);

  memset (&s_addr, 0, sizeof (struct sockaddr_ll));
  s_addr.sll_family = AF_PACKET;
  s_addr.sll_protocol = htons (stream_get_endp (circuit->snd_stream) + LLC_LEN);
  s_addr.sll_ifindex = circuit->interface->ifindex;
  s_addr.sll_pkttype  = PACKET_BROADCAST;
  s_addr.sll_halen = ETH_ALEN;
  
  memcpy (&s_addr.sll_addr, all_isis_rbridges, ETH_ALEN);
  
  /*printf("HW address of all_isis_rbridges is: %02X:%02X:%02X:%02X:%02X:%02X\n",
    (unsigned char)s_addr.sll_addr[0],
    (unsigned char)s_addr.sll_addr[1],
    (unsigned char)s_addr.sll_addr[2],
    (unsigned char)s_addr.sll_addr[3],
    (unsigned char)s_addr.sll_addr[4],
    (unsigned char)s_addr.sll_addr[5]
  );

  /*memcpy (*(uint16_t *)(&s_addr.sll_addr + s_addr.sll_halen), &circuit->vlans->tx_tci, 
   sizeof (circuit->vlans->tx_tci)); */

	i = (unsigned char *)&circuit->vlans->tx_tci;
	s_addr.sll_addr[ETH_ALEN] = *(i + 1) ;
	s_addr.sll_addr[ETH_ALEN + 1] = *i;
	//s_addr.sll_addr[ETH_ALEN + 1] = (unsigned char)circuit->vlans->tx_tci;
	/*printf("HW address of circuit->vlans->tx_tci is: %04X\n",
    circuit->vlans->tx_tci);
	printf("HW address of circuit->vlans->tx_tci is: %02X%02X\n",
    (unsigned char )s_addr.sll_addr[ETH_ALEN],(unsigned char )s_addr.sll_addr[ETH_ALEN + 1]
  );

  /* now set up the data in the buffer */
  sock_buff[0] = ISO_SAP;
  sock_buff[1] = ISO_SAP;
  sock_buff[2] = 0x03;
  msglen = stream_get_endp (circuit->snd_stream);
  if (msglen + LLC_LEN > sizeof (sock_buff))
    return ISIS_WARNING;
  stream_get (sock_buff + LLC_LEN, circuit->snd_stream, msglen);
  msglen += LLC_LEN;

  /* now we can send this */
  written = sendto (circuit->fd, sock_buff, msglen, 0,
		    (struct sockaddr *) &s_addr, sizeof (struct sockaddr_ll));
		    if(written < 0)
		   printf("ERROR! sendto() call failed (Error No: %d \"%s\").\n", errno, strerror(errno));
		    //printf("AMNA MOHSIN \nwritten = %d\nmsglen = %d\n",(int )written,(int )msglen);

  if (written != (ssize_t)msglen)
    return ISIS_WARNING;

  return ISIS_OK;
}

int
trill_send_bpdu (struct isis_circuit *circuit, const void *msg, size_t msglen)
{
  ssize_t written;
  struct sockaddr_ll s_addr;
  char *dp;

  if (circuit->fd == -1)
    return ISIS_ERROR;

  /* add in the LLC header */
  sock_buff[0] = ISO_BPDU;
  sock_buff[1] = ISO_BPDU;
  sock_buff[2] = 0x03;
  memcpy (sock_buff + 3, msg, msglen);
  msglen += 3;

  memset (&s_addr, 0, sizeof (struct sockaddr_ll));
  s_addr.sll_family = AF_PACKET;
  s_addr.sll_protocol = htons(ETH_P_802_2);
  s_addr.sll_ifindex = circuit->interface->ifindex;
  s_addr.sll_halen = ETH_ALEN;
  
  memcpy (&s_addr.sll_addr, bridge_group_address, ETH_ALEN);

  written = sendto (circuit->fd, sock_buff, msglen, 0,
		    (struct sockaddr *) &s_addr, sizeof (struct sockaddr_ll));

  if (written != (ssize_t)msglen)
    return ISIS_WARNING;

  return ISIS_OK;
}
