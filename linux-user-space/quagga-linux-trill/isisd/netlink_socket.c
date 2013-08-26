#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "stream.h"
#include "isisd/isis_constants.h"

# define NETLINK_NITRO 17
# define MAX_PAYLOAD 1600

struct sockaddr_nl s_nladdr, d_nladdr;

int netlink_socket()
{

int fd;
fd=socket(AF_NETLINK ,SOCK_RAW , NETLINK_NITRO );

if (fd < 0)
    {
      zlog_warn ("open_trill_socket(): socket() failed %s",
		 safe_strerror (errno));
      return ISIS_ERROR;
    }

  if (set_nonblocking (fd) < 0)
    {
      zlog_warn ("open_trill_socket(): set_nonblocking() failed: %s",
	  safe_strerror (errno));
      close (fd);
      return ISIS_ERROR;
    }

/* source address */
memset(&s_nladdr, 0 ,sizeof(s_nladdr));
s_nladdr.nl_family= AF_NETLINK ;
s_nladdr.nl_pad=0;
s_nladdr.nl_pid = getpid();
bind(fd, (struct sockaddr*)&s_nladdr, sizeof(s_nladdr));

/* destination address */
memset(&d_nladdr, 0 ,sizeof(d_nladdr));
d_nladdr.nl_family= AF_NETLINK ;
d_nladdr.nl_pad=0;
d_nladdr.nl_pid = 0; /* destined to kernel */



return fd;
}

int send_msg(int fd, void *buf, size_t len)
{
struct msghdr msg ;
struct nlmsghdr *nlh=NULL ;
struct iovec iov;
int i;

/* Fill the netlink message header */
if(len < MAX_PAYLOAD)
{
nlh = (struct nlmsghdr *)malloc(len + sizeof (nlh));
memset(nlh , 0 , len);
}
else
{
zlog_warn ("Send Msg failed %s",
		 safe_strerror (errno));
      return ISIS_ERROR;
}
//strcpy(NLMSG_DATA(nlh), " Mr. Kernel, Are you ready ? Afro, I am doing it...." );

stream_get (NLMSG_DATA(nlh), buf, len);
//for(i=0;i<len;i++)
//printf("%c",buf+i);
printf("\n");
nlh->nlmsg_flags = 1;
nlh->nlmsg_type = 0;

/*iov structure */

iov.iov_base = (void *)nlh;
iov.iov_len = nlh->nlmsg_len;

/* msg */
memset(&msg,0,sizeof(msg));
msg.msg_name = (void *) &d_nladdr ;
msg.msg_namelen=sizeof(d_nladdr);
msg.msg_iov = &iov;
msg.msg_iovlen = 1;
i = sendmsg(fd, &msg, 0);
printf("%d\n",i);
return i;
}

void *recv_msg(int fd)
{
struct msghdr msg ;
struct nlmsghdr *nlh=NULL ;
struct iovec iov;
void *buf;
int i;
// Read message from kernel //
 memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
 recvmsg(fd, &msg, 0);
iov = *msg.msg_iov;
nlh = (struct nlmsghdr *)iov.iov_base;
nlh->nlmsg_len = iov.iov_len;
memset(buf,0,NLMSG_SPACE(MAX_PAYLOAD));
buf = NLMSG_DATA(nlh);
//for (i= 0 ; i < 30 ; i++)
 printf(" Received message payload: %s\n",(char *)buf);
return buf;
}

int close_socket(int fd)
{
close(fd);
return (EXIT_SUCCESS);
}
/*
#include <sys/socket.h>
#include <linux/netlink.h>

#define MAX_PAYLOAD 1024  // maximum payload size//
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;

void main() {
 sock_fd = socket(PF_NETLINK, SOCK_RAW,NETLINK_TEST);

 memset(&src_addr, 0, sizeof(src_addr));
 src__addr.nl_family = AF_NETLINK;
 src_addr.nl_pid = getpid();  // self pid //
 src_addr.nl_groups = 0;  // not in mcast groups //
 bind(sock_fd, (struct sockaddr*)&src_addr,
      sizeof(src_addr));

 memset(&dest_addr, 0, sizeof(dest_addr));
 dest_addr.nl_family = AF_NETLINK;
 dest_addr.nl_pid = 0;   // For Linux Kernel //
 dest_addr.nl_groups = 0; // unicast //

 nlh=(struct nlmsghdr *)malloc(
		         NLMSG_SPACE(MAX_PAYLOAD));
 // Fill the netlink message header//
 nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
 nlh->nlmsg_pid = getpid();  // self pid //
 nlh->nlmsg_flags = 0;
 // Fill in the netlink message payload //
 strcpy(NLMSG_DATA(nlh), "Hello you!");

 iov.iov_base = (void *)nlh;
 iov.iov_len = nlh->nlmsg_len;
 msg.msg_name = (void *)&dest_addr;
 msg.msg_namelen = sizeof(dest_addr);
 msg.msg_iov = &iov;
 msg.msg_iovlen = 1;

 sendmsg(fd, &msg, 0);

 // Read message from kernel //
 memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
 recvmsg(fd, &msg, 0);
 printf(" Received message payload: %s\n",
	NLMSG_DATA(nlh));

 // Close Netlink Socket //
 close(sock_fd);
}*/
