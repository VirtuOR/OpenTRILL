/*
 * netlink_socket library for trill
 */

#ifndef _NETLINK_SOCKET_H
#define _NETLINK_SOCKET_H

extern int netlink_socket();

extern int send_msg(int fd, void *buf, size_t len);

extern void *recv_msg(int fd);

extern int close_socket(int fd);

#endif /* _NETLINK_SOCKET_H */
