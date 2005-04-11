/* Zebra's client header.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _ZEBRA_ZCLIENT_H
#define _ZEBRA_ZCLIENT_H

/* For struct interface and struct connected. */
#include "if.h"

/* For input/output buffer to zebra. */
#define ZEBRA_MAX_PACKET_SIZ          4096

/* Zebra header size. */
#define ZEBRA_HEADER_SIZE                3

/* Structure for the zebra client. */
struct zclient
{
  /* Socket to zebra daemon. */
  int sock;

  /* Flag of communication to zebra is enabled or not.  Default is on.
     This flag is disabled by `no router zebra' statement. */
  int enable;

  /* Connection failure count. */
  int fail;

  /* Input buffer for zebra message. */
  struct stream *ibuf;

  /* Output buffer for zebra message. */
  struct stream *obuf;

  /* Buffer of data waiting to be written to zebra. */
  struct buffer *wb;

  /* Read and connect thread. */
  struct thread *t_read;
  struct thread *t_connect;

  /* Thread to write buffered data to zebra. */
  struct thread *t_write;

  /* Redistribute information. */
  u_char redist_default;
  u_char redist[ZEBRA_ROUTE_MAX];

  /* Redistribute defauilt. */
  u_char default_information;

  /* Pointer to the callback functions. */
  int (*router_id_update) (int, struct zclient *, zebra_size_t);
  int (*interface_add) (int, struct zclient *, zebra_size_t);
  int (*interface_delete) (int, struct zclient *, zebra_size_t);
  int (*interface_up) (int, struct zclient *, zebra_size_t);
  int (*interface_down) (int, struct zclient *, zebra_size_t);
  int (*interface_address_add) (int, struct zclient *, zebra_size_t);
  int (*interface_address_delete) (int, struct zclient *, zebra_size_t);
  int (*ipv4_route_add) (int, struct zclient *, zebra_size_t);
  int (*ipv4_route_delete) (int, struct zclient *, zebra_size_t);
  int (*ipv6_route_add) (int, struct zclient *, zebra_size_t);
  int (*ipv6_route_delete) (int, struct zclient *, zebra_size_t);
};

/* Zebra API message flag. */
#define ZAPI_MESSAGE_NEXTHOP  0x01
#define ZAPI_MESSAGE_IFINDEX  0x02
#define ZAPI_MESSAGE_DISTANCE 0x04
#define ZAPI_MESSAGE_METRIC   0x08

/* Zebra IPv4 route message API. */
struct zapi_ipv4
{
  u_char type;

  u_char flags;

  u_char message;

  u_char nexthop_num;
  struct in_addr **nexthop;

  u_char ifindex_num;
  unsigned int *ifindex;

  u_char distance;

  u_int32_t metric;
};

/* Prototypes of zebra client service functions. */
struct zclient *zclient_new (void);
void zclient_init (struct zclient *, int);
int zclient_start (struct zclient *);
void zclient_stop (struct zclient *);
void zclient_reset (struct zclient *);

/* Get TCP socket connection to zebra daemon at loopback address. */
int zclient_socket (void);

/* Get unix stream socket connection to zebra daemon at given path. */
int zclient_socket_un (const char *);

/* Send redistribute command to zebra daemon. Do not update zclient state. */
int zebra_redistribute_send (int command, struct zclient *, int type);

/* If state has changed, update state and call zebra_redistribute_send. */
void zclient_redistribute (int command, struct zclient *, int type);

/* If state has changed, update state and send the command to zebra. */
void zclient_redistribute_default (int command, struct zclient *);

/* Send the message in zclient->obuf to the zebra daemon (or enqueue it).
   Returns 0 for success or -1 on an I/O error. */
extern int zclient_send_message(struct zclient *);

struct interface *zebra_interface_add_read (struct stream *);
struct interface *zebra_interface_state_read (struct stream *s);
struct connected *zebra_interface_address_read (int, struct stream *);
void zebra_interface_if_set_value (struct stream *, struct interface *);
void zebra_router_id_update_read (struct stream *s, struct prefix *rid);
int zapi_ipv4_route (u_char, struct zclient *, struct prefix_ipv4 *, 
                     struct zapi_ipv4 *);

#ifdef HAVE_IPV6
/* IPv6 prefix add and delete function prototype. */

struct zapi_ipv6
{
  u_char type;

  u_char flags;

  u_char message;

  u_char nexthop_num;
  struct in6_addr **nexthop;

  u_char ifindex_num;
  unsigned int *ifindex;

  u_char distance;

  u_int32_t metric;
};

int zapi_ipv6_route (u_char cmd, struct zclient *zclient, 
                     struct prefix_ipv6 *p, struct zapi_ipv6 *api);
#endif /* HAVE_IPV6 */

#endif /* _ZEBRA_ZCLIENT_H */
