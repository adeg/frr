/*********************************************************************
 * Copyright 2017-2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * bfd_lag.c: implements BFD on LAG interfaces per RFC 7130.
 *
 * Authors
 * -------
 * Anton Degtyarev <anton@cumulusnetworks.com>
 */

#ifndef BFD_LAG_H
#define BFD_LAG_H

#include <netinet/udp.h>
#ifdef BFD_LINUX
#include <netinet/ether.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#endif /* BFD_LINUX */
#ifdef BFD_BSD
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <sys/sockio.h>
#endif

#include "bfd.h"

unsigned short csum(unsigned short *buf, int nwords);
int bp_udp_micro_bfd(void);
int bp_micro_bfd_send_socket(const struct bfd_session *bs);
int bp_micro_bfd_recv_socket(struct interface *ifp);
void bfd_micro_sd_reschedule(int sd, struct bfd_session *bfd);
int bfd_send_eth(struct bfd_session *bs, uint16_t *port, const void *data,
		  size_t bfd_pkt_len);
ssize_t bfd_recv_eth(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      ifindex_t *ifindex, struct sockaddr_any *local,
		      struct sockaddr_any *peer);

#endif /* BFD_LAG_H */
