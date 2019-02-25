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

#include <zebra.h>

#include "bfd.h"
#include "bfd_lag.h"

#define BFD_MAX_ETH_FRAME_SIZE 100
#define BFD_MICRO_BFD_PKT_SESSION_DOWN_FILTER	\
{ 0x30, 0, 0, 0x00000000 },						\
{ 0x54, 0, 0, 0x00000001 },						\
{ 0x15, 0, 7, 0x00000001 },						\
{ 0x28, 0, 0, 0x0000000c },						\
{ 0x15, 0, 5, 0x00000800 },						\
{ 0x20, 0, 0, 0x00000002 },						\
{ 0x15, 0, 3, 0x5e900001 },						\
{ 0x28, 0, 0, 0x00000000 },						\
{ 0x15, 0, 1, 0x00000100 },						\
{ 0x6, 0, 0, 0x00040000 },						\
{ 0x6, 0, 0, 0x00000000 }

#define BFD_MICRO_BFD_DST_PORT_PKT_FILTER		\
	{ 0x28, 0, 0, 0x0000000c },					\
	{ 0x15, 0, 4, 0x000086dd },					\
	{ 0x30, 0, 0, 0x00000014 },					\
	{ 0x15, 0, 11, 0x00000011 },				\
	{ 0x28, 0, 0, 0x00000038 },					\
	{ 0x15, 8, 9, 0x00001a80 },					\
	{ 0x15, 0, 8, 0x00000800 },					\
	{ 0x30, 0, 0, 0x00000017 },					\
	{ 0x15, 0, 6, 0x00000011 },					\
	{ 0x28, 0, 0, 0x00000014 },					\
	{ 0x45, 4, 0, 0x00001fff },					\
	{ 0xb1, 0, 0, 0x0000000e },					\
	{ 0x48, 0, 0, 0x00000010 },					\
	{ 0x15, 0, 1, 0x00001a80 },					\
	{ 0x6, 0, 0, 0x00040000 },					\
	{ 0x6, 0, 0, 0x00000000 }

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

static int bp_get_iface_real_mac(int sd, struct interface *ifp) {
	struct ifreq ifr_mac;
#ifdef BFD_LINUX
	struct ethtool_perm_addr perm_addr;

	memset(&ifr_mac, 0, sizeof(struct ifreq));
	memset(&perm_addr, 0, sizeof(struct ethtool_perm_addr));
	memcpy(&ifr_mac.ifr_name, ifp->name, IFNAMSIZ);
	perm_addr.cmd = ETHTOOL_GPERMADDR;
	perm_addr.size = ETHER_ADDR_LEN;
	ifr_mac.ifr_data = (void *)&perm_addr;
	if (ioctl(sd, SIOCETHTOOL, &ifr_mac) != 0) {
		log_debug("%s: ETHTOOL_GPERMADDR returned error using socket %d for interface %s (%d): %s", __func__, sd, ifp->name, ifp->ifindex, strerror(errno));
		return -1;
	}

//	log_debug("%s: real MAC for interface %s (%d) is %s", __func__, ifp->name, ifp->ifindex, ether_ntoa((const struct ether_addr *)&perm_addr.data));
	memcpy(ifp->hw_addr, (const uint8_t *)&perm_addr.data, ETHER_ADDR_LEN);
	ifp->hw_addr_len = ETHER_ADDR_LEN;
#else
//#error micro-BFD for this OS is not yet supported
#endif

	return 0;
}

static int bp_get_iface_mac(int sd, struct interface *ifp) {
	struct ifreq ifr_mac;

	memset(&ifr_mac, 0, sizeof(struct ifreq));
	memcpy(&ifr_mac.ifr_name, ifp->name, IFNAMSIZ);
	if (ioctl(sd, SIOCGIFHWADDR, &ifr_mac) < 0) {
		log_debug("%s: SIOCGIFHWADDR returned error using socket %d for interface %s (%d): %s", __func__, sd, ifp->name, ifp->ifindex, strerror(errno));
		return -1;
	}

	return 0;
}

static void bp_bind(int sd, struct interface *ifp) {
#ifdef BFD_LINUX
	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_ifindex = ifp->ifindex
	};
#endif /* BFD_LINUX */
#ifdef BFD_BSD
	struct sockaddr_dl sa = {
		.sdl_family = AF_LINK,
		.sdl_index = ifp->ifindex
	};
#endif /* BFD_BSD */

	if (bind(sd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
		log_fatal("%s: unable to bind socket to interface %s (%d)",
		    ifp->name, ifp->ifindex);
	}
}

static void bp_micro_bfd_mcast_join(int sd, struct interface *ifp) {
#ifdef BFD_LINUX
	struct packet_mreq mreq;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = ifp->ifindex;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETHER_ADDR_LEN;
	memcpy(&mreq.mr_address, BFD_SHOP_MICRO_BFD_PEER_ADDR, ETHER_ADDR_LEN);

	if (setsockopt(sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
			sizeof(struct packet_mreq)) != 0) {
		log_error("%s: could not join to micro-BFD multicast: %s", __func__,
				strerror(errno));
	}
#else
//#error micro-BFD for this OS is not yet supported
	struct ifreq ifr_mcast;

	memset(&ifr_mcast, 0, sizeof(ifr_mcast));
	memcpy(&ifr_mcast.ifr_name, ifp->name, IFNAMSIZ);
	memcpy(&ifr_mcast.ifr_hwaddr.sa_data, &micro_bfd_dest_mac, ETHER_ADDR_LEN);

	frr_elevate_privs(&bfdd_privs) {
		/* returns operation now allowed on Linux... */
		if (ioctl(sd, SIOCADDMULTI, &ifr_mcast) != 0) {
			if (errno == EADDRINUSE)
				log_debug("%s: already subscribed to micro-BFD multicast address on socket interface %s (%d)", __func__, ifp->name, ifp->ifindex);
			else /* TODO: this could be improved to just invalidate the peer config instead of crashing whole bfdd */
				log_fatal("%s: could not subscribe to micro-BFD multicast address: %s", __func__,
						strerror(errno));
		}
	}
#endif
}

int bp_udp_micro_bfd(void) {
	int sd;
	int receive_buffer, new_receive_buffer;
	socklen_t receive_buffer_len = sizeof(receive_buffer);

	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sd == -1) {
		log_fatal("%s: could not open socket: %s", __func__,
				strerror(errno));
	}

	receive_buffer = 0;
	if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &receive_buffer,
			sizeof(receive_buffer)) != 0) {
		log_error("%s: could not set SO_RCVBUF (%s)", __func__,
				strerror(errno));
		return -1;
	}
	if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, &new_receive_buffer,
			&receive_buffer_len) != 0) {
		log_debug("%s: could not get new SO_RCVBUF (%s)", __func__,
				strerror(errno));
		return -1;
	}
	log_debug("%s: UDP receive buffer set to %d bytes", __func__,
			new_receive_buffer);

	bp_bind_ip(sd, BFD_DEF_MICRO_BFD_PORT);

	return sd;
}

int bp_micro_bfd_send_socket(const struct bfd_session *bs)
{
	int sd;

//	sd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sd == -1) {
		log_error("%s: failed to create socket: %s", __func__,
			  strerror(errno));
		return -1;
	}
	bp_bind(sd, bs->ifp);

	log_debug("%s: created socket: %d", __func__, sd);

	return sd;
}

int bp_micro_bfd_recv_socket(struct interface *ifp) {
	int sd;

//	sd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP)); // can't decrypt packets
//	sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)); // bind to bond-slave OK, gets packets, ifindex is always bond's
	frr_elevate_privs(&bfdd_privs) {
		sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // bind to bond-slave OK, gets packets for BOTH bond and slave
	}
	if (sd == -1) {
		log_debug("%s: create socket: %s\n", __func__, strerror(errno));
	}
	bp_bind(sd, ifp);

	bp_micro_bfd_mcast_join(sd, ifp);

	log_debug("%s: setting BPF filter for micro-BFD multicast packets", __func__);
//	static struct sock_filter micro_bfd_mcast_filter[] = { BFD_MICRO_BFD_PKT_SESSION_DOWN_FILTER };
	static struct sock_filter micro_bfd_mcast_filter[] = { BFD_MICRO_BFD_DST_PORT_PKT_FILTER };
	struct sock_fprog prog = {
		.filter = micro_bfd_mcast_filter,
		.len = sizeof(micro_bfd_mcast_filter) / sizeof(struct sock_filter)
	};
	if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER,
                &prog, sizeof(prog)) != 0) {
		log_warning("%s: unable to set BPF filter for interface %s (%d)", __func__, ifp->name, ifp->ifindex);
	}

	return sd;
}

int bfd_send_eth(struct bfd_session *bs, uint16_t *port, const void *data,
		  size_t bfd_pkt_len)
{
	log_debug("%s to %s via %s (%d)", __func__, inet_ntoa(bs->shop.peer.sa_sin.sin_addr), bs->ifp->name, bs->ifp->ifindex);
	int datalen = 0;
	char sendbuf[BFD_MAX_ETH_FRAME_SIZE];
	struct ether_header *eh = (struct ether_header *)sendbuf;
	socklen_t to_len;
	ssize_t slen;

#ifdef BFD_LINUX
	struct sockaddr_ll to;
	to.sll_ifindex = bs->ifp->ifindex;
	to.sll_halen = ETH_ALEN;
	to_len = sizeof(struct sockaddr_ll);
	memcpy(&to.sll_addr, BFD_SHOP_MICRO_BFD_PEER_ADDR, sizeof(to.sll_addr));
#endif /* BFD_LINUX */
#ifdef BFD_BSD
	struct sockaddr_dl to = {
		.sdl_index = bs->ifp->ifindex,
		.sdl_alen = ETH_ALEN
	};
	to_len = sizeof(struct sockaddr_dl);
//	memcpy(&to.sll_addr, &micro_bfd_dest_mac, sizeof(to.sll_addr));
#endif /* BFD_BSD */

	struct ip *iph = (struct ip *) (sendbuf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (sendbuf + sizeof(struct ip) + sizeof(struct ether_header));

	// good idea
	struct mbfd_packet4 {
		struct ip		ip;
		struct udphdr	udp;
		char			payload[bfd_pkt_len];
	};

	memset(sendbuf, 0, BFD_MAX_ETH_FRAME_SIZE);

//	log_debug("%s: going to try to send on interface: %s (%d)", __func__, bs->ifp->name, bs->ifp->ifindex);

	/* Get the MAC address of the interface to send on */
	if (bp_get_iface_real_mac(bs->sock, bs->ifp) != 0) {
		if (bp_get_iface_mac(bs->sock, bs->ifp) != 0) {
			log_debug("%s: failed to obtain source MAC address for interface %s (%d). Can't send micro-BFD frame.", __func__, bs->ifp->name, bs->ifp->ifindex);
			return -1;
		}
	}

	/* Ethernet header */
	memcpy(&eh->ether_dhost, BFD_SHOP_MICRO_BFD_PEER_ADDR, sizeof(eh->ether_dhost));
//	memcpy(&eh->ether_shost, &ifr_mac.ifr_hwaddr.sa_data, sizeof(eh->ether_shost));
	memcpy(&eh->ether_shost, (const char *)bs->ifp->hw_addr, sizeof(eh->ether_shost));
	eh->ether_type = htons(ETH_P_IP);
	datalen += sizeof(struct ether_header);

	iph->ip_v = 4;
	iph->ip_hl = 5;
	iph->ip_tos = BFD_TOS_VAL;
	iph->ip_id = 666; /* TODO: DECIDE WHAT TO DO WITH THIS */
	iph->ip_off |= htons(IP_DF);
	iph->ip_ttl = BFD_TTL_VAL;
	iph->ip_p = IPPROTO_UDP;
	iph->ip_src.s_addr = bs->local_ip.sa_sin.sin_addr.s_addr;
	iph->ip_dst.s_addr = bs->shop.peer.sa_sin.sin_addr.s_addr;
	datalen += sizeof(struct ip);

	udph->uh_sport = htons(BFD_SRCPORTINIT);
	udph->uh_dport = htons(BFD_DEF_MICRO_BFD_PORT);
	udph->uh_sum = 0;

	datalen += sizeof(struct udphdr);

//	struct bfd_pkt target_cp = (struct bfd_pkt *) (sendbuf + sizeof(struct udphdr) + sizeof(struct ip) + sizeof(struct ether_header));

#if 0
	int bufsize = sizeof(sendbuf);
	for (int i = 0; i < bfd_pkt_len && datalen < bufsize; i++) {
		sendbuf[datalen++] = (char *)data[i];
	}
#endif

	char sipaddr[INET_ADDRSTRLEN];
	char dipaddr[INET_ADDRSTRLEN];
//	inet_ntop(AF_INET, &(bs->local_ip.sa_sin), sipaddr, INET_ADDRSTRLEN);
//	inet_ntop(AF_INET, &(bs->shop.peer.sa_sin), dipaddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &iph->ip_src, sipaddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &iph->ip_dst, dipaddr, INET_ADDRSTRLEN);
//	log_debug("%s: Attempting send from IP %s to IP %s", __func__, sipaddr, dipaddr);
//	log_debug("%s: before payload datalen is %d and bfd_pkt_len is %d", __func__, datalen, bfd_pkt_len);
	memcpy(&sendbuf[datalen], (char *)data, bfd_pkt_len);
	datalen += bfd_pkt_len;
//	log_debug("%s: after payload datalen is %d and bfd_pkt_len is %d, %02X", __func__, datalen, bfd_pkt_len, sendbuf[ntohs(udph->uh_ulen)+1]);

	udph->uh_ulen = htons(datalen - sizeof(struct ip) - sizeof(struct ether_header));
//	log_debug("%s: uh_ulen %d %d", __func__, udph->uh_ulen, ntohs(udph->uh_ulen));
	iph->ip_len = htons(datalen - sizeof(struct ether_header));
//	log_debug("%s: ip_len %d %d", __func__, iph->ip_len, ntohs(iph->ip_len));
	iph->ip_sum = csum((unsigned short *)(sendbuf + sizeof(struct ether_header)), sizeof(struct ip)/2);

#if 0
	log_debug(
			"%s: Attempting sendto():"
			" bs->sock: %d"
			" to.*_ifindex: %d"
//			" to.sll_addr[0]: %02X:%02X:%02X"
			" eh->ether_dhost[0]: %02X:%02X:%02X"
			" eh->ether_shost[0]: %02X:%02X:%02X"
			" datalen: %d",
			__func__,
			bs->sock,
			to.sll_ifindex,
//			to.sll_addr[0], to.sll_addr[1], to.sll_addr[2],
			eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
			eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
			datalen
	);
#endif

	/* we need SOCK_RAW for the stuff we've done up here */
	slen = sendto(bs->sock_mbfd, sendbuf, datalen, 0, (struct sockaddr *)&to, to_len);
	if (slen <= 0) {
		log_debug("%s: send failure: %s", __func__, strerror(errno));
		return -1;
	}
	if (slen < (ssize_t)datalen)
		log_debug("%s: send partial: %s", __func__, strerror(errno));

	log_debug("%s: sendto() reported %d bytes sent to %s via %s (%d)", __func__, slen, inet_ntoa(bs->shop.peer.sa_sin.sin_addr), bs->ifp->name, bs->ifp->ifindex);

	return 0;
}

ssize_t bfd_recv_eth(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      ifindex_t *ifindex, struct sockaddr_any *local,
		      struct sockaddr_any *peer)
{
#ifdef BFD_LINUX
	struct sockaddr_ll from;
#endif /* BFD_LINUX */
#ifdef BFD_BSD
	struct sockaddr_dl from;
#endif /* BFD_BSD */
	socklen_t fromlen = sizeof(from);
	memset(&from, 0, fromlen);
	ssize_t rlen;
	uint32_t ttlval;

	rlen = recvfrom(sd, msgbuf, msgbuflen, MSG_DONTWAIT, (struct sockaddr *)&from,
						&fromlen);
	if (rlen == -1) {
		if (errno == EAGAIN)
			log_error("%s: EAGAIN error (%s)", __func__,
				  strerror(errno));
		else
			log_error("%s: recvfrom() failed: %s", __func__,
				  strerror(errno));

		return -1;
	}

	switch (ntohs(from.sll_protocol))
	{
		case ETH_P_SLOW:
		case 0x86DD: // LLDP
			return -1;
	}

#ifdef BFD_LINUX
	*ifindex = from.sll_ifindex;
	if (from.sll_pkttype == PACKET_OUTGOING)
		return -1;
	if (from.sll_protocol != ntohs(ETH_P_IP))
		return -1;
#endif /* BFD_LINUX */
#ifdef BFD_BSD
	*ifindex = from.sdl_index;
#endif /* BFD_BSD */

	/* Map the headers to the received frame data */
	struct ether_header *eh = (struct ether_header *)msgbuf;
	struct ip *iph = (struct ip *) (msgbuf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (msgbuf + sizeof(struct ip) + sizeof(struct ether_header));

	if (iph->ip_p != IPPROTO_UDP)
		return -1;

	log_debug("%s from %s via (%d)", __func__, inet_ntoa(iph->ip_src), from.sll_ifindex);
#if 0
	log_debug("%s: received frame on socket %d interface %d", __func__, sd, from.sll_ifindex);
	log_debug("Ethernet Header");
	log_debug("Source Host: %s", ether_ntoa((const struct ether_addr *)eh->ether_shost));
    log_debug("Desti. Host: %s", ether_ntoa((const struct ether_addr *)eh->ether_dhost));
    log_debug("Ether. Type: 0x%0x%s", ntohs(eh->ether_type), ntohs(eh->ether_type) == 0x800 ? " (IP)" : "");
	log_debug("");
	log_debug("IP Header");
	log_debug("Header length: %i", iph->ip_hl);
    log_debug("Version      : %i%s", iph->ip_v, iph->ip_v == IPVERSION ? " (IPv4)" : "");
    log_debug("Type of Serv.: %i", iph->ip_tos);
    log_debug("Identificati.: %i", ntohs(iph->ip_id));
    log_debug("Time to live : %i", iph->ip_ttl);
    log_debug("Protocol     : %i%s", iph->ip_p, iph->ip_p == IPPROTO_UDP ? " (UDP)" : "");
    log_debug("Source Addre.: %s%s", inet_ntoa(iph->ip_src), " (local IP)");
    log_debug("Dest. Address: %s", inet_ntoa(iph->ip_dst));
	log_debug("");
	log_debug("UDP Header");
    log_debug("Source Port: %i", ntohs(udph->uh_sport));
    log_debug("Desti. Port: %i", ntohs(udph->uh_dport));
    log_debug("Packet Len.: %i", ntohs(udph->uh_ulen));
	log_debug("");
	log_debug("");
#endif

#if 0
	log_debug(
			"%s: Received frame"
			" via socket %d"
			" on interface (%d)"
			" eh->ether_dhost: %s"
			" eh->ether_shost: %s"
			__func__,
			sd,
			ifindex,
			ether_ntoa(eh->ether_dhost),
			eh->ether_shost
	);
#endif

//	log_debug("%s: received frame on ifindex %d, sll_protocol %X", __func__, from.sll_ifindex, ntohs(from.sll_protocol));
//	log_debug("%s: received IP packet on ifindex %d, iph->ip_p=%d", __func__, from.sll_ifindex, iph->ip_p);
	if (udph->uh_dport != ntohs(BFD_DEF_MICRO_BFD_PORT)) {
		log_debug("%s: udph->uh_dport is %d, ntohs(udph->uh_dport) is %d", __func__, udph->uh_dport, ntohs(udph->uh_dport));
		return -5;
	}

//	memcpy(&ttlval, &iph->ip_ttl, sizeof(ttlval)); // results in bogus values
	ttlval = iph->ip_ttl;
	if (ttlval > 255) {
		log_debug("%s: invalid TTL: %u", __func__, ttlval);
		return -1;
	}
	*ttl = ttlval;
	local->sa_sin.sin_family = AF_INET;
	local->sa_sin.sin_addr = iph->ip_dst;
	peer->sa_sin.sin_family = AF_INET;
	peer->sa_sin.sin_addr = iph->ip_src;

	return rlen;
}

void bfd_micro_sd_reschedule(int sd, struct bfd_session *bfd)
{
	THREAD_OFF(bfd->t_read_mbfd);
	thread_add_read(master, bfd_recv_cb, bfd, sd,
			&bfd->t_read_mbfd);
}

#if 0
int bfd_micro_recv_cb(struct thread *t)
{
	log_debug("enter %s() for %s", __func__, iface->name);
	uint8_t msgbuf[1516];
//	struct bfd_pkt *cp;
	bool is_mhop = false; // we don't do mhop micro BFD
	ssize_t mlen = 0;
	uint8_t ttl = 0;
	vrf_id_t vrfid = VRF_DEFAULT;
	ifindex_t ifindex = IFINDEX_INTERNAL;
	struct sockaddr_any local, peer;
	mlen = bfd_recv_eth(sd, msgbuf, sizeof(msgbuf), &ttl, &ifindex,
						 &local, &peer);

	if (mlen == -1) {
//		log_debug("%s: bfd_recv_eth() returned error", __func__);
		return 1;
	}

	/* Implement RFC 5880 6.8.6 */
	if (mlen < BFD_PKT_LEN) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "too small (%ld bytes)", mlen);
		return 0;
	}

	/* Validate packet TTL. */
	if ((is_mhop == false) && (ttl != BFD_TTL_VAL)) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "%s: invalid TTL: %d expected %d", __func__, ttl, BFD_TTL_VAL);
//		return 0;
	}

	/*
	 * Parse the control header for inconsistencies:
	 * - Invalid version;
	 * - Bad multiplier configuration;
	 * - Short packets;
	 * - Invalid discriminator;
	 */
	cp = (struct bfd_pkt *)(msgbuf);
//	cp = (struct bfd_pkt *)(msgbuf + sizeof(struct udphdr) + sizeof(struct ip) + sizeof(struct ether_header));

	cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
		 "end of %s", __func__);

	log_debug("exit %s() for %s", __func__, iface->name);
	return 0;
}
#endif
