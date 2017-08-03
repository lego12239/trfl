#ifndef __PKT_UDP_H__
#define __PKT_UDP_H__

struct pkt_udp {
	PKT_HEAD
	uint16_t sport;
	uint16_t dport;
};

#endif  /* __PKT_UDP_H__ */
