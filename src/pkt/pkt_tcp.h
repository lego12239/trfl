#ifndef __PKT_TCP_H__
#define __PKT_TCP_H__

struct pkt_tcp {
	PKT_HEAD
	uint16_t sport;
	uint16_t dport;
};

#endif  /* __PKT_TCP_H__ */
