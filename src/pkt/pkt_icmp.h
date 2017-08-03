#ifndef __PKT_ICMP_H__
#define __PKT_ICMP_H__

struct pkt_icmp {
	PKT_HEAD
	uint8_t type;
	uint8_t code;
};

#endif  /* __PKT_ICMP_H__ */
