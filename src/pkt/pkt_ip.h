#ifndef __PKT_IP_H__
#define __PKT_IP_H__

struct pkt_ip {
	PKT_HEAD
	uint32_t saddr;
	uint32_t daddr;
	uint8_t proto;
};

#endif  /* __PKT_IP_H__ */
