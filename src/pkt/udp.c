#include <netinet/ip.h>
#include <endian.h>
#include <netinet/udp.h>
#include "pkt.h"


int
parse_udp(struct pkt *pkt)
{
	struct udphdr *udph;

	if (!pkt->l3)
		parse_l3(pkt);
	if (!pkt->l3
	iph = (struct iphdr*)pkt->l3_raw;
	pkt->l3_len = be16toh(iph->tot_len);
	pkt->l3_type = l3_type_ip4;
	pkt->l3.ip4.saddr = be32toh(iph->saddr);
	pkt->l3.ip4.daddr = be32toh(iph->daddr);
	pkt->l3.ip4.l4_len = pkt->l3_len - iph->ihl * 4;
	pkt->l3.ip4.l4_raw = pkt->l3_raw + iph->ihl * 4;
	pkt->l3.ip4.l4_type = iph->protocol;
	
	return 0;
}

struct proto proto_udp = {
	"udp",
	parse_udp
};

