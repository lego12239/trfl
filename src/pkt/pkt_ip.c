#include <netinet/ip.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include "log.h"
#include "pkt.h"
#include "pkt_ip.h"
#include "pkts_hdlrs.h"


static struct pkt_hdlrs *ppkts[256];
static char *ppkts_names[256] = {"_", "icmp", "igmp", "ggp", "ipencap",
  "st", "tcp", "cbt", "egp", "igp", "bbn-rcc", "nvp", "pup", "argus", "emcon",
  "xnet", "chaos", "udp"};


static int _dump_pkt(int outlvl, struct pkt *pkt);


static int
init(void)
{
	int i, j;
	
	for(i = 0; ppkts_names[i]; i++)
		for(j = 0; pkts_list[j]; j++)
			if (strcmp(ppkts_names[i], pkts_list[j]->name) == 0) {
				ppkts[i] = pkts_list[j];
				break;
			}
	return 0;
}

static int
parse_pkt(struct pkt *pkt_prev, unsigned char *data, int size)
{
	struct iphdr *iph;
	struct pkt_ip *pkt;
	uint16_t len;
	int ret;

	iph = (struct iphdr*)data;
	if (iph->version != 4)
		return 1;
	len = be16toh(iph->tot_len);
	if (len != size)
		return 1;
	pkt = malloc(sizeof(*pkt));
	if (!pkt)
		return -1;
	memset(pkt, 0, sizeof(*pkt));
	list_item_head_init(&pkt->list);
	list_add(&pkt->list, &pkt_prev->list);

	pkt->pkt_type = pkt_type_ip;
	pkt->pkt_len = size;
	pkt->pkt_raw = data;
	pkt->saddr = be32toh(iph->saddr);
	pkt->daddr = be32toh(iph->daddr);
	pkt->proto = iph->protocol;
	
	if ((ppkts[pkt->proto]) && (ppkts[pkt->proto]->parse_pkt)) {
		ret = ppkts[pkt->proto]->parse_pkt((struct pkt*)pkt,
		  data + iph->ihl * 4, size - iph->ihl * 4);
		if (ret != 0) {
			ERR_OUT("parse_pkt error: %s: %d",
			  ppkts[pkt->proto]->name, ret);
			list_rm(&pkt->list);
			free(pkt);
			return ret;
		}
	}
	return 0;
}

static int
free_pkt(struct pkt *pkt)
{
	struct pkt_ip *pkt_ip;
	
	if (pkt->pkt_type != pkt_type_ip)
		return -2;
	pkt_ip = (struct pkt_ip*)pkt;
	free(pkt_ip);
	return 0;
}

static int
dump_pkt(struct pkt *pkt)
{
	return _dump_pkt(OUTLVL_DBG, pkt);
}

static int
errout_pkt(struct pkt *pkt)
{
	return _dump_pkt(OUTLVL_ERR, pkt);
}

static int
_dump_pkt(int outlvl, struct pkt *pkt)
{
	uint32_t id;
	struct pkt_ip *pkt_ip;
	
	if (pkt->pkt_type != pkt_type_ip)
		return -2;
	id = get_pkt_id(pkt);
	pkt_ip = (struct pkt_ip*)pkt;
	
	ANY_OUT(outlvl, "%u: IP: %02d.%02d.%02d.%02d -> %02d.%02d.%02d.%02d, "
	  "size = %d, proto = %d",
	  id, pkt_ip->saddr >> 24, (pkt_ip->saddr & 0xff0000) >> 16,
	  (pkt_ip->saddr & 0xff00) >> 8, pkt_ip->saddr & 0xff,
	  pkt_ip->daddr >> 24, (pkt_ip->daddr & 0xff0000) >> 16,
	  (pkt_ip->daddr & 0xff00) >> 8, pkt_ip->daddr & 0xff,
	  pkt_ip->pkt_len, pkt_ip->proto);
	return 0;
}

struct pkt_hdlrs pkt_hdlrs_ip = {
	"ip",
	0,
	init,
	parse_pkt,
	free_pkt,
	dump_pkt,
	errout_pkt
};

