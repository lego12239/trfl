#include <netinet/tcp.h>
#include <endian.h>
#include <stdlib.h>
#include <stdint.h>
#include "log.h"
#include "pkt.h"
#include "pkt_tcp.h"
#include "pkts_hdlrs.h"


/* List of payload packets that we can process */
static struct pkt_hdlrs *ppkts[3];
static char *ppkts_names[3] = {"http", "tls", NULL};


static int _dump_pkt(int outlvl, struct pkt *pkt);


static int
init(void)
{
	int i, j, k;
	
	for(i = 0, k = 0; ppkts_names[i]; i++)
		for(j = 0; pkts_list[j]; j++)
			if (strcmp(ppkts_names[i], pkts_list[j]->name) == 0) {
				ppkts[k++] = pkts_list[j];
				break;
			}
	return 0;
}

static int
parse_pkt(struct pkt *pkt_prev, unsigned char *data, int size)
{
	struct tcphdr *tcph;
	struct pkt_tcp *pkt;
	int i, ret;
	
	tcph = (struct tcphdr*)data;
	pkt = malloc(sizeof(*pkt));
	if (!pkt)
		return -1;
	memset(pkt, 0, sizeof(*pkt));
	list_item_head_init(&pkt->list);
	list_add(&pkt->list, &pkt_prev->list);

	pkt->pkt_type = pkt_type_tcp;
	pkt->pkt_len = size;
	pkt->pkt_raw = data;
	pkt->sport = be16toh(tcph->source);
	pkt->dport = be16toh(tcph->dest);

	for(i = 0; ppkts[i]; i++) {
		if (!ppkts[i]->parse_pkt)
			continue;
		ret = ppkts[i]->parse_pkt((struct pkt*)pkt, data + tcph->doff * 4,
		  size - tcph->doff * 4);
		if (ret < 0) {
			ERR_OUT("parse_pkt error: %s: %d", ppkts[i]->name, ret);
			list_rm(&pkt->list);
			free(pkt);
			return ret;
		} else if (ret == 0) {
			break;
		}
	}
	
	return 0;
}

static int
free_pkt(struct pkt *pkt)
{
	struct pkt_tcp *pkt_tcp;
	
	if (pkt->pkt_type != pkt_type_tcp)
		return -2;
	pkt_tcp = (struct pkt_tcp*)pkt;
	free(pkt_tcp);
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
	struct pkt_tcp *pkt_tcp;
	
	if (pkt->pkt_type != pkt_type_tcp)
		return -2;
	id = get_pkt_id(pkt);
	pkt_tcp = (struct pkt_tcp*)pkt;
	
	ANY_OUT(outlvl, "%u: port %d -> port %d, size = %d", id, pkt_tcp->sport,
	  pkt_tcp->dport, pkt_tcp->pkt_len);
	return 0;
}

struct pkt_hdlrs pkt_hdlrs_tcp = {
	"tcp",
	0,
	init,
	parse_pkt,
	free_pkt,
	dump_pkt,
	errout_pkt
};

