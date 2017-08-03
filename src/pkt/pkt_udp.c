#include <netinet/udp.h>
#include <endian.h>
#include <stdlib.h>
#include <stdint.h>
#include "log.h"
#include "pkt.h"
#include "pkt_udp.h"
#include "pkts_hdlrs.h"


/* List of payload packets that we can process */
static struct pkt_hdlrs *ppkts[2];
static char *ppkts_names[2] = {"dns", NULL};


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
	struct udphdr *udph;
	struct pkt_udp *pkt;
	uint16_t len;
	int i, ret;
	
	udph = (struct udphdr*)data;
	len = be16toh(udph->len);
	if (len != size)
		return 1;
	pkt = malloc(sizeof(*pkt));
	if (!pkt)
		return -1;
	memset(pkt, 0, sizeof(*pkt));
	list_item_head_init(&pkt->list);
	list_add(&pkt->list, &pkt_prev->list);

	pkt->pkt_type = pkt_type_udp;
	pkt->pkt_len = size;
	pkt->pkt_raw = data;
	pkt->sport = be16toh(udph->source);
	pkt->dport = be16toh(udph->dest);

	for(i = 0; ppkts[i]; i++) {
		if (!ppkts[i]->parse_pkt)
			continue;
		ret = ppkts[i]->parse_pkt((struct pkt*)pkt, data + 8, size - 8);
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
	struct pkt_udp *pkt_udp;
	
	if (pkt->pkt_type != pkt_type_udp)
		return -2;
	pkt_udp = (struct pkt_udp*)pkt;
	free(pkt_udp);
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
	struct pkt_udp *pkt_udp;
	
	if (pkt->pkt_type != pkt_type_udp)
		return -2;
	id = get_pkt_id(pkt);
	pkt_udp = (struct pkt_udp*)pkt;
	
	ANY_OUT(outlvl, "%u: port %d -> port %d, size = %d", id, pkt_udp->sport,
	  pkt_udp->dport, pkt_udp->pkt_len);
	return 0;
}

struct pkt_hdlrs pkt_hdlrs_udp = {
	"udp",
	0,
	init,
	parse_pkt,
	free_pkt,
	dump_pkt,
	errout_pkt
};

