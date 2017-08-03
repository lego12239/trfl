#include <netinet/tcp.h>
#include <endian.h>
#include <stdlib.h>
#include <stdint.h>
#include "log.h"
#include "pkt.h"
#include "pkt_icmp.h"
#include "pkts_hdlrs.h"


static int _dump_pkt(int outlvl, struct pkt *pkt);


static int
init(void)
{
	return 0;
}

static int
parse_pkt(struct pkt *pkt_prev, unsigned char *data, int size)
{
	struct pkt_icmp *pkt;
	
	pkt = malloc(sizeof(*pkt));
	if (!pkt)
		return -1;
	memset(pkt, 0, sizeof(*pkt));
	list_item_head_init(&pkt->list);
	list_add(&pkt->list, &pkt_prev->list);

	pkt->pkt_type = pkt_type_icmp;
	pkt->pkt_len = size;
	pkt->pkt_raw = data;
	pkt->type = *data;
	pkt->code = *(data + 1);
	
	return 0;
}

static int
free_pkt(struct pkt *pkt)
{
	struct pkt_icmp *pkt_icmp;
	
	if (pkt->pkt_type != pkt_type_icmp)
		return -2;
	pkt_icmp = (struct pkt_icmp*)pkt;
	free(pkt_icmp);
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
	struct pkt_icmp *pkt_icmp;
	
	if (pkt->pkt_type != pkt_type_icmp)
		return -2;
	id = get_pkt_id(pkt);
	pkt_icmp = (struct pkt_icmp*)pkt;
	
	ANY_OUT(outlvl, "%u: type = %d, code = %d, size = %d", id, pkt_icmp->type,
	  pkt_icmp->code, pkt_icmp->pkt_len);
	return 0;
}

struct pkt_hdlrs pkt_hdlrs_icmp = {
	"icmp",
	0,
	init,
	parse_pkt,
	free_pkt,
	dump_pkt,
	errout_pkt
};

