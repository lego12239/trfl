#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "main.h"
#include "log.h"
#include "pkt.h"
#include "pkts_hdlrs.h"


/* List of payload packets that we can process */
static struct pkt_hdlrs *ppkts[3];
static char *ppkts_names[3] = {"ip", "ip6", NULL};


struct pkt_nfq* get_nfq_pkt(struct pkt *pkt);


int
pkt_init(void)
{
	int i, j, k;
	
	for(i = 0; pkts_list[i]; i++) {
		pkts_list[i]->type = i;
		if (pkts_list[i]->init)
			if ((k = pkts_list[i]->init()) < 0)
				return k;
	}
	for(i = 0, k = 0; ppkts_names[i]; i++)
		for(j = 0; pkts_list[j]; j++)
			if (strcmp(ppkts_names[i], pkts_list[j]->name) == 0) {
				ppkts[k++] = pkts_list[j];
				break;
			}
	return 0;
}

struct pkt*
pkt_make(unsigned char *data, int size, uint32_t id)
{
	struct pkt_nfq *pkt;
	int i, ret;
	
	pkt = malloc(sizeof(*pkt));
	if (!pkt)
		return NULL;
	memset(pkt, 0, sizeof(*pkt));
	pkt->pkt_type = pkt_type_nfq;
	pkt->pkt_len = size;
	pkt->pkt_raw = data;
	pkt->id = id;
	for(i = 0; ppkts[i]; i++) {
		if (!ppkts[i]->parse_pkt)
			continue;
		ret = ppkts[i]->parse_pkt((struct pkt*)pkt, data, size);
		if (ret < 0) {
			ERR_OUT("pkt_make: err on parsing %s: %d", ppkts[i]->name, ret);
			free(pkt);
			return NULL;
		} else if (ret == 0) {
			break;
		}
	}
	
	return (struct pkt*)pkt;
}

static void
_pkt_free_pkt_cb(struct list_item_head *lh)
{
	struct pkt *pkt_cur;
	
	pkt_cur = list_item(lh, struct pkt, list);
	if (pkts_list[pkt_cur->pkt_type]->free_pkt)
		pkts_list[pkt_cur->pkt_type]->free_pkt(pkt_cur);
}

static void
_pkt_free_domain_cb(struct list_item_head *lh)
{
	struct conn_domain *domain;
	
	domain = list_item(lh, struct conn_domain, list);
	free(domain->name);
	free(domain);
}

static void
_pkt_free_uri_cb(struct list_item_head *lh)
{
	struct conn_uri *uri;
	
	uri = list_item(lh, struct conn_uri, list);
	free(uri->value);
	free(uri);
}

void
pkt_free(struct pkt *pkt)
{
	struct pkt_nfq *pkt_nfq;

	if (pkt->pkt_type != pkt_type_nfq) {
		ERR_OUT("Call pkt_free() with wrong packet type");
		return;
	}
	list_free(pkt->list.next, _pkt_free_pkt_cb);
	pkt_nfq = (struct pkt_nfq*)pkt;
	list_free(&pkt_nfq->domain->list, _pkt_free_domain_cb);
	list_free(&pkt_nfq->uri->list, _pkt_free_uri_cb);
	free(pkt);
}

void
pkt_dump(struct pkt *pkt)
{
	struct list_item_head *list;
	struct pkt_nfq *pkt_nfq;
	struct conn_domain *domain;
	struct conn_uri *uri;
	
	if (pkt->pkt_type != pkt_type_nfq) {
		ERR_OUT("Call pkt_dump() with wrong packet type");
		return;
	}
	pkt_nfq = (struct pkt_nfq*)pkt;
	list_for_each(list, &pkt_nfq->domain->list) {
		domain = list_item(list, struct conn_domain, list);
		DBG_OUT("%u: pkt domain: %s", pkt_nfq->id, domain->name);
	}
	list_for_each(list, &pkt_nfq->uri->list) {
		uri = list_item(list, struct conn_uri, list);
		DBG_OUT("%u: pkt uri: %s", pkt_nfq->id, uri->value);
	}
	list_for_each(list, pkt->list.next) {
		pkt = list_item(list, struct pkt, list);
		if (pkts_list[pkt->pkt_type]->dump_pkt)
			pkts_list[pkt->pkt_type]->dump_pkt(pkt);
	}
}

void
pkt_errout(struct pkt *pkt, const char * const fmt, ...)
{
	struct list_item_head *lh;
	struct pkt_nfq *pkt_nfq;
	va_list ap;

	va_start(ap, fmt);
	verr_out(fmt, ap);
	va_end(ap);
	
	pkt_nfq = get_nfq_pkt(pkt);
	list_for_each(lh, pkt_nfq->list.next) {
		pkt = list_item(lh, struct pkt, list);
		if (pkts_list[pkt->pkt_type]->errout_pkt)
			pkts_list[pkt->pkt_type]->errout_pkt(pkt);
	}
}

struct pkt_nfq*
get_nfq_pkt(struct pkt *pkt)
{
	struct list_item_head *list;

	for(list = &pkt->list; list->prev; list = list->prev);
	pkt = list_item(list, struct pkt, list);
	return (struct pkt_nfq*)pkt;
}

uint32_t
get_pkt_id(struct pkt *pkt)
{
	return (get_nfq_pkt(pkt))->id;
}

struct pkt*
get_next_pkt(struct pkt *pkt)
{
	struct list_item_head *list;
	
	if (!pkt->list.next)
		return NULL;
	list = pkt->list.next;
	pkt = list_item(list, struct pkt, list);
	return pkt;
}

int
pkt_domain_add(struct pkt *pkt, char *name, int len)
{
	struct conn_domain *domain;
	struct pkt_nfq *pkt_nfq;
	
	domain = malloc(sizeof(*domain));
	if (!domain)
		return -1;
	list_item_head_init(&domain->list);
	domain->name = strndup(name, len);
	if (!domain->name) {
		free(domain);
		return -1;
	}
	pkt_nfq = get_nfq_pkt(pkt);
	if (!pkt_nfq->domain)
		pkt_nfq->domain = domain;
	else
		list_add(&domain->list, &pkt_nfq->domain->list);
	return 0;
}

int
pkt_uri_add(struct pkt *pkt, char *value)
{
	struct conn_uri *uri;
	struct pkt_nfq *pkt_nfq;
	
	uri = malloc(sizeof(*uri));
	if (!uri)
		return -1;
	list_item_head_init(&uri->list);
	uri->value = value;
	pkt_nfq = get_nfq_pkt(pkt);
	if (!pkt_nfq->uri)
		pkt_nfq->uri = uri;
	else
		list_add(&uri->list, &pkt_nfq->uri->list);
	return 0;
}

struct pkt_hdlrs pkt_hdlrs_nfq = {
	"nfq",
	0,
	NULL,
	NULL,
	NULL,
	NULL
};