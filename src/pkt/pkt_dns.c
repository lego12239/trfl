#include <netinet/udp.h>
#include <endian.h>
#include <stdlib.h>
#include <stdint.h>
#include "log.h"
#include "util.h"
#include "pkt.h"
#include "pkt_tcp.h"
#include "pkt_udp.h"
#include "pkt_dns.h"
#include "pkts_hdlrs.h"


struct pkt_dnshdr {
	uint16_t id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned rd:1;
	unsigned tc:1;
	unsigned aa:1;
	unsigned opcode:4;
	unsigned qr:1;
	unsigned rcode:4;
	unsigned cd:1;
	unsigned ad:1;
	unsigned z:1;
	unsigned ra:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned qr:1;
	unsigned opcode:4;
	unsigned aa:1;
	unsigned tc:1;
	unsigned rd:1;
	unsigned ra:1;
	unsigned z:1;
	unsigned ad:1;
	unsigned cd:1;
	unsigned rcode:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};


static int free_pkt(struct pkt *pkt);
static int _parse_qentry(unsigned char *data, int size, struct dns_qentry *qe);
static int _dump_pkt(int outlvl, struct pkt *pkt);


static int
init(void)
{
	return 0;
}

static int
parse_pkt(struct pkt *pkt_prev, unsigned char *data, int size)
{
	struct pkt_dnshdr *dnsh;
	struct pkt_tcp *pkt_tcp;
	struct pkt_udp *pkt_udp;
	struct pkt_dns *pkt;
	struct dns_qentry qentry, *qentry_new;
	unsigned int i, off;
	uint16_t cnt;
	int ret;

	/* Is this really a dns packet? */
	if (size < sizeof(*dnsh))
		return 1;
	if (pkt_prev->pkt_type == pkt_type_tcp) {
		pkt_tcp = (struct pkt_tcp*)pkt_prev;
		if (pkt_tcp->dport != 53)
			return 1;
	} else if (pkt_prev->pkt_type == pkt_type_udp) {
		pkt_udp = (struct pkt_udp*)pkt_prev;
		if (pkt_udp->dport != 53)
			return 1;
	} else
		return 1;
	
	/* Is this a dns request packet? */
	dnsh = (struct pkt_dnshdr*)data;
	cnt = be16toh(dnsh->qdcount);
	if ((dnsh->qr != 0) || (dnsh->rcode != 0))
		return 2;
	if (cnt == 0)
		return 2;
	if (cnt > 1)
		ERR_OUT("%u: dns: more than 1 rr in question section"
		  "(saddr=%u, daddr=%u)!", get_pkt_id(pkt_prev), 0, 0);

	off = sizeof(*dnsh);
	pkt = malloc(sizeof(*pkt));
	if (!pkt)
		return -1;
	memset(pkt, 0, sizeof(*pkt));
	list_item_head_init(&pkt->list);
	list_add(&pkt->list, &pkt_prev->list);

	pkt->pkt_type = pkt_type_dns;
	pkt->pkt_len = size;
	pkt->pkt_raw = data;
	
	/* Do not save this info. For a little speed up */
	/*
	pkt->id = be16toh(dnsh->id);
	pkt->qr = dnsh->qr;
	pkt->opcode = dnsh->opcode;
	pkt->aa = dnsh->aa;
	pkt->tc = dnsh->tc;
	pkt->rd = dnsh->rd;
	pkt->ra = dnsh->ra;
	pkt->z = dnsh->z;
	pkt->ad = dnsh->ad;
	pkt->cd = dnsh->cd;
	pkt->rcode = dnsh->rcode;
	pkt->qdcount = be16toh(dnsh->qdcount);
	pkt->ancount = be16toh(dnsh->ancount);
	pkt->nscount = be16toh(dnsh->nscount);
	pkt->arcount = be16toh(dnsh->arcount);
	*/

	size -= off;
	for(i = 0; i < cnt && size; i++) {
		ret = _parse_qentry(data + off, size, &qentry);
		if (ret < 0) {
			list_rm(&pkt->list);
			free_pkt((struct pkt*)pkt);
			return 1;
		}
		off += ret;
		if (ret > size) {
			list_rm(&pkt->list);
			free_pkt((struct pkt*)pkt);
			return 1;
		}
		size -= ret;
		qentry_new = (struct dns_qentry*)realloc(pkt->qentry,
		  (i+1)*sizeof(struct dns_qentry));
		if (!qentry_new) {
			list_rm(&pkt->list);
			free_pkt((struct pkt*)pkt);
			return -1;
		}
		pkt->qentry = qentry_new;
		memcpy(&pkt->qentry[i].qname, &qentry.qname, qentry.qname_len + 1);
		pkt->qentry[i].qname_len = qentry.qname_len;
		pkt->qentry[i].qtype = qentry.qtype;
		pkt->qentry[i].qclass = qentry.qclass;
		
		if (pkt_domain_add(pkt_prev, qentry.qname, qentry.qname_len) < 0) {
			list_rm(&pkt->list);
			free_pkt((struct pkt*)pkt);
			return -1;
		}
	}
	/* size == 0 and i != cnt */
	if (i != cnt) {
		list_rm(&pkt->list);
		free_pkt((struct pkt*)pkt);
		return 1;
	}
	
	return 0;
}

static int
free_pkt(struct pkt *pkt)
{
	struct pkt_dns *pkt_dns;
	
	if (pkt->pkt_type != pkt_type_dns)
		return -2;
	pkt_dns = (struct pkt_dns*)pkt;
	free(pkt_dns->qentry);
	free(pkt_dns);
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
	int i;
	struct pkt_dns *pkt_dns;
	
	if (pkt->pkt_type != pkt_type_dns)
		return -2;
	id = get_pkt_id(pkt);
	pkt_dns = (struct pkt_dns*)pkt;
	
	ANY_OUT(outlvl, "%u: dns: id - %hu, size = %d(qr=%u,opcode=%u,aa=%u,"
	  "tc=%u,rd=%u,ra=%u,z=%u,ad=%u,cd=%u,rcode=%u), qdcount=%hu, "
	  "ancount=%hu, nscount=%hu, arcount=%hu", id, pkt_dns->id, pkt_dns->pkt_len,
	  pkt_dns->qr,  pkt_dns->opcode, pkt_dns->aa,
	  pkt_dns->tc, pkt_dns->rd, pkt_dns->ra, pkt_dns->z, pkt_dns->ad,
	  pkt_dns->cd, pkt_dns->rcode, pkt_dns->qdcount,
	  pkt_dns->ancount, pkt_dns->nscount, pkt_dns->arcount);
	for(i = 0; i < pkt_dns->qdcount; i++)
		ANY_OUT(outlvl, "%u: dns: qentry - %s", id, pkt_dns->qentry[i].qname);
	return 0;
}

struct pkt_hdlrs pkt_hdlrs_dns = {
	"dns",
	0,
	init,
	parse_pkt,
	free_pkt,
	dump_pkt,
	errout_pkt
};

static int
_parse_qentry(unsigned char *data, int size, struct dns_qentry *qe)
{
	int i = 0, max_size;
	
	max_size = PKT_DNS_NAME_MAXSIZE;
	size -= 2 + 2 + 1; /* subtract qtype, qclass and first byte */
	if (max_size > size)
		max_size = size;
	
	while ((i < max_size) && (data[i])) {
		if (data[i] > (max_size - i - 1))
			return -1;
		if (i)
			qe->qname[i - 1] = '.';
		memcpy(qe->qname + i, data + i + 1, data[i]);
		i += data[i] + 1;
	}
	qe->qname[i - 1] = '\0';
	if (normalize_and_check_domain_name(qe->qname) < 0)
		return -1;
	qe->qname_len = i - 1;
	i++;
	qe->qtype = be16toh(*((uint16_t*)(data + i)));
	i += 2;
	qe->qclass = be16toh(*((uint16_t*)(data + i)));
	i += 2;
	
	return i;
}

