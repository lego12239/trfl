#ifndef __PKT_DNS_H__
#define __PKT_DNS_H__

#define PKT_DNS_NAME_MAXSIZE 256

struct dns_qentry {
	char qname[PKT_DNS_NAME_MAXSIZE];
	unsigned int qname_len;
	uint16_t qtype;
	uint16_t qclass;
};

struct pkt_dns {
	PKT_HEAD
	uint16_t id;
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
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
	struct dns_qentry *qentry;
};

#endif  /* __PKT_DNS_H__ */
