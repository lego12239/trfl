#ifndef __PKT_H__
#define __PKT_H__

#include "../list.h"
#include "pkts_types.h"

#define PKT_HEAD \
	struct list_item_head list; \
	enum pkt_type pkt_type; \
	unsigned int pkt_len; \
	unsigned char *pkt_raw;

struct pkt {
	PKT_HEAD
};

struct conn_domain {
	struct list_item_head list;
	char *name;
};

struct conn_uri {
	struct list_item_head list;
	char *value;
};

struct pkt_nfq {
	PKT_HEAD
	uint32_t id;
	struct conn_domain *domain;
	struct conn_uri *uri;
};


#define PKT_ERROUT(pkt, fmt, ...) pkt_errout((pkt), "%s:%u: " fmt "\n", \
  __FILE__, __LINE__, ##__VA_ARGS__)


int pkt_init(void);
struct pkt* pkt_make(unsigned char *data, int size, uint32_t id);
uint32_t get_pkt_id(struct pkt *pkt);
struct pkt* get_next_pkt(struct pkt *pkt);
int pkt_domain_add(struct pkt *pkt, char *name, int len);
int pkt_uri_add(struct pkt *pkt, char *value);
void pkt_free(struct pkt *pkt);
void pkt_dump(struct pkt *pkt);
void pkt_errout(struct pkt *pkt, const char * const fmt, ...);


#endif /* __PKT_H__ */
