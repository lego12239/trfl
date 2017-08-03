#ifndef __PKTS_HDLRS_H__
#define __PKTS_HDLRS_H__

#include "pkt.h"
#include "pkts_types.h"

/*
 * init and parse_pkt error codes:
 * -1  - no mem
 */
struct pkt_hdlrs {
	char *name;
	enum pkt_type type;
	int (*init)(void);
	int (*parse_pkt)(struct pkt *pkt_prev, unsigned char *data, int size);
	int (*free_pkt)(struct pkt *pkt);
	int (*dump_pkt)(struct pkt *pkt);
	int (*errout_pkt)(struct pkt *pkt);
};

extern struct pkt_hdlrs *pkts_list[];

#endif /* __PKTS_HDLRS_H__ */