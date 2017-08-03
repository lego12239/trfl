#ifndef __IPPROTOS_H__
#define __IPPROTOS_H__

#include "pkt/pkt.h"

struct ipproto {
	char *name;
	unsigned char idx;
	int (*make_value)(char **fields, unsigned int n, uint8_t *value, unsigned int value_size);
	int (*make_value2)(struct pkt *pkt, uint8_t *value, unsigned int value_size);
};

extern struct ipproto *ipprotos_list[];

#endif /* __IPPROTOS_H__ */