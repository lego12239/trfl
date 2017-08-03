#ifndef __FILTERS_H__
#define __FILTERS_H__

#include "pkt/pkt.h"

struct filter {
	char *name;
	int (*init)(void);
	int (*list_make)(void **list);
	int (*list_free)(void *list);
	int (*list_entry_add)(void *list, char **fields, unsigned int n);
	int (*list_stat_out)(void *list);
	int (*filter_pkt)(void *list, struct pkt *pkt);
};

extern struct filter *filters[];

#endif /* __FILTERS_H__ */