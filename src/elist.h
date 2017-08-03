#ifndef __ELIST_H__
#define __ELIST_H__

#include <stdint.h>
#include "list.h"


enum elist_act {
	elist_act_accept,
	elist_act_drop,
	elist_act_repeat
};

struct elist {
	struct list_item_head list;
	char *name;
	char *fname;
	void **f_list;
	enum elist_act act_on_match;
	uint32_t mark_on_match;
};

struct elist_chain {
	struct elist *elist_first;
	void *conf;
	/* FUTURE: */
	enum elist_act act_default;
	uint32_t mark_default;
};

/*
 * Make an empty elist.
 *
 * return:
 *   elist - a pointer to a created elist
 *   NULL - a memory error occured
 */
struct elist* elist_make(void);
void elist_free(struct elist *elist);
/*
 * Add new elist to tail of the existing elists chain.
 * elist - any elist from a chain
 * new - new elist to add
 */
void elist_add(struct elist *elist, struct elist *new);

/*
 * Create a elist chain.
 *
 * return:
 *   elist_chain - a pointer to a created elist chain
 *   NULL - a memory error occured
 */
struct elist_chain* elist_chain_make(void);
void elist_chain_free(struct elist_chain *elchain);

#endif  /* __ELIST_H__ */