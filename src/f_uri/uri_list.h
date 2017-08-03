#ifndef __URILIST_H__
#define __URILIST_H__

#include "list.h"
#include "avltree.h"

struct uri_list {
	struct uri_list_item *first;
	unsigned int len;
};

struct uri_list_item_value {
	struct list_item_head list;
	char *value;
};

struct uri_list_item {
	struct avltree_node_head tree;
	struct uri_list_item_value *values;
};


/*
 * Create new uri list with name of name.
 *
 * name - name of the list.
 *
 * return:
 *   pointer - if everything is ok
 *   NULL - if a memory error occured
 */
struct uri_list* uri_list_make(void);
/*
 * Free a uri list l.
 *
 * l - a pointer to a uri list to be freed
 *
 * return:
 *   0 - if everything is ok
 *   -EINVAL - if l is NULL
 */
int uri_list_free(struct uri_list *l);
/*
 * Add specified uri to a specified uri_list.
 *
 * l - a pointer to uri_list
 * value - a value to add
 *
 * return:
 *   pointer - a pointer to struct uri_list_item_value with new uri
 *   NULL - if memory error occured or value too large
 */
struct uri_list_item_value* uri_list_add(struct uri_list *l, char *value);
int uri_list_value_exist(struct uri_list *l, char *value);


#endif /* __URILIST_H__ */
