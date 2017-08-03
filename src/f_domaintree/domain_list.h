#ifndef __DOMAINLIST_H__
#define __DOMAINLIST_H__

#include "list.h"
#include "avltree.h"

struct domain_list {
	struct domain_list_item *first;
	unsigned int len;
};

struct domain_list_item_value {
	struct list_item_head list;
	char *value;
	unsigned int len;
};

struct domain_list_item {
	struct avltree_node_head tree;
	struct domain_list_item_value *values;
};


/*
 * Create new domain list with name of name.
 *
 * name - name of the list.
 *
 * return:
 *   pointer - if everything is ok
 *   NULL - if a memory error occured
 */
struct domain_list* domain_list_make(void);
/*
 * Free a domain list l.
 *
 * l - a pointer to a domain list to be freed
 *
 * return:
 *   0 - if everything is ok
 *   -EINVAL - if l is NULL
 */
int domain_list_free(struct domain_list *l);
/*
 * Add specified domain to a specified domain_list.
 *
 * l - a pointer to domain_list
 * value - a value to add
 * size - a value size
 * vfk - a value for key generation
 * vfk_size - a size of value for key
 *
 * return:
 *   pointer - a pointer to struct domain_list_item_value with new domain
 *   NULL - if memory error occured or value too large
 */
struct domain_list_item_value* domain_list_add(struct domain_list *l, char *value, unsigned int size, char *vfk, unsigned int vfk_size);
int domain_list_value_exist(struct domain_list *l, char *value, unsigned int size, char *vfk, unsigned int vfk_size);


#endif /* __DOMAINLIST_H__ */
