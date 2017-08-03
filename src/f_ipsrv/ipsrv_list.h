#ifndef __IPSRVLIST_H__
#define __IPSRVLIST_H__

#include "list.h"
#include "avltree.h"

#define IPSRVLIST_VALUE_SIZE 7

struct ipsrv_list {
	struct ipsrv_list_item *first;
	unsigned int len;
};

struct ipsrv_list_item_value {
	struct list_item_head list;
	/* ip(4):proto(1):port(2) */
	uint8_t value[IPSRVLIST_VALUE_SIZE];
	unsigned int len;
};

struct ipsrv_list_item {
	struct avltree_node_head tree;
	struct ipsrv_list_item_value *values;
};


struct ipsrv_list* ipsrv_list_make(void);
int ipsrv_list_free(struct ipsrv_list *l);
struct ipsrv_list_item_value* ipsrv_list_add(struct ipsrv_list *l, uint8_t *value, unsigned int value_size, uint8_t *value_for_key, unsigned int vfk_size);
int ipsrv_list_value_exist(struct ipsrv_list *l, uint8_t *value, unsigned int value_size, uint8_t *value_for_key, unsigned int vfk_size);


#endif /* __IPSRVLIST_H__ */
