/*
 * traffic filter
 * Copyright (C) 2017, Oleg Nemanov <lego12239@yandex.ru>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "ipsrv_list.h"


static void ipsrv_list_item_free(struct ipsrv_list_item *item);
static struct ipsrv_list_item* ipsrv_list_item_make(uint8_t *value, unsigned int value_size, uint8_t *value_for_key, unsigned int vfk_size);
static struct ipsrv_list_item_value* ipsrv_list_item_value_make(uint8_t *value, unsigned int size);


static uint32_t
jenkins_one_at_a_time_hash(const uint8_t* key, size_t length)
{
	size_t i = 0;
	uint32_t hash = 0;
	
	while (i != length) {
		hash += key[i++];
		hash += hash << 10;
		hash ^= hash >> 6;
	}
	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;
	return hash;
}

static unsigned int
ipsrv_list_gen_key(uint8_t *value, unsigned int size)
{
	return jenkins_one_at_a_time_hash(value, size);
}

/*
 * Create new ip list with name of name.
 *
 * name - name of the list.
 *
 * return:
 *   pointer - if everything is ok
 *   NULL - if a memory error occured
 */
struct ipsrv_list*
ipsrv_list_make(void)
{
	struct ipsrv_list *l;
	
	l = malloc(sizeof(*l));
	if (!l)
		return NULL;
	memset(l, 0, sizeof(*l));
	
	return l;
}

static void
_ipsrv_list_free_item(struct avltree_node_head *h)
{
	struct ipsrv_list_item *item;
	
	item = avltree_node(h, struct ipsrv_list_item, tree);
	ipsrv_list_item_free(item);
}

/*
 * Free an ip list l.
 *
 * l - a pointer to an ip list to be freed
 *
 * return:
 *   0 - if everything is ok
 *   -EINVAL - if l is NULL
 */
int
ipsrv_list_free(struct ipsrv_list *l)
{
	if (!l)
		return -EINVAL;
	if (l->first)
		avltree_for_each_after(&(l->first->tree), _ipsrv_list_free_item);
	free(l);
	
	return 0;
}

static void
ipsrv_list_item_value_free(struct ipsrv_list_item_value *v)
{
	free(v);
}

static void
ipsrv_list_item_free(struct ipsrv_list_item *item)
{
	struct list_item_head *h;
	struct ipsrv_list_item_value *v;

	if (item->values) {	
		h = &(item->values->list);
		while (h) {
			v = list_item(h, struct ipsrv_list_item_value, list);
			h = h->next;
			ipsrv_list_item_value_free(v);
		}
	}
	free(item);
}

static int
_ipsrv_list_add_cb(struct avltree_node_head *new, struct avltree_node_head *e)
{
	struct ipsrv_list_item *item_new, *item_e;
	
	item_new = avltree_node(new, struct ipsrv_list_item, tree);
	item_e = avltree_node(e, struct ipsrv_list_item, tree);
	list_add(&(item_new->values->list), &(item_e->values->list));
	
	return 1;
}

/*
 * Add specified ip to a specified ipsrv_list.
 *
 * l - a pointer to ipsrv_list
 * value - a value to add
 * value_for_key - a value for key generation
 *
 * return:
 *   pointer - a pointer to struct ipsrv_list_item_value with new ip
 *   NULL - if memory error occured or value too large
 */
struct ipsrv_list_item_value*
ipsrv_list_add(struct ipsrv_list *l, uint8_t *value, unsigned int value_size,
  uint8_t *value_for_key, unsigned int vfk_size)
{
	struct ipsrv_list_item *item;
	struct ipsrv_list_item_value *v;
	struct avltree_node_head *new_root = &(l->first->tree);
	int ret;
	
	if (value_size > IPSRVLIST_VALUE_SIZE)
		return NULL;
	item = ipsrv_list_item_make(value, value_size, value_for_key, vfk_size);
	if (!item)
		return NULL;
	v = item->values;
	
	if (!l->first) {
		l->first = item;
	} else {
		ret = avltree_add(&(item->tree), &(l->first->tree), _ipsrv_list_add_cb,
		  &new_root);
		if (ret == 1) {
			item->values = NULL;
			ipsrv_list_item_free(item);
		} else if (ret != 0) {
			ipsrv_list_item_free(item);
			return NULL;
		}
		l->first = avltree_node(new_root, struct ipsrv_list_item, tree);
	}
	
	l->len++;
	
	return v;
}

static struct ipsrv_list_item*
ipsrv_list_item_make(uint8_t *value, unsigned int value_size,
  uint8_t *value_for_key, unsigned int vfk_size)
{
	struct ipsrv_list_item *item;

	item = malloc(sizeof(*item));
	if (!item)
		return NULL;
	memset(item, 0, sizeof(*item));
	avltree_node_head_init(&(item->tree));
	item->values = ipsrv_list_item_value_make(value, value_size);
	if (!item->values) {
		free(item);
		return NULL;
	}
	
	item->tree.key = ipsrv_list_gen_key(value_for_key, vfk_size);
	
	return item;
}

static struct ipsrv_list_item_value*
ipsrv_list_item_value_make(uint8_t *value, unsigned int size)
{
	struct ipsrv_list_item_value *v;
	
	v = malloc(sizeof(*v));
	if (!v)
		return NULL;
	memset(v, 0, sizeof(*v));
	list_item_head_init(&(v->list));
	v->len = size;
	memcpy(v->value, value, v->len);

	return v;
}

int
ipsrv_list_value_exist(struct ipsrv_list *l, uint8_t *value,
  unsigned int value_size, uint8_t *value_for_key, unsigned int vfk_size)
{
	struct ipsrv_list_item *item;
	struct ipsrv_list_item_value *v;
	struct avltree_node_head *nh;
	struct list_item_head *lh;
	unsigned int key;
	
	if (!l->first)
		return 0;
	key = ipsrv_list_gen_key(value_for_key, vfk_size);
	nh = avltree_search(&(l->first->tree), key);
	if (!nh)
		return 0;
	item = avltree_node(nh, struct ipsrv_list_item, tree);
	list_for_each(lh, &(item->values->list)) {
		v = list_item(lh, struct ipsrv_list_item_value, list);
		if (v->len <= value_size)
			if (memcmp(value, v->value, v->len) == 0)
				return 1;
	}
	
	return 0;
}
