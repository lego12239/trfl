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
#include "domain_list.h"


static void domain_list_item_free(struct domain_list_item *item);
static struct domain_list_item* domain_list_item_make(char *value, unsigned int size, char *vfk, unsigned int vfk_size);
static struct domain_list_item_value* domain_list_item_value_make(char *value, unsigned int size);


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
domain_list_gen_key(char *value, unsigned int size)
{
	return jenkins_one_at_a_time_hash((uint8_t*)value, size);
}

/*
 * Create new domain list with name of name.
 *
 * name - name of the list.
 *
 * return:
 *   pointer - if everything is ok
 *   NULL - if a memory error occured
 */
struct domain_list*
domain_list_make(void)
{
	struct domain_list *l;
	
	l = malloc(sizeof(*l));
	if (!l)
		return NULL;
	memset(l, 0, sizeof(*l));
	
	return l;
}

static void
_domain_list_free_item(struct avltree_node_head *h)
{
	struct domain_list_item *item;
	
	item = avltree_node(h, struct domain_list_item, tree);
	domain_list_item_free(item);
}

/*
 * Free a domain list l.
 *
 * l - a pointer to a domain list to be freed
 *
 * return:
 *   0 - if everything is ok
 *   -EINVAL - if l is NULL
 */
int
domain_list_free(struct domain_list *l)
{
	if (!l)
		return -EINVAL;
	if (l->first)
		avltree_for_each_after(&(l->first->tree), _domain_list_free_item);
	free(l);
	
	return 0;
}

static void
domain_list_item_value_free(struct domain_list_item_value *v)
{
	if (v->value)
		free(v->value);
	free(v);
}

static void
domain_list_item_free(struct domain_list_item *item)
{
	struct list_item_head *h;
	struct domain_list_item_value *v;

	if (item->values) {	
		h = &(item->values->list);
		while (h) {
			v = list_item(h, struct domain_list_item_value, list);
			h = h->next;
			domain_list_item_value_free(v);
		}
	}
	free(item);
}

static int
_domain_list_add_cb(struct avltree_node_head *new, struct avltree_node_head *e)
{
	struct domain_list_item *item_new, *item_e;
	
	item_new = avltree_node(new, struct domain_list_item, tree);
	item_e = avltree_node(e, struct domain_list_item, tree);
	list_add(&(item_new->values->list), &(item_e->values->list));
	
	return 1;
}

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
struct domain_list_item_value*
domain_list_add(struct domain_list *l, char *value, unsigned int size,
  char *vfk, unsigned int vfk_size)
{
	struct domain_list_item *item;
	struct domain_list_item_value *v;
	struct avltree_node_head *new_root = &(l->first->tree);
	int ret;
	
	item = domain_list_item_make(value, size, vfk, vfk_size);
	if (!item)
		return NULL;
	v = item->values;
	
	if (!l->first) {
		l->first = item;
	} else {
		ret = avltree_add(&(item->tree), &(l->first->tree), _domain_list_add_cb,
		  &new_root);
		if (ret == 1) {
			item->values = NULL;
			domain_list_item_free(item);
		} else if (ret != 0) {
			domain_list_item_free(item);
			return NULL;
		}
		l->first = avltree_node(new_root, struct domain_list_item, tree);
	}
	
	l->len++;
	
	return v;
}

static struct domain_list_item*
domain_list_item_make(char *value, unsigned int size, char *vfk,
  unsigned int vfk_size)
{
	struct domain_list_item *item;

	item = malloc(sizeof(*item));
	if (!item)
		return NULL;
	memset(item, 0, sizeof(*item));
	avltree_node_head_init(&(item->tree));
	item->values = domain_list_item_value_make(value, size);
	if (!item->values) {
		free(item);
		return NULL;
	}
	
	item->tree.key = domain_list_gen_key(vfk, vfk_size);
	
	return item;
}

static struct domain_list_item_value*
domain_list_item_value_make(char *value, unsigned int size)
{
	struct domain_list_item_value *v;
	
	v = malloc(sizeof(*v));
	if (!v)
		return NULL;
	memset(v, 0, sizeof(*v));
	list_item_head_init(&(v->list));
	v->len = size;
	v->value = malloc(size);
	if (!v->value) {
		free(v);
		return NULL;
	}
	memcpy(v->value, value, size);

	return v;
}

int
domain_list_value_exist(struct domain_list *l, char *value,
  unsigned int size, char *vfk, unsigned int vfk_size)
{
	struct domain_list_item *item;
	struct domain_list_item_value *v;
	struct avltree_node_head *nh;
	struct list_item_head *lh;
	unsigned int key;
	
	if (!l->first)
		return 0;
	key = domain_list_gen_key(vfk, vfk_size);
	nh = avltree_search(&(l->first->tree), key);
	if (!nh)
		return 0;
	item = avltree_node(nh, struct domain_list_item, tree);
	list_for_each(lh, &(item->values->list)) {
		v = list_item(lh, struct domain_list_item_value, list);
		if ((size >= v->len) && (memcmp(value, v->value, v->len) == 0))
			return 1;
	}
	
	return 0;
}
