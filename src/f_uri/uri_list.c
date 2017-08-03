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
#include "uri_list.h"


static void uri_list_item_free(struct uri_list_item *item);
static struct uri_list_item* uri_list_item_make(char *value);
static struct uri_list_item_value* uri_list_item_value_make(char *value);


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
uri_list_gen_key(char *value)
{
	return jenkins_one_at_a_time_hash((uint8_t*)value, strlen(value));
}

/*
 * Create new uri list with name of name.
 *
 * name - name of the list.
 *
 * return:
 *   pointer - if everything is ok
 *   NULL - if a memory error occured
 */
struct uri_list*
uri_list_make(void)
{
	struct uri_list *l;
	
	l = malloc(sizeof(*l));
	if (!l)
		return NULL;
	memset(l, 0, sizeof(*l));
	
	return l;
}

static void
_uri_list_free_item(struct avltree_node_head *h)
{
	struct uri_list_item *item;
	
	item = avltree_node(h, struct uri_list_item, tree);
	uri_list_item_free(item);
}

/*
 * Free a uri list l.
 *
 * l - a pointer to a uri list to be freed
 *
 * return:
 *   0 - if everything is ok
 *   -EINVAL - if l is NULL
 */
int
uri_list_free(struct uri_list *l)
{
	if (!l)
		return -EINVAL;
	if (l->first)
		avltree_for_each_after(&(l->first->tree), _uri_list_free_item);
	free(l);
	
	return 0;
}

static void
uri_list_item_value_free(struct uri_list_item_value *v)
{
	if (v->value)
		free(v->value);
	free(v);
}

static void
uri_list_item_free(struct uri_list_item *item)
{
	struct list_item_head *h;
	struct uri_list_item_value *v;

	if (item->values) {	
		h = &(item->values->list);
		while (h) {
			v = list_item(h, struct uri_list_item_value, list);
			h = h->next;
			uri_list_item_value_free(v);
		}
	}
	free(item);
}

static int
_uri_list_add_cb(struct avltree_node_head *new, struct avltree_node_head *e)
{
	struct uri_list_item *item_new, *item_e;
	
	item_new = avltree_node(new, struct uri_list_item, tree);
	item_e = avltree_node(e, struct uri_list_item, tree);
	list_add(&(item_new->values->list), &(item_e->values->list));
	
	return 1;
}

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
struct uri_list_item_value*
uri_list_add(struct uri_list *l, char *value)
{
	struct uri_list_item *item;
	struct uri_list_item_value *v;
	struct avltree_node_head *new_root = &(l->first->tree);
	int ret;
	
	item = uri_list_item_make(value);
	if (!item)
		return NULL;
	v = item->values;
	
	if (!l->first) {
		l->first = item;
	} else {
		ret = avltree_add(&(item->tree), &(l->first->tree), _uri_list_add_cb,
		  &new_root);
		if (ret == 1) {
			item->values = NULL;
			uri_list_item_free(item);
		} else if (ret != 0) {
			uri_list_item_free(item);
			return NULL;
		}
		l->first = avltree_node(new_root, struct uri_list_item, tree);
	}
	
	l->len++;
	
	return v;
}

static struct uri_list_item*
uri_list_item_make(char *value)
{
	struct uri_list_item *item;

	item = malloc(sizeof(*item));
	if (!item)
		return NULL;
	memset(item, 0, sizeof(*item));
	avltree_node_head_init(&(item->tree));
	item->values = uri_list_item_value_make(value);
	if (!item->values) {
		free(item);
		return NULL;
	}
	
	item->tree.key = uri_list_gen_key(value);
	
	return item;
}

static struct uri_list_item_value*
uri_list_item_value_make(char *value)
{
	struct uri_list_item_value *v;
	
	v = malloc(sizeof(*v));
	if (!v)
		return NULL;
	memset(v, 0, sizeof(*v));
	list_item_head_init(&(v->list));
	v->value = strdup(value);
	if (!v->value) {
		free(v);
		return NULL;
	}

	return v;
}

int
uri_list_value_exist(struct uri_list *l, char *value)
{
	struct uri_list_item *item;
	struct uri_list_item_value *v;
	struct avltree_node_head *nh;
	struct list_item_head *lh;
	unsigned int key;
	
	if (!l->first)
		return 0;
	key = uri_list_gen_key(value);
	nh = avltree_search(&(l->first->tree), key);
	if (!nh)
		return 0;
	item = avltree_node(nh, struct uri_list_item, tree);
	list_for_each(lh, &(item->values->list)) {
		v = list_item(lh, struct uri_list_item_value, list);
		if (strcmp(value, v->value) == 0)
			return 1;
	}
	
	return 0;
}
