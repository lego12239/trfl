/*
 * AVL-tree library
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
#include <errno.h>
#include "avltree.h"


static struct avltree_node_head* _avltree_search(unsigned int mode, struct avltree_node_head *h, unsigned int key);
static void _avltree_balance(struct avltree_node_head *h, struct avltree_node_head **new_root);
static int _avltree_node_bf(struct avltree_node_head *h);
static void _avltree_node_rotate_r(struct avltree_node_head *h, struct avltree_node_head **new_root);
static void _avltree_node_rotate_l(struct avltree_node_head *h, struct avltree_node_head **new_root);
static void _avltree_node_height_update(struct avltree_node_head *h);
static int _avltree_node_height_get(struct avltree_node_head *h);
static struct avltree_node_head* _avltree_search_min(struct avltree_node_head *h);


/*
 * Init a node head.
 *
 * h - a node head to init
 */
void
avltree_node_head_init(struct avltree_node_head *h)
{
	memset(h, 0, sizeof(*h));
}

/*
 * Search a node with a given key.
 *
 * h - a node to start searching from
 * key - a key to search
 *
 * return:
 *   pointer - if node is found
 *   NULL - if node isn't found
 */
struct avltree_node_head*
avltree_search(struct avltree_node_head *h, unsigned int key)
{
	return _avltree_search(0, h, key);
}

/*
 * Search a node with a given key(mode = 0).
 * Search a node with a given key or, if such node isn't yet exist, a node
 * which would be a parent for a such node(mode = 1).
 *
 * mode - an operation mode
 * h - a node to start searching from
 * key - a key to search
 *
 * return:
 *   pointer - if node is found
 *   NULL - if node isn't found
 */
static struct avltree_node_head*
_avltree_search(unsigned int mode, struct avltree_node_head *h,
  unsigned int key)
{
	struct avltree_node_head *next;
	
	for(; h && h->key != key; h = next) {
		if (key > h->key)
			next = h->right;
		else
			next = h->left;
		if ((mode == 1) && (!next))
			break;
	}
	
	return h;
}

/*
 * Add new node to a tree.
 * Node must be removed from previous tree(if any), before this function
 * call.
 * Callback is called, if node with this key already exist.
 *
 * new  - a node head to add
 * h    - a tree root node head
 * cb   - a callback function(must return 0 on ok, non avltree_add()
 *        return codes on error)
 * new_root - if root node is changed due to rebalancing, here will be
 *            placed a pointer to it
 * return:
 *   0 - if everything is ok
 *   -EINVAL - if new or h is NULL
 *   -EADDRINUSE - item is already linked
 *   -EEXIST - node with new->key exist and no callback is supplied
 *   ANOTHER - any other value which returned by callback
 */
int
avltree_add(struct avltree_node_head *new, struct avltree_node_head *h,
  int (*cb)(struct avltree_node_head*, struct avltree_node_head*),
  struct avltree_node_head **new_root)
{
	struct avltree_node_head *parent;
	
	if ((!new) || (!h))
		return -EINVAL;
	parent = _avltree_search(1, h, new->key);
	if (parent->key == new->key) {
		if (!cb)
			return -EEXIST;
		return cb(new, parent);
	}
	
	new->parent = parent;
	if (new->key > parent->key)
		parent->right = new;
	else
		parent->left = new;

	_avltree_balance(parent, new_root);
	
	return 0;
}

static void
_avltree_balance(struct avltree_node_head *h,
  struct avltree_node_head **new_root)
{
	int bf;
	
	while (h) {
		bf = _avltree_node_bf(h);
		if (bf > 1) {
			if (_avltree_node_bf(h->left) < 0)
				_avltree_node_rotate_l(h->left, new_root);
			_avltree_node_rotate_r(h, new_root);
		} else if (bf < -1) {
			if (_avltree_node_bf(h->right) > 0)
				_avltree_node_rotate_r(h->right, new_root);
			_avltree_node_rotate_l(h, new_root);
		}
		
		_avltree_node_height_update(h);
		h = h->parent;
	}
}

static int
_avltree_node_bf(struct avltree_node_head *h)
{
	int bf = _avltree_node_height_get(h->left);
	
	bf -= _avltree_node_height_get(h->right);

	return bf;
}

static int
_avltree_node_height_get(struct avltree_node_head *h)
{
	if (!h)
		return -1;
	return h->height;
}

static void
_avltree_node_height_update(struct avltree_node_head *h)
{
	int hl, hr;
	
	hl = _avltree_node_height_get(h->left);
	hr = _avltree_node_height_get(h->right);
	h->height = ((hl > hr) ? hl : hr) + 1;
}

static void
_avltree_node_rotate_r(struct avltree_node_head *h,
  struct avltree_node_head **new_root)
{
	struct avltree_node_head *p;
	
	p = h->left;
	h->left = p->right;
	if (p->right)
		p->right->parent = h;
	p->right = h;
	p->parent = h->parent;
	h->parent = p;
	if (p->parent) {	
		if (p->parent->left == h)
			p->parent->left = p;
		else
			p->parent->right = p;
	} else {
		*new_root = p;
	}
	
	_avltree_node_height_update(h);
	_avltree_node_height_update(p);
}

static void
_avltree_node_rotate_l(struct avltree_node_head *h,
  struct avltree_node_head **new_root)
{
	struct avltree_node_head *p;
	
	p = h->right;
	h->right = p->left;
	if (p->left)
		p->left->parent = h;
	p->left = h;
	p->parent = h->parent;
	h->parent = p;
	if (p->parent) {	
		if (p->parent->left == h)
			p->parent->left = p;
		else
			p->parent->right = p;
	} else {
		*new_root = p;
	}

	_avltree_node_height_update(h);
	_avltree_node_height_update(p);
}

/*
 * Remove a node from a tree.
 * Node must be removed from previous tree(if any), before this function
 * call.
 *
 * h - a node to remove
 * new_root - if root node is changed due to rebalancing, here will be
 *            placed a pointer to it
 *
 * return:
 *   0 - if everything is ok
 *   -EINVAL - if t or item is NULL
 *   -EADDRINUSE - item is already linked
 */
int
avltree_rm(struct avltree_node_head *h, struct avltree_node_head **new_root)
{
	struct avltree_node_head *r; /* replacement node */
	struct avltree_node_head *rb; /* node to start rebalancing from */
	unsigned int children_n;
	
	if (!h)
		return -EINVAL;
		
	if ((!h->left) && (!h->right)) {
		/* 1 case: no children */
		children_n = 0;
		r = NULL;
		rb = h->parent;
	} else if ((!h->left) || (!h->right)) {
		/* 2 case: 1 child */
		children_n = 1;
		if (h->left)
			r = h->left;
		else
			r = h->right;
		rb = h->parent;
	} else {
		/* 3 case: 2 children */
		children_n = 2;
		r = _avltree_search_min(h->right);
		avltree_rm(r, new_root);
		rb = r;
	}
	
	if (h->parent) {
		if (h->parent->left == h)
			h->parent->left = r;
		else
			h->parent->right = r;
	}
	if (children_n == 0)
		goto out;
	r->parent = h->parent;
	if (children_n == 1)
		goto out;
	if (h->left)
		h->left->parent = r;
	r->left = h->left;
	if (h->right)
		h->right->parent = r;
	r->right = h->right;

out:
	h->parent = NULL;
	h->left = NULL;
	h->right = NULL;
	
	_avltree_balance(rb, new_root);
	
	return 0;
}

static struct avltree_node_head*
_avltree_search_min(struct avltree_node_head *h)
{
	if (!h)
		return NULL;
	while (h->left)
		h = h->left;
	
	return h;
}

/*
 * Recursively walk through tree, starting from specified node head,
 * and call a callback for each node head _before_ processing it left and
 * right nodes.
 *
 * h - a pointer to node head to start walking from
 * cb - a pointer to a callback
 */
void
avltree_for_each_before(struct avltree_node_head *h,
  void (*cb)(struct avltree_node_head*))
{
	if (!h)
		abort();
	
	cb(h);
	if (h->left)
		avltree_for_each_before(h->left, cb);
	if (h->right)
		avltree_for_each_before(h->right, cb);
}

/*
 * Recursively walk through tree, starting from specified node head,
 * and call a callback for each node head _after_ processing it left and
 * right nodes.
 *
 * h - a pointer to node head to start walking from
 * cb - a pointer to a callback
 */
void
avltree_for_each_after(struct avltree_node_head *h,
  void (*cb)(struct avltree_node_head*))
{
	if (!h)
		abort();
	
	if (h->left)
		avltree_for_each_after(h->left, cb);
	if (h->right)
		avltree_for_each_after(h->right, cb);
	cb(h);
}

void
avltree_dump(struct avltree_node_head *h)
{
	unsigned int kl, kr, kp;

	if (!h)
		return;
		
	if (h->left)
		kl = h->left->key;
	else
		kl = 0;
	if (h->right)
		kr = h->right->key;
	else
		kr = 0;
	if (h->parent)
		kp = h->parent->key;
	else
		kp = 0;
	printf("node %u(height - %u), parent - %u, left - %u, right - %u\n", 
	  h->key, h->height, kp, kl, kr);
	avltree_dump(h->left);
	avltree_dump(h->right);
}
