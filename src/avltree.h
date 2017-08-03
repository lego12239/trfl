#ifndef __AVLTREE_H__
#define __AVLTREE_H__


#include <stddef.h>


struct avltree_node_head {
	unsigned int key;
	unsigned int height;
	struct avltree_node_head *parent;
	struct avltree_node_head *left;
	struct avltree_node_head *right;
};


#ifdef __GNUC__
#define avltree_node(ptr, type, member) ({ \
	const typeof(((type*)0)->member) *__mptr = (ptr); \
	(type*)((char*)(__mptr) - offsetof(type, member));})
#else
#define avltree_node(ptr, type, member) \
	(type*)((char*)(ptr) - offsetof(type, member))
#endif  /* __GNUC__ */

/*
 * Init a node head.
 *
 * h - a node head to init
 */
void avltree_node_head_init(struct avltree_node_head *h);

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
struct avltree_node_head* avltree_search(struct avltree_node_head *h, unsigned int key);

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
int avltree_add(struct avltree_node_head *new, struct avltree_node_head *h, int (*cb)(struct avltree_node_head*, struct avltree_node_head*), struct avltree_node_head **new_root);

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
int avltree_rm(struct avltree_node_head *h, struct avltree_node_head **new_root);
/*
 * Recursively walk through tree, starting from specified node head,
 * and call a callback for each node head _before_ processing it left and
 * right nodes.
 *
 * h - a pointer to node head to start walking from
 * cb - a pointer to a callback
 */
void avltree_for_each_before(struct avltree_node_head *h, void (*cb)(struct avltree_node_head*));
/*
 * Recursively walk through tree, starting from specified node head,
 * and call a callback for each node head _after_ processing it left and
 * right nodes.
 *
 * h - a pointer to node head to start walking from
 * cb - a pointer to a callback
 */
void avltree_for_each_after(struct avltree_node_head *h, void (*cb)(struct avltree_node_head*));
void avltree_dump(struct avltree_node_head *h);


#endif /* __AVLTREE_H__ */
