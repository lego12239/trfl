#ifndef __LIST_H__
#define __LIST_H__

/*
 * TODO:
 * - list_replace()?
 * - list_move()?
 * - join head and tail like in kernel list.h?
 */

#include <stddef.h>
#include <string.h>


struct list_item_head {
	struct list_item_head *next;
	struct list_item_head *prev;
};

#ifdef __GNUC__
#define list_item(ptr, type, member) ({ \
	const typeof(((type*)0)->member) *__mptr = (ptr); \
	(type*)((char*)(__mptr) - offsetof(type, member));})
#else
#define list_item(ptr, type, member) \
	(type*)((char*)(ptr) - offsetof(type, member))
#endif  /* __GNUC__ */

#define list_for_each(h, start) \
	for(h = (start); h; h = h->next)

static inline void list_item_head_init(struct list_item_head *h)
{
	memset(h, 0, sizeof(*h));
}

static inline void _list_add(struct list_item_head *new, struct list_item_head *prev, struct list_item_head *next)
{
	new->prev = prev;
	new->next = next;
	if (next)
		next->prev = new;
	if (prev)
		prev->next = new;
}

static inline void list_add(struct list_item_head *new, struct list_item_head *h)
{
	_list_add(new, h, h->next);
}

static inline void list_add_before(struct list_item_head *new, struct list_item_head *h)
{
	_list_add(new, h->prev, h);
}

static inline void list_rm(struct list_item_head *h)
{
	if (h->prev)
		h->prev->next = h->next;
	if (h->next)
		h->next->prev = h->prev;
	h->next = NULL;
	h->prev = NULL;
}

static inline void list_free(struct list_item_head *h, void (*cb)(struct list_item_head *lh))
{
	struct list_item_head *next;
	
	for(; h; h = next) {
		next = h->next;
		cb(h);
	}
}

#endif /* __LIST_H__ */
