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
#include <stdint.h>
#include <pthread.h>
#include "filters.h"
#include "log.h"
#include "elist.h"


/*
 * Make an empty elist.
 *
 * return:
 *   elist - a pointer to a created elist
 *   NULL - a memory error occured
 */
struct elist*
elist_make(void)
{
	struct elist *elist;
	int i;
	
	elist = malloc(sizeof(*elist));
	if (!elist)
		return NULL;
	memset(elist, 0, sizeof(*elist));
	for(i = 0; filters[i]; i++);
	elist->f_list = malloc(sizeof(*elist->f_list) * i);
	if (!elist->f_list) {
		free(elist);
		return NULL;
	}
	memset(elist->f_list, 0, sizeof(*elist->f_list) * i);
	return elist;
}

void
elist_free(struct elist *elist)
{
	int i;
	
	free(elist->name);
	free(elist->fname);
	for(i = 0; filters[i]; i++)
		if (elist->f_list[i])
			filters[i]->list_free(elist->f_list[i]);
	free(elist);
}

/*
 * Add new elist to tail of the existing elists chain.
 * elist - any elist from a chain
 * new - new elist to add
 */
void
elist_add(struct elist *elist, struct elist *new)
{
	struct list_item_head *lh;
	
	list_for_each(lh, &elist->list) {
		if (!lh->next) {
			list_add(&new->list, lh);
			break;
		}
	}
}

/*
 * Create a elist chain.
 *
 * return:
 *   elist_chain - a pointer to a created elist chain
 *   NULL - a memory error occured
 */
struct elist_chain*
elist_chain_make(void)
{
	struct elist_chain *elchain;
	
	elchain = malloc(sizeof(*elchain));
	if (!elchain) {
		ERR_OUT("elist chain creation error: no memory");
		return NULL;
	}
	memset(elchain, 0, sizeof(*elchain));
	
	return elchain;
}

static void
_elist_chain_free_cb(struct list_item_head *lh)
{
	struct elist *elist;
	
	elist = list_item(lh, struct elist, list);
	elist_free(elist);
}

void
elist_chain_free(struct elist_chain *elchain)
{
	list_free(&elchain->elist_first->list, _elist_chain_free_cb);
	free(elchain);
}
