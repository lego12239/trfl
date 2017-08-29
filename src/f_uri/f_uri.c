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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include "main.h"
#include "log.h"
#include "pkt/pkt.h"
#include "filters.h"
#include "uri_list.h"


static int
init(void)
{
	return 0;
}

static int
list_make(void **list)
{
	struct uri_list *urilist;

	urilist = uri_list_make();
	if (!urilist) {
		ERR_OUT("uri: can't allocate memory for list");
		return -1;
	}
	
	*list = urilist;
	
	return 0;
}

static int
flist_free(void *list)
{
	struct uri_list *urilist = list;
	
	if (uri_list_free(urilist) != 0)
		ERR_OUT("uri: error on list free");
	
	return 0;
}

/*
 * Try to add entry to list.
 * If entry is not processible by this filter, ignore it and return -1.
 * list - a pointer to a list
 * fields - a pointer to array of strings
 * n - number of strings in array
 *
 * return:
 *   1 - entry is not processible by this filter - ignored
 *   0 - entry is added
 *  <0 - an error is occured
 */
static int
list_entry_add(void *list, char **fields, unsigned int n)
{
	struct uri_list *urilist = list;
	
	if (strcmp(fields[0], "uri") != 0)
		return 1;
	if (n < 2)
		return 0;
	if (fields[1][0] != '\0') {
		if (!uri_list_add(urilist, fields[1])) {
			ERR_OUT("uri: uri add error: %s: no memory", fields[1]);
			return -1;
		}
		DBG_OUT("uri: add uri %s", fields[1]);
	}
	
	return 0;
}

static int
list_stat_out(void *list)
{
	struct uri_list *urilist = list;
	
	INFO_OUT("f_uri: list entries %u", urilist->len);
	
	return 0;
}

static int
filter_pkt(void *list, struct pkt *pkt)
{
	struct uri_list *urilist = list;
	struct pkt_nfq *pkt_nfq;
	struct list_item_head *lh;
	struct conn_uri *uri;
	int ret;
	
	pkt_nfq = (struct pkt_nfq*)pkt;
	if (!pkt_nfq->uri)
		return 0;

	list_for_each(lh, &pkt_nfq->uri->list) {
		uri = list_item(lh, struct conn_uri, list);
		ret = uri_list_value_exist(urilist, uri->value);
		if (ret)
			return 1;
	}
	return 0;
}

struct filter filter_f_uri = {
	"uri",
	init,
	list_make,
	flist_free,
	list_entry_add,
	list_stat_out,
	filter_pkt
};

