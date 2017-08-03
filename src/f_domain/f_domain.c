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
#include <string.h>
#include <endian.h>
#include "main.h"
#include "log.h"
#include "util.h"
#include "pkt/pkt.h"
#include "filters.h"
#include "domain_list.h"


static int
init(void)
{
	return 0;
}

static int
list_make(void **list)
{
	struct domain_list *domainlist;

	domainlist = domain_list_make();
	if (!domainlist) {
		ERR_OUT("domain: can't allocate memory for list");
		return -1;
	}
	
	*list = domainlist;
	
	return 0;
}

static int
flist_free(void *list)
{
	struct domain_list *domainlist = list;
	
	if (domain_list_free(domainlist) != 0)
		ERR_OUT("domain: error on list free");
	
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
 *  <0 - an error occured
 */
static int
list_entry_add(void *list, char **fields, unsigned int n)
{
	struct domain_list *domainlist = list;
	char buf[260];
	unsigned int len;
	
	if (strcmp(fields[0], "domain") != 0)
		return 1;
	if (n < 2)
		return 0;
	if (fields[1][0] != '\0') {
		len = strlen(fields[1]);
		if (len > 255) {
			ERR_OUT("domain: domain add error: %s: name too long", fields[1]);
			return -1;
		}
		len++;
		memcpy(buf, fields[1], len);
		normalize_domain_name(buf);
		if (!domain_list_add(domainlist, buf, len, buf, len)) {
			ERR_OUT("domain: domain add error: %s: no memory", buf);
			return -1;
		}
		DBG_OUT("domain: add domain %s", buf);
	}
	
	return 0;
}

static int
list_stat_out(void *list)
{
	struct domain_list *domainlist = list;
	
	INFO_OUT("f_domain: list entries %u", domainlist->len);
	
	return 0;
}

static int
filter_pkt(void *list, struct pkt *pkt)
{
	struct domain_list *domainlist = list;
	struct pkt_nfq *pkt_nfq;
	struct list_item_head *lh;
	struct conn_domain *domain;
	int ret;
	
	pkt_nfq = (struct pkt_nfq*)pkt;
	if (!pkt_nfq->domain)
		return 0;
	list_for_each(lh, &pkt_nfq->domain->list) {
		domain = list_item(lh, struct conn_domain, list);
		ret = domain_list_value_exist(domainlist, domain->name,
		  strlen(domain->name) + 1, domain->name, strlen(domain->name) + 1);
		if (ret)
			return 1;
	}
	return 0;
}

struct filter filter_f_domain = {
	"domain",
	init,
	list_make,
	flist_free,
	list_entry_add,
	list_stat_out,
	filter_pkt
};

