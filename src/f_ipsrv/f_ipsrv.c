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
#include "main.h"
#include "log.h"
#include "pkt/pkt.h"
#include "pkt/pkt_ip.h"
#include "filters.h"
#include "ipsrv_list.h"
#include "ipprotos.h"


static struct ipproto *ipprotos[256];


static int _parse_ip(char *str, uint32_t *addr, uint8_t *mask);
static uint8_t _parse_proto(char *str);
static unsigned int _make_value(uint32_t ip, uint8_t proto, uint8_t *out);


static int
init(void)
{
	int i;
	
	for(i = 0; ipprotos_list[i]; i++)
		ipprotos[ipprotos_list[i]->idx] = ipprotos_list[i];
	
	return 0;
}

static int
list_make(void **list)
{
	int i;
	struct ipsrv_list **iplist;
	
	iplist = malloc(sizeof(*iplist) * 32);
	if (!iplist) {
		ERR_OUT("ip-srv: can't allocate memory for ip list");
		return -1;
	}
		
	for(i = 0; i < 32; i++) {
		iplist[i] = ipsrv_list_make();
		if (!iplist[i]) {
			ERR_OUT("ip-srv: can't allocate memory for ip list");
			free(iplist);
			return -1;
		}
	}
	
	*list = iplist;
	
	return 0;
}

static int
flist_free(void *list)
{
	int i;
	struct ipsrv_list **iplist = list;
	
	for(i = 0; i < 32; i++)
		if (ipsrv_list_free(iplist[i]) != 0)
			ERR_OUT("ip-srv: error on list free");
	free(iplist);
	
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
 *  -1 - error occured
 */
static int
list_entry_add(void *list, char **fields, unsigned int n)
{
	struct ipsrv_list **iplist = list;
	uint32_t ip;
	uint8_t proto = 0, mask;
	uint8_t value[IPSRVLIST_VALUE_SIZE];
	unsigned int value_size;
	int ret;
	
	if (strcmp(fields[0], "ip-srv") != 0)
		return 1;
	ret = _parse_ip(fields[1], &ip, &mask);
	if (ret < 0)
		return ret;
	if (n > 2)
		proto = _parse_proto(fields[2]);
	ip = (ip >> (32 - mask)) << (32 - mask);
	value_size = _make_value(ip, proto, value);
	if (n > 3) {
		if (ipprotos[proto]) {
			ret = ipprotos[proto]->make_value(&fields[3], n - 3,
			  value + value_size, IPSRVLIST_VALUE_SIZE - value_size);
			if (ret < 0) {
				ERR_OUT("ip-srv: protocol %d module making value error",
				  proto);
				return -1;
			}
			value_size += ret;
		} else {
			ERR_OUT("ip-srv: no module to process '%s:%s:%s:...' entry. "
			  "Fallback to filtering by ip & proto.", fields[0], fields[1],
			  fields[2]);
		}
		
	}
	if (!ipsrv_list_add(iplist[mask - 1], value, value_size, value, 4)) {
		ERR_OUT("ip-srv: ip-srv add error: %u:%hhu:...: no memory", ip, proto);
		return -1;
	} else {
		DBG_OUT("ip-srv: add ip-srv %u:%hhu:...", ip, proto);
	}
	
	return 0;
}

static int
list_stat_out(void *list)
{
	struct ipsrv_list **iplist = list;
	int i, is_empty = 1;
	
	for(i = 0; i < 32; i++)
		if (iplist[i]->len > 0) {
			INFO_OUT("f_ipsrv: /%u list entries %u", i + 1, iplist[i]->len);
			is_empty = 0;
		}
	/* show something to understand that filter works */
	if (is_empty)
		INFO_OUT("f_ipsrv: list entries 0");
	
	return 0;
}

static int
filter_pkt(void *list, struct pkt *pkt)
{
	struct ipsrv_list **iplist = list;
	uint8_t value[IPSRVLIST_VALUE_SIZE];
	uint32_t addr;
	unsigned int value_size;
	struct pkt_ip *pkt_ip;
	//unsigned int pkt_id;
	int ret, i;
	
	//pkt_id = get_pkt_id(pkt);
	pkt = get_next_pkt(pkt);
	if (!pkt)
		return 0;
	if (pkt->pkt_type != pkt_type_ip)
		return 0;
	pkt_ip = (struct pkt_ip*)pkt;
	
	for(i = 0; i < 32; i++) {
		if (iplist[i]->len == 0)
			continue;
		addr = (pkt_ip->daddr >> (32 - (i + 1))) << (32 - (i + 1));
		value_size = _make_value(addr, pkt_ip->proto, value);
		pkt = get_next_pkt((struct pkt*)pkt_ip);
		if ((pkt) && (ipprotos[pkt_ip->proto])) {
			ret = ipprotos[pkt_ip->proto]->make_value2(pkt,
			  value + value_size, IPSRVLIST_VALUE_SIZE - value_size);
			if (ret < 0) {
				ERR_OUT("ip-srv: protocol %d module making value2 error",
				  pkt_ip->proto);
				return 0;
			}
			value_size +=ret;
		}
		ret = ipsrv_list_value_exist(iplist[i], value, value_size, value, 4);
		if (ret)
			return ret;
	}
	
	return 0;
}

struct filter filter_f_ipsrv = {
	"ip-srv",
	init,
	list_make,
	flist_free,
	list_entry_add,
	list_stat_out,
	filter_pkt
};

static int
_parse_ip(char *str, uint32_t *addr, uint8_t *mask)
{
	unsigned long int n;
	char *s = str, *e;
	
	*addr = 0;
	n = strtoul(s, &e, 10);
	if ((*e != '.') || (n > 255)) {
		ERR_OUT("ip-srv: wrong ip prefix format: %s", str);
		return -2;
	}
	*addr |= (n & 0xff) << 24;

	s = e + 1;
	n = strtoul(s, &e, 10);
	if ((*e != '.') || (n > 255)) {
		ERR_OUT("ip-srv: wrong ip prefix format: %s", str);
		return -2;
	}
	*addr |= (n & 0xff) << 16;
	
	s = e + 1;
	n = strtoul(s, &e, 10);
	if ((*e != '.') || (n > 255)) {
		ERR_OUT("ip-srv: wrong ip prefix format: %s", str);
		return -2;
	}
	*addr |= (n & 0xff) << 8;
	
	s = e + 1;
	n = strtoul(s, &e, 10);
	if (((*e != '/') && (*e != '\0')) || (n > 255)) {
		ERR_OUT("ip-srv: wrong ip prefix format: %s", str);
		return -2;
	}
	*addr |= (n & 0xff);
	
	*mask = 32;
	if (*e == '/') {
		s = e + 1;
		n = strtoul(s, &e, 10);
		if ((*e != '\0') || (n > 32) || (n < 1)) {
			ERR_OUT("ip-srv: wrong ip prefix format: %s", str);
			return -2;
		}
		*mask = n;
	}
	return 0;
}

static uint8_t
_parse_proto(char *str)
{
	unsigned long int n;
	char *e;
	
	n = strtoul(str, &e, 10);
	if ((*e != '\0') || (n > 255)) {
		ERR_OUT("ip-srv: wrong proto format: %s", str);
		exit(EXIT_FAILURE);
	}
	
	return (uint8_t)n;
}

static unsigned int
_make_value(uint32_t ip, uint8_t proto, uint8_t *out)
{
	unsigned int len = 0;
	uint32_t *i32;
	
	i32 = (uint32_t*)out;
	*i32 = ip;
	len = 4;
	if (!proto)
		goto out;
	*(out + len) = proto;
	len++;

out:
	return len;
}
