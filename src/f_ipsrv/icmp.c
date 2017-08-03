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
#include "log.h"
#include "pkt/pkt.h"
#include "pkt/pkt_icmp.h"
#include "filters.h"
#include "ipsrv_list.h"
#include "ipprotos.h"


static uint8_t _parse_type(char *str);
static uint8_t _parse_code(char *str);
static unsigned int _make_value(uint8_t type, uint8_t code, uint8_t *out);


static int
make_value(char **fields, unsigned int n, uint8_t *value,
  unsigned int value_size)
{
	uint8_t type = 0;
	uint8_t code = 0;
	
	if (n == 0)
		return 0;
	if (n > 0)
		type = _parse_type(fields[0]);
	if (n > 1)
		code = _parse_code(fields[1]);
	value_size = _make_value(type, code, value);
	
	return value_size;
}

static int
make_value2(struct pkt *pkt, uint8_t *value, unsigned int value_size)
{
	struct pkt_icmp *pkt_icmp;
	
	pkt_icmp = (struct pkt_icmp*)pkt;
	value_size = _make_value(pkt_icmp->type,
	  pkt_icmp->code, value);
	return value_size;
}

struct ipproto ipproto_icmp = {
	"icmp",
	1,
	make_value,
	make_value2
};

static uint8_t
_parse_type(char *str)
{
	unsigned long int n;
	char *e;
	
	n = strtoul(str, &e, 10);
	if ((*e != '\0') || (n > 255)) {
		ERR_OUT("Wrong icmp type format: %s", str);
		exit(EXIT_FAILURE);
	}
	
	return (uint8_t)n;
}

static uint8_t
_parse_code(char *str)
{
	unsigned long int n;
	char *e;
	
	n = strtoul(str, &e, 10);
	if ((*e != '\0') || (n > 255)) {
		ERR_OUT("Wrong icmp code format: %s", str);
		exit(EXIT_FAILURE);
	}
	
	return (uint8_t)n;
}

static unsigned int
_make_value(uint8_t type, uint8_t code, uint8_t *out)
{
	unsigned int len = 0;

	if (!type)
		goto out;
	*out = type;
	len++;
	if (!code)
		goto out;
	*(out + len) = code;
	len++;

out:
	return len;
}
