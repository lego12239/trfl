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
#include "pkt/pkt_udp.h"
#include "filters.h"
#include "ipsrv_list.h"
#include "ipprotos.h"


static uint16_t _parse_port(char *str);
static unsigned int _make_value(uint16_t ip, uint8_t *out);


static int
make_value(char **fields, unsigned int n, uint8_t *value,
  unsigned int value_size)
{
	uint16_t port;
	
	port = _parse_port(fields[0]);
	value_size = _make_value(port, value);
	
	return value_size;
}

static int
make_value2(struct pkt *pkt, uint8_t *value, unsigned int value_size)
{
	struct pkt_udp *pkt_udp;
	
	pkt_udp = (struct pkt_udp*)pkt;
	value_size = _make_value(pkt_udp->dport, value);
	return value_size;
}

struct ipproto ipproto_udp = {
	"udp",
	17,
	make_value,
	make_value2
};

static uint16_t
_parse_port(char *str)
{
	unsigned long int n;
	char *e;
	
	n = strtoul(str, &e, 10);
	if ((*e != '\0') || (n > 65535)) {
		ERR_OUT("Wrong port format: %s", str);
		exit(EXIT_FAILURE);
	}
	
	return (uint16_t)n;
}

static unsigned int
_make_value(uint16_t port, uint8_t *out)
{
	unsigned int len = 0;
	uint16_t *i16;
	
	if (!port)
		return len;
	i16 = (uint16_t*)out;
	*i16 = port;
	len += 2;

	return len;
}
