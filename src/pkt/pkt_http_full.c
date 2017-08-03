#include <netinet/udp.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "log.h"
#include "util.h"
#include "pkt.h"
#include "pkt_http.h"
#include "pkt_tcp.h"
#include "pkts_hdlrs.h"


struct http_token_ctx {
	char *buf;
	int buf_size;
	char *t_start;
	int t_len;
};


static int free_pkt(struct pkt *pkt);
static int _parse_start_line(struct pkt_http *pkt, char **buf, int *size);
static int _parse_header(struct pkt_http *pkt, char **buf, int *size);
static struct http_header* _http_header_add(struct pkt_http *pkt, char *name, int name_len, char *value, int value_len);
static unsigned int _get_token(char *str, unsigned int n, char **end);
static void _lc(char *name);
static int _dump_pkt(int outlvl, struct pkt *pkt);


static int
init(void)
{
	return 0;
}

static int
parse_pkt(struct pkt *pkt_prev, unsigned char *data, int size)
{
	char *uri = NULL, *ptr;
	struct pkt_http *pkt;
	int ret, len, id, is_host_found = 0;

	/* get tcp port number */
	if (pkt_prev->pkt_type != pkt_type_tcp) {
		ERR_OUT("http protocol can't be in %s protocol",
		  pkts_list[pkt_prev->pkt_type]->name);
		return -2;
	}
	
	pkt = malloc(sizeof(*pkt));
	if (!pkt)
		return -1;
	memset(pkt, 0, sizeof(*pkt));
	list_item_head_init(&pkt->list);
	list_add(&pkt->list, &pkt_prev->list);
	
	pkt->pkt_type = pkt_type_http;
	pkt->pkt_len = size;
	pkt->pkt_raw = data;
	
	ret = _parse_start_line(pkt, (char**)&data, &size);
	if (ret != 0)
		goto err_free_pkt;
	
	while ((ret = _parse_header(pkt, (char**)&data, &size)) == 0) {
		if (strcmp(pkt->headers->name, "host") == 0) {
			ret = normalize_and_check_domain_name(pkt->headers->value);
			if (ret < 0)
				goto err_free_pkt;
			len = snprintf(NULL, 0, "http://%s%s", pkt->headers->value,
			  pkt->target);
			ret = -1;
			uri = malloc(len + 1);
			if (!uri)
				goto err_free_pkt;
			snprintf(uri, len + 1, "http://%s%s", pkt->headers->value,
			  pkt->target);
			ret = pkt_uri_add(pkt_prev, uri);
			if (ret < 0) {
				free(uri);
				goto err_free_pkt;
			}
			len = strlen(pkt->headers->value);
			ptr = strrchr(pkt->headers->value, ':');
			if (ptr)
				len = ptr - pkt->headers->value;
			ret = pkt_domain_add(pkt_prev, pkt->headers->value, len);
			if (ret < 0)
				goto err_free_pkt;
			is_host_found = 1;
			/* do process other headers */
			ret = 2;
			break;
		}
	}
	if (ret != 2) {
		id = get_pkt_id(pkt_prev);
		PKT_ERROUT((struct pkt*)pkt, "%u: http: headers parse error", id);
		/* try to process wrong request too */
		if (!is_host_found)
			goto err_free_pkt;
	}
	if (!is_host_found) {
		id = get_pkt_id(pkt_prev);
		PKT_ERROUT((struct pkt*)pkt, "%u: http: can't found host header", id);
	}
	
	return 0;

err_free_pkt:
	if (ret < 0) {
		id = get_pkt_id(pkt_prev);
		PKT_ERROUT((struct pkt*)pkt, "%u: http parse error %d", id, ret);
	}
	list_rm(&pkt->list);
	free_pkt((struct pkt*)pkt);
	return ret;
}

static void
_free_pkt_header_cb(struct list_item_head *lh)
{
	struct http_header *hdr;
	
	hdr = list_item(lh, struct http_header, list);
	free(hdr->name);
	free(hdr->value);
	free(hdr);
}

static int
free_pkt(struct pkt *pkt)
{
	struct pkt_http *pkt_http;
	
	if (pkt->pkt_type != pkt_type_http)
		return -2;
	pkt_http = (struct pkt_http*)pkt;
	free(pkt_http->method);
	free(pkt_http->target);
	free(pkt_http->version);
	if (pkt_http->headers)
		list_free(&pkt_http->headers->list, _free_pkt_header_cb);
	free(pkt_http);
	return 0;
}

static int
dump_pkt(struct pkt *pkt)
{
	return _dump_pkt(OUTLVL_DBG, pkt);
}

static int
errout_pkt(struct pkt *pkt)
{
	return _dump_pkt(OUTLVL_ERR, pkt);
}

static int
_dump_pkt(int outlvl, struct pkt *pkt)
{
	uint32_t id;
	struct list_item_head *lh;
	struct http_header *header;
	struct pkt_http *pkt_http;
	
	if (pkt->pkt_type != pkt_type_http)
		return -2;
	id = get_pkt_id(pkt);
	pkt_http = (struct pkt_http*)pkt;
	
	ANY_OUT(outlvl, "%u: http: %s %s %s, size = %d", id, pkt_http->method,
	  pkt_http->target, pkt_http->version, pkt_http->pkt_len);
	list_for_each(lh, &pkt_http->headers->list) {
		header = list_item(lh, struct http_header, list);
		ANY_OUT(outlvl, "%u: http: %s: %s", id, header->name, header->value);
	}
	ANY_OUT(outlvl, "%u: http: PACKET DUMP: %.*s", pkt_http->pkt_len,
	  pkt_http->pkt_raw);
	return 0;
}

struct pkt_hdlrs pkt_hdlrs_http = {
	"http",
	0,
	init,
	parse_pkt,
	free_pkt,
	dump_pkt,
	errout_pkt
};

static int
_parse_start_line(struct pkt_http *pkt, char **buf, int *size)
{
	int ret;
	char *s, *e, *ee;

	s = *buf;	
	/* get method */
	ret = _get_token(s, *size, &e);
	if (ret != 3)
		return 1;
	*size -= e - s;
	if ((e - s) > 7)
		return 1;
	pkt->method = strndup(s, e - s);
	if (!pkt->method)
		return -1;
	
	s = e;
	ret = _get_token(e, *size, &e);
	if (ret != 1)
		return 1;
	*size -= e - s;
	
	/* get target */
	s = e;
	ret = _get_token(e, *size, &e);
	if (ret != 3)
		return 1;
	*size -= e - s;
	ee = e;
	while ((ee != s) && (*(ee - 1) == '/'))
		ee--;
	pkt->target = strndup(s, ee - s);
	if (!pkt->target)
		return -1;
	
	s = e;
	ret = _get_token(e, *size, &e);
	if (ret != 1)
		return 1;
	*size -= e - s;
	
	/* get version */
	s = e;
	ret = _get_token(e, *size, &e);
	if (ret != 3)
		return 1;
	*size -= e - s;
	if ((e - s) != 8)
		return 1;
	if (strncmp("HTTP/1.1", s, 8) != 0)
		return 1;
	pkt->version = strndup(s, e - s);
	if (!pkt->version)
		return -1;

	s = e;
	ret = _get_token(e, *size, &e);
	if (ret != 2)
		return 1;
	*size -= e - s;

	*buf = e;
	return 0;	
}

static int
_parse_header(struct pkt_http *pkt, char **buf, int *size)
{
	int ret;
	char *s, *ss, *e;
	struct http_header *hdr;

	s = *buf;
	/* get header name */
	ret = _get_token(s, *size, &e);
	if ((ret == 2) || (ret == 0))
		return 2;
	if (ret != 3)
		return 1;
	*size -= e - s;
	if (*(e - 1) != ':')
		return 1;
	hdr = _http_header_add(pkt, s, e - s - 1, NULL, 0);
	if (!hdr)
		return -1;
	_lc(hdr->name);
	
	s = e;
	ret = _get_token(e, *size, &e);
	if (ret != 1)
		return 1;
	*size -= e - s;
	
	/* get header value */
	s = ss = e;
	while (((ret = _get_token(e, *size, &e)) == 1) ||
	       (ret == 3)) {
		*size -= e - s;
		s = e;
	}
	if (ret == 0)
		return 1;
	*size -= e - s;
	hdr->value = strndup(ss, s - ss);
	if (!hdr->value)
		return -1;

	*buf = e;
	return 0;	
}

static struct http_header*
_http_header_add(struct pkt_http *pkt, char *name, int name_len, char *value,
  int value_len)
{
	struct http_header *header;
	
	header = malloc(sizeof(*header));
	if (!header)
		return NULL;
	memset(header, 0, sizeof(*header));
	list_item_head_init(&header->list);
	
	if (name) {
		header->name = strndup(name, name_len);
		if (!header->name)
			goto err_cleanup;
	}
	if (value) {
		header->value = strndup(value, value_len);
		if (!header->value)
			goto err_cleanup;
	}
	if (pkt->headers)
		list_add_before(&header->list, &pkt->headers->list);
	pkt->headers = header;

	return header;
	
err_cleanup:
	free(header->name);
	free(header->value);
	free(header);
	return NULL;
}

/*
 * Find a token end and return it length.
 * str - a buffer with tokens
 * n - a buffer size
 * end - a pointer to place address of character after last character of token
 *
 * return:
 *   0 - token not found
 *   1 - token is space
 *   2 - token is new line
 *   3 - token is not space
 */
static unsigned int
_get_token(char *str, unsigned int n, char **end)
{
	unsigned int i = 0, state = 0, ret = 0;
	
	for(i = 0; (state < 2) && (i < n); i++)
		switch (state) {
		case 0:
			state = 1;
			if ((str[i] == ' ') || (str[i] == '\t'))
				ret = 1;
			else if ((str[i] == '\r') || (str[i] == '\n'))
				ret = 2;
			else
				ret = 3;
			break;
		case 1:
			switch (ret) {
			case 1:
				if ((str[i] != ' ') && (str[i] != '\t')) {
					state = 2;
					i--;
				}
				break;
			case 2:
				state = 2;
				if ((str[i] != '\n') && (str[i] != '\r'))
					i--;
				break;
			case 3:
				if ((str[i] == ' ') || (str[i] == '\t')) {
					state = 2;
					i--;
				} else if (str[i] == '\n') {
					state = 2;
					i--;
					if (str[i] == '\r')
						i--;
					ret = 3;
				}
				break;
			}
			break;
		}
	
	*end = str + i;
	
	return ret;
}

static void
_lc(char *name)
{
	while (*name) {
		if ((*name >= 65) && (*name <= 90))
			*name = *name + 32;
		name++;
	}
}

