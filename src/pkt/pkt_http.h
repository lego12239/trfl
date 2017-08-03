#ifndef __PKT_HTTP_H__
#define __PKT_HTTP_H__

#include "list.h"

struct http_header {
	struct list_item_head list;
	char *name;
	char *value;
};

struct pkt_http {
	PKT_HEAD
	char *method;
	char *target;
	char *version;
	struct http_header *headers;
};

#endif  /* __PKT_HTTP_H__ */
