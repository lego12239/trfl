#ifndef __PKT_TLS_H__
#define __PKT_TLS_H__

#include "list.h"

struct tls_ext_sni_name {
	struct list_item_head list;
	uint8_t type;
	union {
		struct {
			char *name;
		} hostname;
	};
};

struct tls_ext {
	struct list_item_head list;
	uint16_t type;
	uint16_t length;
	union {
		struct {
			struct tls_ext_sni_name *names;
		} sni;
	};
};

struct tls_msg {
	struct list_item_head list;
	uint8_t type;
	uint32_t length;
	union {
		struct {
			uint8_t version_major;
			uint8_t version_minor;
			uint8_t sess_id_len;
			uint8_t *sess_id;
			uint16_t cipher_suites_len;
			uint16_t *cipher_suites;
			uint8_t comp_methods_len;
			uint8_t *comp_methods;
			uint16_t exts_len;
			struct tls_ext *exts;
		} clientHello;
	};
};

struct pkt_tls {
	PKT_HEAD
	uint8_t type;
	uint8_t version_major;
	uint8_t version_minor;
	uint16_t length;
	struct tls_msg *msgs;
};

#endif  /* __PKT_TLS_H__ */
