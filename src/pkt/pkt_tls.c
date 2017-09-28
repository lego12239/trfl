#include <netinet/udp.h>
#include <endian.h>
#include <stdlib.h>
#include <stdint.h>
#include "log.h"
#include "util.h"
#include "pkt.h"
#include "pkt_tls.h"
#include "pkts_hdlrs.h"


struct tlshdr {
	uint8_t type;
	uint8_t version_major;
	uint8_t version_minor;
	uint16_t length;
} __attribute__ ((__packed__));

struct tlsmsghdr {
	uint8_t type;
	uint8_t length[3];
} __attribute__ ((__packed__));


static int free_pkt(struct pkt *pkt);
static int _add_msg(struct pkt_tls *pkt, unsigned char **data, int *size);
static int _add_msg_clientHello_ext(struct tls_msg *msg, unsigned char **data, int *size);
static int _dump_pkt(int outlvl, struct pkt *pkt);


static int
init(void)
{
	INFO_OUT("tls: protocol version <3.1(< TLS 1.0) is not supported!");
	return 0;
}

static int
parse_pkt(struct pkt *pkt_prev, unsigned char *data, int size)
{
	struct list_item_head *lh, *lh1;
	struct tlshdr *tlsh;
	struct tls_ext *ext;
	struct tls_ext_sni_name *sni;
	struct pkt_tls *pkt;
	int len, ret;

	if (sizeof(*tlsh) != 5) {
		ERR_OUT("tls: struct tlshdr size is't equal to 5!");
		return -3;
	}
	/* Is this really a tls packet? */
	if (size < sizeof(*tlsh))
		return 1;
	if (pkt_prev->pkt_type != pkt_type_tcp) {
		ERR_OUT("tls protocol can't be in %s protocol",
		  pkts_list[pkt_prev->pkt_type]->name);
		return -2;
	}
	tlsh = (struct tlshdr*)data;
	len = be16toh(tlsh->length);
	if ((len + sizeof(*tlsh)) != size)
		return 1;
	if (tlsh->version_major != 3) {
		/*
		ERR_OUT("tls: version not equal to 3.x is not supported!");
		return -3;
		*/
		return 3;
	}
	if (tlsh->version_minor < 1) {
		/*
		ERR_OUT("tls: version 3.0 is not supported!");
		return -3;
		*/
		return 3;
	}
	if (tlsh->type != 22)
		return 1;
	
	pkt = malloc(sizeof(*pkt));
	if (!pkt)
		return -1;
	memset(pkt, 0, sizeof(*pkt));
	list_item_head_init(&pkt->list);
	list_add(&pkt->list, &pkt_prev->list);
	
	pkt->pkt_type = pkt_type_tls;
	pkt->pkt_len = size;
	pkt->pkt_raw = data;
	
	pkt->type = tlsh->type;
	pkt->version_major = tlsh->version_major;
	pkt->version_minor = tlsh->version_minor;
	pkt->length = len;
	
	size -= sizeof(*tlsh);
	data += sizeof(*tlsh);
	while ((ret = _add_msg(pkt, &data, &size)) == 0) {
		if (pkt->msgs->type == 1) {
			if (pkt->msgs->clientHello.exts) {
				list_for_each(lh, &pkt->msgs->clientHello.exts->list) {
					ext = list_item(lh, struct tls_ext, list);
					if (ext->type == 0) {
						list_for_each(lh1, &ext->sni.names->list) {
							sni = list_item(lh1, struct tls_ext_sni_name,
							  list);
							if (sni->type == 0) {
								normalize_domain_name(sni->hostname.name);
								ret = pkt_domain_add(pkt_prev,
								  sni->hostname.name,
								  strlen(sni->hostname.name));
								if (ret < 0)
									goto err_free_pkt;
							}
						}
					}
				}
			}
		}
	}
	if (ret != 1)
		goto err_free_pkt;
	
	return 0;

err_free_pkt:
	list_rm(&pkt->list);
	free_pkt((struct pkt*)pkt);
	return ret;
}

static void
_free_pkt_msg_ext_sni_names_cb(struct list_item_head *lh)
{
	struct tls_ext_sni_name *name;
	
	name = list_item(lh, struct tls_ext_sni_name, list);
	switch (name->type) {
	case 0:
		free(name->hostname.name);
		break;
	default:
		break;
	}
	free(name);
}

static void
_free_pkt_msg_ext_cb(struct list_item_head *lh)
{
	struct tls_ext *ext;
	
	ext = list_item(lh, struct tls_ext, list);
	switch (ext->type) {
	case 0:
		if (ext->sni.names)
			list_free(&ext->sni.names->list, _free_pkt_msg_ext_sni_names_cb);
		break;
	default:
		break;
	}
	free(ext);
}

static void
_free_pkt_msg_cb(struct list_item_head *lh)
{
	struct tls_msg *msg;
	
	msg = list_item(lh, struct tls_msg, list);
	switch (msg->type) {
	case 1:
		free(msg->clientHello.sess_id);
		free(msg->clientHello.cipher_suites);
		free(msg->clientHello.comp_methods);
		if (msg->clientHello.exts)
			list_free(&msg->clientHello.exts->list, _free_pkt_msg_ext_cb);
		break;
	default:
		break;
	}
	free(msg);
}

static int
free_pkt(struct pkt *pkt)
{
	struct pkt_tls *pkt_tls;
	
	if (pkt->pkt_type != pkt_type_tls)
		return -2;
	pkt_tls = (struct pkt_tls*)pkt;
	list_free(&pkt_tls->msgs->list, _free_pkt_msg_cb);
	free(pkt_tls);
	return 0;
}

static int _dump_pkt_msg_clientHello(uint32_t id,struct tls_msg *msg);

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
	struct list_item_head *lh;
	struct tls_msg *msg;
	uint32_t id;
	struct pkt_tls *pkt_tls;
	char *str;
	
	if (pkt->pkt_type != pkt_type_tls)
		return -2;
	id = get_pkt_id(pkt);
	pkt_tls = (struct pkt_tls*)pkt;
	
	switch (pkt_tls->type) {
	case 20:
		str = "ChangeCipherSpec";
		break;
	case 21:
		str = "Alert";
		break;
	case 22:
		str = "Handshake";
		break;
	case 23:
		str = "Application";
		break;
	case 24:
		str = "HeartBeat";
		break;
	default:
		str = "UNKNOWN";
		break;
	}
	ANY_OUT(outlvl, "%u: tls: type=%hhu(%s), ver=%hhu.%hhu, length=%hu "
	  "(size - %u)",
	  id, pkt_tls->type, str, pkt_tls->version_major, pkt_tls->version_minor,
	  pkt_tls->length, pkt_tls->pkt_len);
	list_for_each(lh, &pkt_tls->msgs->list) {
		msg = list_item(lh, struct tls_msg, list);
		switch (msg->type) {
		case 0:
			str = "HelloRequest";
			break;
		case 1:
			str = "ClientHello";
			break;
		case 2:
			str = "ServerHello";
			break;
		case 4:
			str = "NewSessionTicket";
			break;
		case 11:
			str = "Certificate";
			break;
		case 12:
			str = "ServerKeyExchange";
			break;
		case 13:
			str = "CertificateRequest";
			break;
		case 14:
			str = "ServerHelloDone";
			break;
		case 15:
			str = "CertificateVerify";
			break;
		case 16:
			str = "ClientKeyExchange";
			break;
		case 20:
			str = "Finished";
			break;
		default:
			str = "UNKNOWN";
			break;
		}
		ANY_OUT(outlvl, "%u: tls: msg_type=%hhu(%s)", id, msg->type, str);
		switch (msg->type) {
		case 1:
			_dump_pkt_msg_clientHello(id, msg);
			break;
		default:
			break;
		}
	}
	return 0;
}

static int
_dump_pkt_msg_clientHello(uint32_t id, struct tls_msg *msg)
{
	struct list_item_head *lh, *lh1;
	struct tls_ext *ext;
	struct tls_ext_sni_name *name;
	char *str;

	DBG_OUT("%u: tls: msg_type=%hhu: ver=%hhu.%hhu", id, msg->type,
	  msg->clientHello.version_major, msg->clientHello.version_minor);
	if (msg->clientHello.exts)
		list_for_each(lh, &msg->clientHello.exts->list) {
			ext = list_item(lh, struct tls_ext, list);
			switch (ext->type) {
			case 0:
				str = "sni";
				break;
			case 1:
				str = "max_fragment_length";
				break;
			case 2:
				str = "client_certificate_url";
				break;
			case 3:
				str = "trusted_ca_keys";
				break;
			case 4:
				str = "truncated_hmac";
				break;
			case 5:
				str = "status_request";
				break;
			case 6:
				str = "user_mapping";
				break;
			case 7:
				str = "client_authz";
				break;
			case 8:
				str = "server_authz";
				break;
			case 9:
				str = "cert_type";
				break;
			case 10:
				str = "elliptic_curves";
				break;
			case 11:
				str = "ec_point_formats";
				break;
			case 12:
				str = "srp";
				break;
			case 13:
				str = "signature_algorithms";
				break;
			case 14:
				str = "use_srtp";
				break;
			case 15:
				str = "heartbeat";
				break;
			case 16:
				str = "application_layer_protocol_negotiation";
				break;
			case 17:
				str = "status_request_v2";
				break;
			case 18:
				str = "signed_certificate_timestamp";
				break;
			case 19:
				str = "client_certificate_type";
				break;
			case 20:
				str = "server_certificate_type";
				break;
			case 21:
				str = "padding";
				break;
			case 22:
				str = "encrypt_then_mac";
				break;
			case 23:
				str = "extended_master_secret";
				break;
			case 24:
				str = "token_binding";
				break;
			case 25:
				str = "cached_info";
				break;
			case 35:
				str = "SessionTicket TLS";
				break;
			case 13172:
				str = "next_protocol_negotiation";
				break;
			case 65281:
				str = "renegotiation_info";
				break;
			default:
				str = "UNKNOWN";
				break;
			}
			DBG_OUT("%u: tls: msg_type=%hhu: ext_type=%hu(%s)", id, msg->type,
			  ext->type, str);
			switch (ext->type) {
			case 0:
				if (!ext->sni.names)
					break;
				list_for_each(lh1, &ext->sni.names->list) {
					name = list_item(lh1, struct tls_ext_sni_name, list);
					switch (name->type) {
					case 0:
						DBG_OUT("%u: tls: msg_type=%hhu: ext_type=%hu: "
						  "hostname=%s", id, msg->type, ext->type,
						  name->hostname.name);
						break;
					default:
						break;
					}
				}
				break;
			default:
				break;
			}
		}
	return 0;
}

struct pkt_hdlrs pkt_hdlrs_tls = {
	"tls",
	0,
	init,
	parse_pkt,
	free_pkt,
	dump_pkt,
	errout_pkt
};

static int _add_msg_clientHello(struct tls_msg *msg, unsigned char *data, int size);

static int
_add_msg(struct pkt_tls *pkt, unsigned char **data, int *size)
{
	struct tls_msg *tlsmsg;
	struct tlsmsghdr *tlsmsgh;
	uint32_t len, ret;
	
	if (*size == 0)
		return 1;
	
	tlsmsgh = (struct tlsmsghdr*)(*data);
	len = (tlsmsgh->length[0] << 16) | (tlsmsgh->length[1] << 8) |
	  tlsmsgh->length[2];
	if (*size < (len + sizeof(*tlsmsgh)))
		return -3;
	
	tlsmsg = malloc(sizeof(*tlsmsg));
	if (!tlsmsg)
		return -1;
	memset(tlsmsg, 0, sizeof(*tlsmsg));
	list_item_head_init(&tlsmsg->list);
	if (pkt->msgs)
		list_add_before(&tlsmsg->list, &pkt->msgs->list);
	pkt->msgs = tlsmsg;

	tlsmsg->type = tlsmsgh->type;
	tlsmsg->length = len;
	
	switch (tlsmsgh->type) {
	case 1:
		ret = _add_msg_clientHello(tlsmsg, *data + sizeof(*tlsmsgh), len);
		break;
	default:
		ret = 0;
		break;
	}

	*size -= len + sizeof(*tlsmsgh);
	*data += len + sizeof(*tlsmsgh);

	return ret;
}

static int
_add_msg_clientHello(struct tls_msg *msg, unsigned char *data, int size)
{
	int len, ret;
	
	if (size < 34)
		return 2;
	msg->clientHello.version_major = *data;
	data++;
	msg->clientHello.version_minor = *data;
	data++;
	/* random */
	data += 32;
	size -= 34;
	/* session id */
	len = *data;
	if (size < (1 + len))
		return 2;
	msg->clientHello.sess_id_len = len;
	data += 1 + len;
	size -= 1 + len;
	/* cipher suites */
	len = be16toh(*(uint16_t*)data);
	if (size < (2 + len))
		return 2;
	msg->clientHello.cipher_suites_len = len;
	data += 2 + len;
	size -= 2 + len;
	/* compression methods */
	len = *data;
	if (size < (1 + len))
		return 2;
	msg->clientHello.comp_methods_len = len;
	data += 1 + len;
	size -= 1 + len;
	/* extensions */
	len = be16toh(*(uint16_t*)data);
	if (size < (2 + len))
		return 2;
	msg->clientHello.exts_len = len;
	data += 2;
	size = len;
	
	while ((ret = _add_msg_clientHello_ext(msg, &data, &size)) == 0);
	if (ret != 1)
		return ret;
	
	return 0;
}

static int _add_msg_clientHello_ext_sni(struct tls_ext *ext, unsigned char *data, int size);

static int
_add_msg_clientHello_ext(struct tls_msg *msg, unsigned char **data, int *size)
{
	struct tls_ext *ext;
	uint32_t len, ret;
	
	if (*size == 0)
		return 1;
	
	ext = malloc(sizeof(*ext));
	if (!ext)
		return -1;
	memset(ext, 0, sizeof(*ext));
	list_item_head_init(&ext->list);
	if (msg->clientHello.exts)
		list_add_before(&ext->list, &msg->clientHello.exts->list);
	msg->clientHello.exts = ext;
	
	if (*size < 4)
		return 2;
	len = be16toh(*(uint16_t*)*data);
	ext->type = len;
	*data += 2;
	*size -= 2;
	
	len = be16toh(*(uint16_t*)*data);
	if (*size < (2 + len))
		return 2;
	ext->length = len;
	*data += 2;
	*size -= 2;
	
	switch (ext->type) {
	case 0:
		ret = _add_msg_clientHello_ext_sni(ext, *data, len);
		break;
	default:
		ret = 0;
		break;
	}

	*size -= len;
	*data += len;

	return ret;
}

static int _add_msg_clientHello_ext_sni_name(struct tls_ext *ext, unsigned char **data, int *size);

static int
_add_msg_clientHello_ext_sni(struct tls_ext *ext, unsigned char *data,
  int size)
{
	int len, ret;
	
	if (size < 5)
		return 2;
	len = be16toh(*(uint16_t*)data);
	data += 2;
	size -= 2;
	
	if (size != len)
		return 2;
	
	while ((ret = _add_msg_clientHello_ext_sni_name(ext, &data, &size)) == 0);
	if (ret != 1)
		return ret;

	return 0;
}

static int
_add_msg_clientHello_ext_sni_name(struct tls_ext *ext, unsigned char **data,
  int *size)
{
	struct tls_ext_sni_name *name;
	uint32_t len;
	
	if (*size == 0)
		return 1;
	
	if (*size < 3)
		return 2;
	name = malloc(sizeof(*name));
	if (!name)
		return -1;
	memset(name, 0, sizeof(*name));
	list_item_head_init(&name->list);
	if (ext->sni.names)
		list_add_before(&name->list, &ext->sni.names->list);
	ext->sni.names = name;

	name->type = **data;
	*data += 1;
	*size -= 1;
	
	switch (name->type) {
	case 0:
		len = be16toh(*(uint16_t*)*data);
		if (*size < (2 + len))
			return 2;
		*data += 2;
		*size -= 2;
		name->hostname.name = strndup((char*)*data, len);
		if (!name->hostname.name)
			return -1;
		*data += len;
		*size -= len;
		break;
	default:
		break;
	}
	
	return 0;
}
