TARGET := libpkt.a
PROTOS := ip icmp tcp udp http dns tls
OBJS := pkt.o pkts_list.o \
	$(patsubst %, pkt_%.o,$(PROTOS))

include ../common.mk

clean-extra:
	rm -f pkts_list.c pkts_types.h $(TARGET)

pkts_list.c: gen_pkts_list.o.sh
	./gen_pkts_list.o.sh $(PROTOS)


