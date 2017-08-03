TARGET := libf_ipsrv.a
PROTOS := tcp udp icmp
OBJS := f_ipsrv.o ipsrv_list.o ipprotos.o \
	$(patsubst %, %.o,$(PROTOS))

include ../common.mk

clean-extra:
	rm -f ipprotos.c $(TARGET)

ipprotos.c: gen_ipprotos.o.sh
	./gen_ipprotos.o.sh $(PROTOS)


