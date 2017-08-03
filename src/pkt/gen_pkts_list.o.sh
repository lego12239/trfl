#!/bin/bash

echo "#include <stdint.h>" > pkts_list.c
echo "#include <stdio.h>" >> pkts_list.c
echo "#include \"pkt.h\"" >> pkts_list.c
echo "#include \"pkts_hdlrs.h\"" >> pkts_list.c
echo >> pkts_list.c

echo "extern struct pkt_hdlrs pkt_hdlrs_nfq;" >> pkts_list.c
for i in $@; do
	echo "extern struct pkt_hdlrs pkt_hdlrs_$i;" >> pkts_list.c
done

echo "struct pkt_hdlrs *pkts_list[] = {" >> pkts_list.c
echo "  &pkt_hdlrs_nfq," >> pkts_list.c
for i in $@; do
	echo "  &pkt_hdlrs_$i," >> pkts_list.c
done
echo "  NULL" >> pkts_list.c
echo "};" >> pkts_list.c


echo "#ifndef __PKTS_TYPES_H__" > pkts_types.h
echo "#define __PKTS_TYPES_H__" >> pkts_types.h
echo "enum pkt_type {" >> pkts_types.h
echo "  pkt_type_nfq," >> pkts_types.h
for i in $@; do
	echo "  pkt_type_$i," >> pkts_types.h
done
   
echo "  pkt_type__" >> pkts_types.h
echo "};" >> pkts_types.h
echo "#endif  /* __PKTS_TYPES_H__ */" >> pkts_types.h
