#!/bin/bash

echo "#include <stdint.h>" > ipprotos.c
echo "#include <stdio.h>" >> ipprotos.c
echo "#include \"pkt/pkt.h\"" >> ipprotos.c
echo "#include \"ipprotos.h\"" >> ipprotos.c
echo >> ipprotos.c
    
for i in $@; do
	echo "extern struct ipproto ipproto_$i;" >> ipprotos.c
done

echo "struct ipproto *ipprotos_list[] = {" >> ipprotos.c
for i in $@; do
	echo "  &ipproto_$i," >> ipprotos.c
done
echo "  NULL" >> ipprotos.c
echo "};" >> ipprotos.c
