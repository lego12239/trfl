#!/bin/bash

echo "#include <stdint.h>" > filters.c
echo "#include <stdio.h>" >> filters.c
echo "#include \"pkt/pkt.h\"" >> filters.c
echo "#include \"filters.h\"" >> filters.c
echo >> filters.c
    
for i in $@; do
	echo "extern struct filter filter_$i;" >> filters.c
done

echo "struct filter *filters[] = {" >> filters.c
for i in $@; do
	echo "  &filter_$i," >> filters.c
done
echo "  NULL" >> filters.c
echo "};" >> filters.c
