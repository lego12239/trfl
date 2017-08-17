#!/bin/bash

pgrep rknr_get.pl && exit

DIR=${0%/*}

[[ $DIR != $0 ]] && cd $DIR

false
while [[ $? -ne 0 ]]; do
	ERRMSG=`./rknr_get.pl -o tf_list -r req.xml -s req.xml.sig conf 2>&1`
done

kill -USR1 `cat /var/run/trfl.pid`
