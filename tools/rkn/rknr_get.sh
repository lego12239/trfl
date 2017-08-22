#!/bin/bash

PID_SELF=$$
PIDS=$(pgrep $(basename $0))
PIDS=$(echo "$PIDS" | grep -v $PID_SELF)
[[ $PIDS != "" ]] && exit

DIR=${0%/*}

[[ $DIR != $0 ]] && cd $DIR

false
while [[ $? -ne 0 ]]; do
	ERRMSG=`./rknr_get.pl -o tf_list -r req.xml -s req.xml.sig conf 2>&1`
done

kill -USR1 `cat /var/run/trfl.pid`
