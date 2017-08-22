#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

PID_SELF=$$
PIDS=$(pgrep $(basename $0))
PIDS=$(echo "$PIDS" | grep -v $PID_SELF || true)
[[ $PIDS != "" ]] && exit

DIR=${0%/*}

[[ $DIR != $0 ]] && cd $DIR

while true; do
	ERRMSG=`./rknr_get.pl -o tf_list -r req.xml -s req.xml.sig conf 2>&1`
	[[ $? -eq 0 ]] && break
done

kill -USR1 `cat /var/run/trfl.pid`
