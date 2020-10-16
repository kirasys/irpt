#!/bin/bash

if [ "$#" -lt 2 ]; then
	echo "Usage: $0 src dst"
	exit 1
fi

scp -P 2222 \
	-i ~/.ssh/id_rsa \
	$1 kirasys@localhost:$2

