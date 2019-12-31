#!/bin/bash

gateway=10.0.0.1
adapter="eth0"
route_bin="/sbin/route"

./talkdesk_ranges.pl -s 'example' | sort -n | while read range ; do
    if [ ${range: -3} != "/32" ] ; then
        $route_bin add -net $range gw $gateway dev $adapter 2>/dev/null
    else
        $route_bin add ${range%/32} gw $gateway dev $adapter 2>/dev/null
    fi
done
