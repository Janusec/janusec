#!/bin/bash
ulimit -n 1024000
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=1024000
log=/var/log/janusec.log
if [ -f ${log} ]; then
    bak_log="/var/log/janusec.log."$(date '+%Y%m%d%H%M%S')
    mv -f ${log} ${bak_log}
fi
cd /usr/local/janusec/
exec &>>$log
echo $(date '+%Y/%m/%d %H:%M:%S')" Starting..."
( exec /usr/local/janusec/janusec &>>$log ) &
exit 0
