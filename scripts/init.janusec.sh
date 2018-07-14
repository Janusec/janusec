#!/bin/bash
# chkconfig: - 85 15
# description: Janusec Application Gateway


start() {
    cd /usr/local/janusec/
    ./janusec.sh
}

stop() {    
    killall -9 /usr/local/janusec/janusec >/dev/null 2>&1
}

case "$1" in 
    start)
       start
       ;;
    stop)
       stop
       ;;
    restart)
       stop
       start
       ;;
    status)
       ps -ef | grep janusec
       ;;
    *)
       echo "Usage: $0 {start|stop|status|restart}"
       ;;
esac

exit 0

