#!/bin/bash
### BEGIN INIT INFO
# Provides:          rum
# Required-Start:    $network $local_fs
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: One process tcp redirector
# Description:	rum is one process tcp redirector with socket file support and more listen ports/socket files, using libevent. 
#		It's also mysql reverse proxy for more mysql servers (the key to select destination server is username send 
#		by client) using cdb database.

### END INIT INFO

# Author: Tomas Corej <tomas.corej@websupport.sk>
# Author: Matus Bursa <matus.bursa@eset.sk>

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC=rum             # Introduce a short description here
NAME=rum             # Introduce the short server's name here
DAEMON=/usr/sbin/rum # Introduce the server's location here
DAEMON_ARGS=""             # Arguments to run the daemon with
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME

# Exit if the package is not installed
[ -x $DAEMON ] || exit 0

# Read configuration variable file if it is present
# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started

	[ -f /etc/default/$NAME ] && INSTANCES=`grep -v ^# /etc/default/$NAME`
        grep -v ^# /etc/default/$NAME | \
	while read instance
	do
		export PIDFILE=/var/run/${instance%%:*}.pid
		DAEMON_ARGS=${instance#*:}
			start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --test > /dev/null \
				||  log_warning_msg "daemon was already running"
			start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- \
				$DAEMON_ARGS \
				|| log_failure_msg "daemon could not be started"
		# Add code here, if necessary, that waits for the process to be ready
		# to handle requests from services started subsequently which depend
		# on this one.  As a last resort, sleep for some time.
	done
}

#
# Function that stops the daemon/service
#
do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
        grep -v ^# /etc/default/$NAME | \
	while read instance
        do
		PIDFILE=/var/run/${instance%%:*}.pid
		DAEMON_ARGS=${instance#*:}
		start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name $NAME
		# Wait for children to finish too if this is a daemon that forks
		# and if the daemon is only ever run from this initscript.
		# If the above conditions are not satisfied then add some other code
		# that waits for the process to drop all resources that could be
		# needed by services started subsequently.  A last resort is to
		# sleep for some time.
		start-stop-daemon --stop --quiet --oknodo --pidfile $PIDFILE --retry=0/30/KILL/5 --exec $DAEMON
		# Many daemons don't delete their pidfiles when they exit.
		[ -f $PIDFILE ] && rm -f $PIDFILE
	done
	unset IFS
	return 0
}

#
# Function that sends a SIGHUP to the daemon/service
#
do_reload() {
	#
	# If the daemon can reload its configuration without
	# restarting (for example, when it is sent a SIGHUP),
	# then implement that here.
	#
	grep -v ^# /etc/default/$NAME | \
        while read instance
	do
		export PIDFILE=/var/run/${instance%%:*}.pid
		PROCESS=$(cat $PIDFILE 2> /dev/null)
		PROCESS_NAME=$(ps -p $PROCESS -o comm= 2> /dev/null)	

		PROCESS_ARGS=$(ps -p $PROCESS -o args= 2> /dev/null)
		DAEMON_ARGS=${instance#*:}
	
		if [ "rum" != "$PROCESS_NAME" ]; then
			log_daemon_msg "Reloading $DESC" "${instance%%:*}"
			# TCP only for now
			if [[ $DAEMON_ARGS =~ ^.*\-\s\ +tcp:([0-9]{1,3}.){3}[0-9]{1,3}:([0-9]+)\ .+$ ]]; then
				PORT=${BASH_REMATCH[2]}
				PID=`lsof -i4:$PORT -t`
				if [[ $PID =~ ^([0-9]+)$ ]]; then
					PID=${BASH_REMATCH[1]}
					kill $PID
					sleep 3
				fi	
			unset PORT
			unset PID
			fi
			# start not running process
			start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- $DAEMON_ARGS 
			continue
		elif [ "$DAEMON $DAEMON_ARGS" != "$PROCESS_ARGS" ]; then
			log_daemon_msg "Reloading $DESC" "${instance%%:*}"
				# stop running process with bad arguments
			start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name $NAME
			start-stop-daemon --stop --quiet --oknodo --pidfile $PIDFILE --retry=0/30/KILL/5 --exec $DAEMON
			[ -f $PIDFILE ] && rm -f $PIDFILE
			
			# start process
			start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- $DAEMON_ARGS 
		fi
	done
	return 0
}

do_status() {
	grep -v ^# /etc/default/$NAME | \
	( retn=0 ;
        while read instance
        do
		PIDFILE=/var/run/${instance%%:*}.pid
                PROCESS=$(cat $PIDFILE 2> /dev/null)
                PROCESS_NAME=$(ps -p $PROCESS -o comm= 2> /dev/null)

                PROCESS_ARGS=$(ps -p $PROCESS -o args= 2> /dev/null)
                DAEMON_ARGS="${instance#*:} -p ${PIDFILE}"

		if [ "rum" != "$PROCESS_NAME" ]; then
			echo ${instance%%:*} is not running
			retn=1
		elif [ "$DAEMON $DAEMON_ARGS" != "$PROCESS_ARGS" ]; then
			echo ${instance%%:*} is running with bad arguments
			retn=2
		else
			echo ${instance%%:*} is running
		fi
	done
	return $retn )
}

case "$1" in
  start)
    [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC " "$NAME"
    do_start
    case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
  ;;
  stop)
	[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
	do_stop
	case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  status)
#       status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
	do_status
	exit $?
       ;;
  reload|force-reload)
	#
	# If do_reload() is not implemented then leave this commented out
	# and leave 'force-reload' as an alias for 'restart'.
	#
	#log_daemon_msg "Reloading $DESC" "$NAME"
	do_reload
	#log_end_msg $?
	;;
  restart|force-reload)
	#
	# If the "reload" option is implemented then remove the
	# 'force-reload' alias
	#
	log_daemon_msg "Restarting $DESC" "$NAME"
	do_stop
	case "$?" in
	  0|1)
		do_start
		case "$?" in
			0) log_end_msg 0 ;;
			1) log_end_msg 1 ;; # Old process is still running
			*) log_end_msg 1 ;; # Failed to start
		esac
		;;
	  *)
	  	# Failed to stop
		log_end_msg 1
		;;
	esac
	;;
  *)
	#echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
	exit 3
	;;
esac

:
