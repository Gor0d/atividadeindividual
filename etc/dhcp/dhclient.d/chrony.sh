#!/bin/bash

SERVERFILE=$SAVEDIR/chrony.servers.$interface

chrony_config() {
	# Disable modifications if called from a NM dispatcher script
	[ -n "$NM_DISPATCHER_ACTION" ] && return 0

	rm -f "$SERVERFILE"
	if [ "$PEERNTP" != "no" ]; then
		for server in $new_ntp_servers; do
			echo "$server ${NTPSERVERARGS:-iburst}" >> "$SERVERFILE"
		done
		/usr/libexec/chrony-helper update-daemon || :
	fi
}

chrony_restore() {
	[ -n "$NM_DISPATCHER_ACTION" ] && return 0

	if [ -f "$SERVERFILE" ]; then
		rm -f "$SERVERFILE"
		/usr/libexec/chrony-helper update-daemon || :
	fi
}
