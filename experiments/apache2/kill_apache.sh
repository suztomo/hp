#!/bin/sh
# Kills apaches on virtual hosts.

VHOST_ID=0
VHOST_END=1000
APACHE_PID_FILE=/var/run/apache2.pid
while [ $VHOST_ID -lt $VHOST_END ]; do
  NUM=`printf "%05d" $VHOST_ID`
  FILE=/j/${NUM}${APACHE_PID_FILE}
  if [ -r $FILE ]; then
    CMD="sudo kill `cat $FILE`"
    $CMD
  fi
  VHOST_ID=`expr $VHOST_ID + 1`
done

