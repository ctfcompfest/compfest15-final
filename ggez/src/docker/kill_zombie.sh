#!/usr/bin/env sh
while true
do
    DATA=$(ps -o pid,user | sed 's/^  *//g' | sed 's/  */;/g' | tail -n +2)
    for elm in $DATA; do
        PID=$(echo $elm | cut -d \; -f 1)
        USER=$(echo $elm | cut -d \; -f 2)
        if [ $USER = "nobody" ];
        then
            CHILD=$(pgrep -P $PID | tr "\n" " ")
            if [ "$CHILD" != "" ]; then
                kill -9 $CHILD
            fi
        fi;
    done
    sleep 300
done