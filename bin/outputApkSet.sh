#!/bin/bash
#
# Need to be put in /home/dao/autoApk/apkFile
#

for dir in $(ls jehApps)
do
    dirname="jehApps/$dir"
    pathname="$dirname/*/*.apk"

    i=0
    for apk in $(ls $pathname)
    do
        if [ $i -eq 300 ]; then
            break
        fi
        echo "$apk"
        ((i = i + 1))
    done
done
