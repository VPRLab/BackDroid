#!/bin/bash
#
# Need to be put in /home/dao/autoApk/apkFile
#

for dir in $(ls jehApps)
do
    dirname="jehApps/$dir"
    pathname="$dirname/*/*.apk"
    number=$( ls $pathname | wc -l )
    echo "$dir: $number"
done
