#!/bin/bash
#
# Need to be put in /home/dao/autoApk/apkFile/Mobi_Usage_AppBackup
#

for apkname in $(ls *.apk)
do
    result=$( grep "$apkname" applist_date.log )
    echo "$result"
done
