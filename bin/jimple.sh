#!/bin/bash

# $1: the class wish to be dumped
# $2: the dex2jar file containing the clas
if [ $1 ] && [ $2 ]
then
java -cp ../lib/soot-trunk.jar soot.Main -cp $2:../lib/android_v18.jar -pp -f jimple $1
fi
