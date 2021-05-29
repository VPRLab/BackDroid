#!/bin/bash

sootJar=../lib/sootclasses-trunk-jar-with-dependencies-3.3.0.jar
infoflow=../lib/soot-infoflow-classes-2.7.1.jar
infodroid=../lib/soot-infoflow-android-classes-2.7.1.jar
otherJar=../lib/slf4j-api-1.7.5.jar:../lib/slf4j-simple-1.7.5.jar:../lib/axml-2.0.jar:../lib/trove-3.0.3.jar:../lib/commons-cli-1.2.jar

# $1: -a, the apk prefix name
if [ $1 ]
then
time timeout 301m java -Xmx12g -Xss100m -cp ../TestFlowDroid/bin:$sootJar:$infoflow:$infodroid:$otherJar edu.smu.testfd.GenCallGraph -a $1
fi
