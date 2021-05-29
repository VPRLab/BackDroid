#!/bin/bash

sootJar=../lib/soot-trunk.jar
infoflow=../lib/soot-infoflow.jar
infodroid=../lib/soot-infoflow-android.jar
otherJar=../lib/slf4j-api-1.7.5.jar:../lib/slf4j-simple-1.7.5.jar:../lib/axml-2.0.jar

time java -Xmx4g -cp ../BackDroid/bin:$sootJar:$infoflow:$infodroid:$otherJar edu.smu.backdroid.TestCallGraph
