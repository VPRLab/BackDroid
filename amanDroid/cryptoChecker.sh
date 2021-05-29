#!/bin/bash

amanJar=argus-saf_2.11-2.0.5-assembly.jar

# $ time java -jar argus-saf_2.11-2.0.4-assembly.jar a -df -c CRYPTO_MISUSE com.sa.electrico.tacto.apk
if [ $1 ]
then
time timeout 61m java -Xmx12g -Xss100m -jar $amanJar a -df -c CRYPTO_MISUSE $1
fi
