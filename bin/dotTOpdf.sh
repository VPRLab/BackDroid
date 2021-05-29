#!/bin/bash

# $ ../bin/dotTOpdf.sh . hu.tagsoft.ttorrent.lite-10000068_hu.tagsoft.ttorrent.webserver.a.j_BDG.dot
if [ $1 ] && [ $2 ]
then
    for dotfile in $(ls $1/$2)
    do
        # https://unix.stackexchange.com/a/144330
        dotname=${dotfile::-4}
        echo $dotname
        laststr=".pdf"
        dot -Tpdf $dotfile -o $dotname$laststr
    done
elif [ $1 ]
# $ ../bin/dotTOpdf.sh .
then
    for dotfile in $(ls $1/*.dot)
    do
        # https://unix.stackexchange.com/a/144330
        dotname=${dotfile::-4}
        echo $dotname
        laststr=".pdf"
        dot -Tpdf $dotfile -o $dotname$laststr
    done
fi
