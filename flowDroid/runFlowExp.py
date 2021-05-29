#!/usr/bin/python
# -*- coding: utf-8 -*- 

import os, sys, time, threading, shlex
import urllib, urllib2
from optparse import OptionParser
#from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice
from xml.dom import minidom
from os.path import join, isdir, isfile, getsize
from subprocess import Popen, PIPE
import random


DEVCONFIG = 'devconfig.txt'
APPDUMP = 'appdump'
SODUMP = 'sodump'
STRDUMP = 'strdump'
SLEEPTIME = 2
SMLSLEEP = 4
BIGSLEEP = 12 #since attack 3 requires 8s
DATAOUT = 'dataOut'
dexdump = '/home/dao/software/android-sdk-linux_x86/build-tools/28.0.3/dexdump'
dex2jar="/home/dao/software/dex2jar/dex2jar-2.1/d2j-dex2jar.sh"
flowdroid="gencallgraph.sh"


"""
from http://stackoverflow.com/questions/1191374/subprocess-with-timeout
"""
class MyCmd(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None

    def run(self, timeout=60):
        def target():
            self.process = Popen(self.cmd, shell=True)
            (out, err) = self.process.communicate()

        thread = threading.Thread(target=target)
        thread.start()

        thread.join(timeout)
        if thread.is_alive():
            print 'Terminating: %s' % self.cmd
            self.process.terminate()
            thread.join()

"""
IN:  /dir1/dir2/dir3/xxx.apk
OUT: /dir1/dir2/dir3/xxx
"""
def getApkPrefix(apkpath):
    return apkpath[0:-4]

"""
.FileBrowser --> com.dropbox.android.FileBrowser
App --> org.mozilla.firefox.App
"""
def translateName(component, package):
    if component.startswith('.'):
        return '%s%s' % (package, component)
    else:
        if '.' in component:
            return component
        else:
            return '%s.%s' % (package, component)

"""
get package name for an apk
"""
def getPackageName(apk):
    # aapt to get package
    p1 = Popen(['aapt', 'dump', 'badging', apk], stdout=PIPE)
    p2 = Popen(['sed', '-n', "s/package.*name='\\([^']*\\).*/\\1/p"], stdin=p1.stdout, stdout=PIPE)
    (out, err) = p2.communicate()
    package = out.rstrip('\n')
    return package


def myExit(code):
    print '[Main] Start exiting...'
    sys.exit(code)

def flush():
    sys.stdout.flush()


"""
==============
main entry
==============
"""
# parse param
usage = "usage: python %prog -a apkdir -f listfile -w NO"
parser = OptionParser(usage=usage)
parser.add_option('-a', '--apk', action='store', type='string', dest='apk',
        help='The dir of apk files.')
parser.add_option('-f', '--listfile', action='store', type='string', dest='listfile',
        help='The list of apk files.')
parser.add_option('-w', '--whether', action='store', type='string', dest='whether',
        help='Whether to remove temp files.')
(options, args) = parser.parse_args()
if (not options.apk) and (not options.listfile):
    parser.error('-a (apkdir) or -f (listfile) is mandatory')
if options.apk:
    APPDIR = options.apk
    if APPDIR.endswith('/'):
        APPDIR = APPDIR[:-1]
if options.listfile:
    APPDUMP = options.listfile
ISREMOVE = True     # by default, we remove temp files
if options.whether:
    whether = options.whether
    if whether == 'NO' or whether == 'no' or whether == 'No':
        ISREMOVE = False


# read app list
applist = []
print '[Main] Read app list...'
flush()
if options.apk:
    os.system('ls %s/*.apk > %s' % (APPDIR, APPDUMP))
f = open(APPDUMP, 'r')
for line in f:
    app = line.rstrip('\n') #'appset/org.tint-10-v1.8.apk' #the full path depends on the value of appset
    applist.append(app)
if f:
    f.close()


# http://stackoverflow.com/a/415525/197165
curtime = time.strftime("%Y-%m-%d %H:%M:%S")
print 'Current Time: ', curtime
flush()


# loop app list
i = 0
for app in applist:
    apkprefix = getApkPrefix(app) #'/home/dao/autoApk/apkFile/top22687/abc.apple.emoji.theme.gif.keyboard'
    splits = apkprefix.split('/')
    appdir = splits[len(splits)-1] #'abc.apple.emoji.theme.gif.keyboard'

    # print
    i = i + 1
    print '[%d] App: %s' % (i, appdir)
    flush()

    # run FlowDroid 
    os.system('./%s %s' % (flowdroid, app))


curtime = time.strftime("%Y-%m-%d %H:%M:%S")
print 'Current Time: ', curtime
flush()

if (not options.listfile) and options.apk:
    os.system('rm %s' % APPDUMP)

# exit
myExit(0)
