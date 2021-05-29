# BackDroid

**BackDroid: Targeted and Efficient Inter-procedural Analysis of Modern Android Apps**
* Paper link: https://daoyuan14.github.io/papers/DSN21_BackDroid.pdf
* An earlier version of BackDroid had been used in our [[NDSS'19](https://daoyuan14.github.io/papers/NDSS19_OpenPort.pdf)] paper: ```Understanding Open Ports in Android Applications: Discovery, Diagnosis, and Security Assessment```.

If you use BackDroid or its code, please cite our DSN'21 paper as follows:
```
@INPROCEEDINGS{BackDroid21,
  AUTHOR =       {Daoyuan Wu and Debin Gao and Robert H. Deng and Rocky K. C. Chang},
  TITLE =        {When Program Analysis Meets Bytecode Search: Targeted and Efficient Inter-procedural Analysis of Modern {Android} Apps in {BackDroid}},
  BOOKTITLE =    {Proc. IEEE/IFIP International Conference on Dependable Systems and Networks (DSN)},
  YEAR =         {2021},
}
```

BackDroid was initially developed in a private BitBucket repo, and we are now migrating it to GitHub.
We also include some binaries and scripts of Amandroid and FlowDroid for a quick comparison between them and BackDroid.

We are **cleaning and refactoring the code** of BackDroid to make it easy-to-use and extensible.
The current version was mainly set for Daoyuan's computer and used some hard-code.

Our ultimate goal is to **make BackDroid a *practical* and *full-stack* Android static analysis tool**, which can run as **a standalone tool** and also be used as **a generic SDK** to support customization for different problems.


## The Required Tool/SDK

1. I use Eclipse to compile BackDroid, OldFlowDroid, and TestFlowDroid.<br>
**TODO:** use Gradle to make environment-independent compilation.

2. Need these two tools to generate _dexdump.log and _dex2jar.jar from an APK:
```
dexdump = '/home/dao/software/android-sdk-linux_x86/build-tools/28.0.3/dexdump'
dex2jar="/home/dao/software/dex2jar/dex2jar-2.1/d2j-dex2jar.sh"
```

3. Android SDK used by BackDroid (already in the lib folder):
```
Scene.v().extendSootClassPath("../lib/android-support-v7-recyclerview.jar");
Scene.v().extendSootClassPath("../lib/android-support-v4.jar");
......
Scene.v().extendSootClassPath("../lib/android_v28.jar");
Scene.v().extendSootClassPath("../lib/android_v23.jar");
Scene.v().extendSootClassPath("../lib/android_v19.jar");
```

4. Android SDK used by FlowDroid:
```
public static String AndroSDK = "/home/dao/software/android-sdk-linux_x86/platforms";
```

5. I use Java 7 (Open JDK) to compile in Eclipse, but use Java 8 (Oracle) to run the code:
```
Scene.v().setSootClassPath("/usr/lib/jvm/java-8-oracle/jre/lib/rt.jar");
```

6. The associated Python scripts have been tested under Python 2.7 but not Python 3+.


## Source Folders Explained

### BackDroid Related
1. BackDroid: the main source code
```
-- PortDetector is the main class
-- DumpAPIClass directly dumps an app class using Soot for debug
-- TestCallGraph is the old call graph generator using FlowDroid. Need to be
removed
-- analysis folder is the main analyzers
-- graph and structure folders are for data structures
-- util folder is some supporting class
```

2. grepApk: the script for automatically running BackDroid for experiments
```
-- grepCrypto.py: for crypto API related sinks
-- grepPort.py: for open port API related sinks
-- XXX_only.py: only count whether an APK contains the target sinks or not
   That is, "_only.py" means do not run BackDroid.
   A benefit of this script to to generate _dexdump.log and _dex2jar.jar.
   For example, backDroid/test$ python ../grepApk/grepPort_only.py -a . -w No         
   -a . for the current "test" folder; -w No for keeping dexdump.log and .jar
```

3. bin: the script for manually running BackDroid for debug
```
-- Require the generated _dexdump.log and _dex2jar.jar before we can run it.
-- You can understand the usage and see the examples by "cat" it.
   For example:
   backDroid/test$ ../bin/rawdroid.sh com.kugou.android 3 OpenPort
   backDroid/test$ ../bin/dotTOpdf.sh .
```

4. lib, test, exp, log are self-explained.

### FlowDroid Related
1. flowDroid: for experiments and scripts
```
-- gencallgraph.sh to run TestFlowDroid for automatic experiments.
-- oldcallgraph.sh to run OldFlowDroid for manual testing.
```

2. TestDroid: Java code used by gencallgraph.sh

3. OldFlowDroid: Java code used by oldcallgraph.sh

### AmanDroid Related
1. amanDroid: for experiments and scripts


## A Running Example
Once you compile BackDroid to generate .class files, you can manually run BackDroid like the example below:
```
// Test BackDroid using two APKs in the test folder
BackDroid$ cd test/

// Generate the _dexdump.log and _dex2jar.jar files using the "-w" option
BackDroid/test$ python ../grepApk/grepCrypto_only.py -a . -w No // For APKs with crypto APIs
BackDroid/test$ python ../grepApk/grepPort_only.py -a . -w No   // For APKs with open port usages

// Run the main BackDroid code in the release mode ("3")
BackDroid/test$ ../bin/rawdroid.sh com.adobe.fas 3 CRYPTO
BackDroid/test$ ../bin/rawdroid.sh com.kugou.android 3 OpenPort

// Draw plot files of the generated BDG graphs
BackDroid/test$ ../bin/dotTOpdf.sh .
```
You also can automatically run BackDroid for experiments using `grepCrypto.py` or `grepPort.py`.
